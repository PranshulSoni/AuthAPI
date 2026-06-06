import { consumeRefreshToken,createAuthAccount,createOAuthUser,createUser,deleteAllRefreshTokens,deleteRefreshToken,findUserByAuthAccount,findUserByEmail,findUserById,setEmailVerificationToken,setPasswordResetToken,storeRefreshToken,verifyUserByEmailToken,resetPasswordByToken } from "../repository/user.repository.js";
import * as db from 'pg';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { AuthConfig } from "../types/index.js";
import { sendPasswordResetEmail, sendVerificationEmail } from "./email.service.js";

export interface RegisterInput {
  email: string
  password: string
  username: string
  role?: string 
}
export interface loginInput {
  email: string
  password: string
}
export interface LogoutInput {
  refreshToken: string
}
export interface RefreshInput{
    refreshToken:string
}
export interface ResetPasswordInput {
    token:string
    newPassword:string
}
export interface ForgotPasswordInput {
    email:string
}
export interface OAuthLoginInput {
    provider:string
    providerAccountId:string
    email:string
    username:string
}
interface AuthUserRow {
    id:string
    username:string
    email:string
    password?:string | null
    role:string
    is_verified:boolean
    [key:string]: unknown
}

type SafeUser = Omit<AuthUserRow, 'password'>

export interface AuthTokens {
    accessToken:string
    refreshToken:string
}

export async function registerUser(pool:db.Pool,input:RegisterInput,emailConfig?:AuthConfig['email'],verificationBaseUrl?:string){
    const user=await findUserByEmail(pool,input.email);
    if(user){
        throw new Error("Email Already exists");
    }
    else{
        const pass=await bcrypt.hash(input.password,10);
        const newUser=await createUser(pool,input.email,pass,input.username,input.role??'user');
        if(emailConfig!=null && verificationBaseUrl!=null){
            const verificationToken=crypto.randomUUID();
            const verificationTokenHash=hashToken(verificationToken);
            const expiresAt=new Date(Date.now() + 24 * 60 * 60 * 1000);
            await setEmailVerificationToken(pool,newUser.id,verificationTokenHash,expiresAt);
            const verificationUrl=`${verificationBaseUrl}?token=${verificationToken}`;
            await sendVerificationEmail(emailConfig,newUser.email,verificationUrl);
        }
        return sanitizeUser(newUser);
    }
}

function sanitizeUser(user:AuthUserRow):SafeUser{
    const {password,...safeUser}=user;
    return safeUser;
}

export async function issueAuthTokens(pool: db.Pool, user: AuthUserRow, jwtSecret: string, accessTokenExpiry: string):Promise<AuthTokens> {
    const { accessToken, refreshToken } = generateTokens(user.id, user.role, user.is_verified, jwtSecret, accessTokenExpiry);
    const expiresAt = new Date(Date.now()+30*24*60*60*1000);
    const hashedRefreshToken = hashRefreshToken(refreshToken);
    await storeRefreshToken(pool, user.id, hashedRefreshToken, expiresAt);
    return { accessToken, refreshToken };
}

export async function loginUser(pool: db.Pool, input: loginInput, jwtSecret: string, accessTokenExpiry: string) {
    const user=await findUserByEmail(pool,input.email);
    if(user==null){
        throw new Error("User does not exist");
    }
    else{
        const pass=input.password;
        if(user.password == null){
            throw new Error("Invalid Password");
        }
        const comp=await bcrypt.compare(pass,user.password);
        if(comp){
            const tokens = await issueAuthTokens(pool, user, jwtSecret, accessTokenExpiry);
            return { user: sanitizeUser(user), tokens };
        }
        else{
            throw new Error("Invalid Password");
        }
    }
}

function hashRefreshToken(refreshToken:string) {
    return hashToken(refreshToken);
}

function hashToken(token:string) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

export async function verifyEmail(pool:db.Pool,token:string){
    const tokenHash=hashToken(token);
    const user=await verifyUserByEmailToken(pool,tokenHash);
    if(user==null){
        throw new Error("Email verification token is invalid or expired");
    }
    return sanitizeUser(user);
}

export async function logoutUser(pool:db.Pool,input:LogoutInput){
    if(input.refreshToken==null){
        throw new Error("Refresh token is required");
    }
    const hashedRefreshToken = hashRefreshToken(input.refreshToken);
    await deleteRefreshToken(pool,hashedRefreshToken);
    return {loggedOut:true};
}

export async function reAuthUser(pool:db.Pool,input:RefreshInput,jwtSecret:string,accessTokenExpiry:string){
    if(input.refreshToken==null){
        throw new Error("Refresh token is required");
    }
    const hashedRefreshToken = hashRefreshToken(input.refreshToken);
    const consumedToken=await consumeRefreshToken(pool,hashedRefreshToken);
    if(consumedToken){
        const user=await findUserById(pool,consumedToken.user_id);
        if(user==null){
            throw new Error("User does not exist");
        }
        return issueAuthTokens(pool, user, jwtSecret, accessTokenExpiry);
    }
    else{
        throw new Error("Refresh Token Invalid");
    }
}

export async function forgotPassword(pool:db.Pool,input:ForgotPasswordInput,emailConfig:AuthConfig['email'],resetBaseUrl:string){
    const user=await findUserByEmail(pool,input.email);

    if(user==null){
        return { message: "If an account exists then a reset password mail has been sent" }
    }
    const resetToken=crypto.randomUUID();
    const resetTokenHash=hashToken(resetToken);
    const expires_at=new Date(Date.now()+15*60*1000);

    await setPasswordResetToken(pool,user.id,resetTokenHash,expires_at);
    const resetUrl=`${resetBaseUrl}?token=${resetToken}`;
    await sendPasswordResetEmail(emailConfig!,user.email,resetUrl);
    return { message: "If an account exists then a reset password mail has been sent" }
}

export async function resetPassword(pool:db.Pool,input:ResetPasswordInput) {
    const tokenHash=hashToken(input.token);
    const passwordHash = await bcrypt.hash(input.newPassword, 10)
    
    const user = await resetPasswordByToken(pool, tokenHash, passwordHash);
    if(user == null){
        throw new Error("Password reset token is invalid or expired")
    }
    await deleteAllRefreshTokens(pool,user.id);

    return { passwordReset: true }
}


export function generateTokens(userId: string,role: string,isVerified:boolean,jwtSecret: string,accessTokenExpiry: string){
    const refreshToken=crypto.randomUUID();
    const accessToken=jwt.sign({userId,role,isVerified},jwtSecret,{expiresIn:accessTokenExpiry}as jwt.SignOptions);
    return {accessToken,refreshToken};
}

export function generateAccessTokens(userId: string,role: string,isVerified:boolean,jwtSecret: string,accessTokenExpiry: string){
    const accessToken=jwt.sign({userId,role,isVerified},jwtSecret,{expiresIn:accessTokenExpiry}as jwt.SignOptions);
    return accessToken;
}

export async function oauthLoginUser(pool:db.Pool,input:OAuthLoginInput,jwtSecret:string,accessTokenExpiry:string) {
    const userByAuthAccount=await findUserByAuthAccount(pool,input.provider,input.providerAccountId);
    if(userByAuthAccount){
        const tokens = await issueAuthTokens(pool,userByAuthAccount,jwtSecret,accessTokenExpiry);
        return { user: sanitizeUser(userByAuthAccount), tokens };
    }

    const userByEmail=await findUserByEmail(pool,input.email);
    if(userByEmail){
        await createAuthAccount(pool,userByEmail.id,input.provider,input.providerAccountId,input.email);
        const tokens = await issueAuthTokens(pool,userByEmail,jwtSecret,accessTokenExpiry);
        return { user: sanitizeUser(userByEmail), tokens };
    }

    const newUser=await createOAuthUser(pool,input.email,input.username,'user');
    await createAuthAccount(pool,newUser.id,input.provider,input.providerAccountId,input.email);
    const tokens = await issueAuthTokens(pool,newUser,jwtSecret,accessTokenExpiry);
    return { user: sanitizeUser(newUser), tokens };
}
