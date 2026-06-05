import { createUser,deleteRefreshToken,findUserByEmail,findRefreshToken,storeRefreshToken } from "../repository/user.repository.js";
import * as db from 'pg';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

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

export async function registerUser(pool:db.Pool, input:RegisterInput){
    const user=await findUserByEmail(pool,input.email);
    if(user){
        throw new Error("Email Already exists");
    }
    else{
        const pass=await bcrypt.hash(input.password,10);
        const newUser=await createUser(pool,input.email,pass,input.username,input.role??'user');
        return sanitizeUser(newUser);
    }
}

function sanitizeUser(user:any){
    const {password,...safeUser}=user;
    return safeUser;
}

export async function loginUser(pool: db.Pool, input: loginInput, jwtSecret: string, accessTokenExpiry: string) {
    const user=await findUserByEmail(pool,input.email);
    if(user==null){
        throw new Error("User does not exist");
    }
    else{
        const pass=input.password;
        const comp=await bcrypt.compare(pass,user.password);
        if(comp){
            const tokens = generateTokens(user.id, user.role, jwtSecret, accessTokenExpiry)
            const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
            const hashedRefreshToken=hashRefreshToken(tokens.refreshToken);
            await storeRefreshToken(pool,user.id,hashedRefreshToken,expiresAt);
            return {user:sanitizeUser(user),tokens};
        }
        else{
            throw new Error("Invalid Password");
        }
    }
}

function hashRefreshToken(refreshToken:string) {
    return crypto.createHash('sha256').update(refreshToken).digest('hex');
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
    const results=await findRefreshToken(pool,hashedRefreshToken);
    if(results){
        const accessToken=generateAccessTokens(results.user_id,results.role,jwtSecret,accessTokenExpiry);
        return accessToken;
    }
    else{
        throw new Error("Refresh Token Invalid");
    }
}

export function generateTokens(userId: string,role: string,jwtSecret: string,accessTokenExpiry: string){
    const refreshToken=crypto.randomUUID();
    const accessToken=jwt.sign({userId,role},jwtSecret,{expiresIn:accessTokenExpiry}as jwt.SignOptions);
    return {accessToken,refreshToken};
}

export function generateAccessTokens(userId: string,role: string,jwtSecret: string,accessTokenExpiry: string){
    const accessToken=jwt.sign({userId,role},jwtSecret,{expiresIn:accessTokenExpiry}as jwt.SignOptions);
    return accessToken;
}
