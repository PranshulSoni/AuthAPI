import { consumeRefreshToken, createAuthAccount, createOAuthUser, createUser, deleteAllRefreshTokens, deleteRefreshToken, findUserByAuthAccount, findUserByEmail, findUserById, setEmailVerificationToken, setPasswordResetToken, storeRefreshToken, verifyUserByEmailToken, resetPasswordByToken } from "../repository/user.repository.js";
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
}
export interface loginInput {
    email: string
    password: string
}
export interface LogoutInput {
    refreshToken: string
}
export interface RefreshInput {
    refreshToken: string
}
export interface ResetPasswordInput {
    token: string
    newPassword: string
}
export interface ForgotPasswordInput {
    email: string
}
export interface OAuthLoginInput {
    provider: string
    providerAccountId: string
    email: string
    username: string
}
interface AuthUserRow {
    id: string
    username: string
    email: string
    password?: string | null
    role: string
    is_verified: boolean
    [key: string]: unknown
}
export interface AuthTokens {
    accessToken: string
    refreshToken: string
}

const INVALID_LOGIN_MESSAGE = "Invalid email or password";
const dummyHash = "$2b$10$7EqJtq98hPqEX7fNZaFWoOHi8YDxw7FqaifQqE7UD5N4rQUmyXh5O";

function normalizeEmail(email: string) {
    if (typeof email !== "string" || email.trim() === "") {
        throw new Error("Invalid Email");
    }

    const normalizedEmail=email.trim().toLowerCase();
    const emailRegex = /^[a-z0-9._%+-]{2,}@[a-z0-9.-]+\.[a-z]{2,}$/;
    if (!emailRegex.test(normalizedEmail)) {
        throw new Error("Invalid Email");
    }

    return normalizedEmail;
}

function validatePassword(password: string) {
    if (typeof password !== "string" || password.trim() === "") {
        throw new Error("Password is required");
    }

    if (password.length < 8) {
        throw new Error("Password must be at least 8 characters");
    }

    if (!/[A-Z]/.test(password)) {
        throw new Error("Password must contain at least one uppercase letter");
    }

    if (!/[0-9]/.test(password)) {
        throw new Error("Password must contain at least one number");
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
        throw new Error("Password must contain at least one special character");
    }

    return password;
}

function validateLoginPassword(password: string) {
    if (typeof password!=="string" || password.trim()==="") {
        throw new Error("Password is required");
    }

    return password;
}

function normalizeUsername(username: string) {
    if (typeof username!=="string" ||username.trim()==="") {
        throw new Error("Username is required");
    }

    const normalizedUsername = username.trim();
    if (normalizedUsername.length < 2 || normalizedUsername.length > 50) {
        throw new Error("Username must be between 2 and 50 characters");
    }

    if (/[<>]/.test(normalizedUsername)) {
        throw new Error("Username contains invalid characters");
    }

    return normalizedUsername;
}

function validateRequiredToken(token: string, message: string) {
    if (typeof token !== "string" || token.trim() === "") {
        throw new Error(message);
    }

    return token;
}

export async function registerUser(pool: db.Pool, input: RegisterInput, emailConfig?: AuthConfig['email'], verificationBaseUrl?: string) {
    const email = normalizeEmail(input.email);
    const password = validatePassword(input.password);
    const username = normalizeUsername(input.username);
    const user = await findUserByEmail(pool, email);
    if(user){
        throw new Error("Email Already exists");
    }
    else {
        const pass = await bcrypt.hash(password, 10);
        const newUser = await createUser(pool, email, pass, username,'user');
        if (emailConfig != null && verificationBaseUrl != null) {
            const verificationToken = crypto.randomUUID();
            const verificationTokenHash = hashToken(verificationToken);
            const expiresAt = new Date(Date.now() +24*60*60*1000);
            await setEmailVerificationToken(pool, newUser.id, verificationTokenHash, expiresAt);
            const verificationUrl = `${verificationBaseUrl}?token=${verificationToken}`;
            await sendVerificationEmail(emailConfig, newUser.email, verificationUrl);
        }
        return sanitizeUser(newUser);
    }
}

function sanitizeUser(user: AuthUserRow) {
    const { password, ...safeUser } = user;
    return safeUser;
}

export async function issueAuthTokens(pool: db.Pool, user: AuthUserRow, jwtSecret: string, accessTokenExpiry: string): Promise<AuthTokens> {
    const { accessToken, refreshToken } = generateTokens(user.id, user.role, user.is_verified, jwtSecret, accessTokenExpiry);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const hashedRefreshToken = hashRefreshToken(refreshToken);
    await storeRefreshToken(pool, user.id, hashedRefreshToken, expiresAt);
    return { accessToken, refreshToken };
}

export async function loginUser(pool: db.Pool, input: loginInput, jwtSecret: string, accessTokenExpiry: string) {
    const email = normalizeEmail(input.email);
    const pass = validateLoginPassword(input.password);
    const user = await findUserByEmail(pool, email);
    if (user==null){
        await bcrypt.compare(pass, dummyHash);
        throw new Error(INVALID_LOGIN_MESSAGE);
    }
    else {
        if (user.password == null) {
            await bcrypt.compare(pass, dummyHash);
            throw new Error(INVALID_LOGIN_MESSAGE);
        }
        const comp = await bcrypt.compare(pass, user.password);
        if (comp) {
            const tokens = await issueAuthTokens(pool, user, jwtSecret, accessTokenExpiry);
            return { user: sanitizeUser(user), tokens };
        }
        else {
            throw new Error(INVALID_LOGIN_MESSAGE);
        }
    }
}

function hashRefreshToken(refreshToken: string) {
    return hashToken(refreshToken);
}

function hashToken(token: string) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

export async function verifyEmail(pool: db.Pool, token: string) {
    const tokenHash = hashToken(validateRequiredToken(token, "Email verification token is required"));
    const user = await verifyUserByEmailToken(pool, tokenHash);
    if (user == null) {
        throw new Error("Email verification token is invalid or expired");
    }
    return sanitizeUser(user);
}

export async function logoutUser(pool: db.Pool, input: LogoutInput) {
    const refreshToken = validateRequiredToken(input.refreshToken, "Refresh token is required");
    const hashedRefreshToken = hashRefreshToken(refreshToken);
    await deleteRefreshToken(pool, hashedRefreshToken);
    return { loggedOut: true };
}

export async function reAuthUser(pool: db.Pool, input: RefreshInput, jwtSecret: string, accessTokenExpiry: string) {
    const refreshToken = validateRequiredToken(input.refreshToken, "Refresh token is required");
    const hashedRefreshToken = hashRefreshToken(refreshToken);
    const consumedToken = await consumeRefreshToken(pool, hashedRefreshToken);
    if (consumedToken) {
        const user = await findUserById(pool, consumedToken.user_id);
        if (user == null) {
            throw new Error("User does not exist");
        }
        return issueAuthTokens(pool, user, jwtSecret, accessTokenExpiry);
    }
    else {
        throw new Error("Refresh Token Invalid");
    }
}

export async function forgotPassword(pool: db.Pool, input: ForgotPasswordInput, emailConfig: AuthConfig['email'], resetBaseUrl: string) {
    const email = normalizeEmail(input.email);
    const user = await findUserByEmail(pool, email);

    if (user == null) {
        return { message: "If an account exists then a reset password mail has been sent" }
    }
    const resetToken = crypto.randomUUID();
    const resetTokenHash = hashToken(resetToken);
    const expires_at = new Date(Date.now() + 15 * 60 * 1000);

    await setPasswordResetToken(pool, user.id, resetTokenHash, expires_at);
    const resetUrl = `${resetBaseUrl}?token=${resetToken}`;
    await sendPasswordResetEmail(emailConfig!, user.email, resetUrl);
    return { message: "If an account exists then a reset password mail has been sent" }
}

export async function resetPassword(pool: db.Pool, input: ResetPasswordInput) {
    const tokenHash = hashToken(validateRequiredToken(input.token, "Password reset token is required"));
    const passwordHash = await bcrypt.hash(validatePassword(input.newPassword), 10)

    const user = await resetPasswordByToken(pool, tokenHash, passwordHash);
    if (user == null) {
        throw new Error("Password reset token is invalid or expired")
    }
    await deleteAllRefreshTokens(pool, user.id);

    return { passwordReset: true }
}


export function generateTokens(userId: string, role: string, isVerified: boolean, jwtSecret: string, accessTokenExpiry: string) {
    const refreshToken = crypto.randomUUID();
    const accessToken = jwt.sign({ userId, role, isVerified }, jwtSecret, { expiresIn: accessTokenExpiry } as jwt.SignOptions);
    return { accessToken, refreshToken };
}

export function generateAccessTokens(userId: string, role: string, isVerified: boolean, jwtSecret: string, accessTokenExpiry: string) {
    const accessToken = jwt.sign({ userId, role, isVerified }, jwtSecret, { expiresIn: accessTokenExpiry } as jwt.SignOptions);
    return accessToken;
}

export async function oauthLoginUser(pool: db.Pool, input: OAuthLoginInput, jwtSecret: string, accessTokenExpiry: string) {
    const provider = validateRequiredToken(input.provider, "OAuth provider is required").trim().toLowerCase();
    const providerAccountId = validateRequiredToken(input.providerAccountId, "OAuth provider account id is required").trim();
    const email = normalizeEmail(input.email);
    const username = normalizeUsername(input.username);
    const userByAuthAccount = await findUserByAuthAccount(pool, provider, providerAccountId);
    if (userByAuthAccount) {
        const tokens = await issueAuthTokens(pool, userByAuthAccount, jwtSecret, accessTokenExpiry);
        return { user: sanitizeUser(userByAuthAccount), tokens };
    }

    const userByEmail = await findUserByEmail(pool, email);
    if (userByEmail) {
        await createAuthAccount(pool, userByEmail.id, provider, providerAccountId, email);
        const tokens = await issueAuthTokens(pool, userByEmail, jwtSecret, accessTokenExpiry);
        return { user: sanitizeUser(userByEmail), tokens };
    }

    const newUser = await createOAuthUser(pool, email, username, 'user');
    await createAuthAccount(pool, newUser.id, provider, providerAccountId, email);
    const tokens = await issueAuthTokens(pool, newUser, jwtSecret, accessTokenExpiry);
    return { user: sanitizeUser(newUser), tokens };
}
