import { createAuthAccount, deleteAllRefreshTokens, deleteRefreshToken, findAuthAccount, storeRefreshToken, consumeRefreshToken } from "../repository/user.repository.js";
import * as db from 'pg';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import type { AuthConfig, UserRepo } from "../types/index.js";
import { sendPasswordResetEmail, sendVerificationEmail } from "./email.service.js";

export interface RegisterInput {
    email: string
    password: string
    username: string
}
export interface loginInput {
    email: string
    password: string
    tenantId?: string
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
export interface AuthTokens {
    accessToken: string
    refreshToken: string
}

const INVALID_LOGIN_MESSAGE = "Invalid email or password";

function resolveSecret(jwtSecret: string | (() => string)): string {
    return typeof jwtSecret === "function" ? jwtSecret() : jwtSecret
}
const dummyHash = "$2b$10$7EqJtq98hPqEX7fNZaFWoOHi8YDxw7FqaifQqE7UD5N4rQUmyXh5O";

function normalizeEmail(email: string) {
    if (typeof email !== "string" || email.trim() === "") {
        throw new Error("Invalid Email");
    }
    const normalizedEmail = email.trim().toLowerCase();
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
    if (typeof password !== "string" || password.trim() === "") {
        throw new Error("Password is required");
    }
    return password;
}

function normalizeUsername(username: string) {
    if (typeof username !== "string" || username.trim() === "") {
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

function sanitizeUser(user: Record<string, unknown>) {
    const { password, ...safeUser } = user;
    void password;
    return safeUser;
}

export async function registerUser(repo: UserRepo, input: RegisterInput, emailConfig?: AuthConfig['email'], verificationBaseUrl?: string) {
    const email = normalizeEmail(input.email);
    const password = validatePassword(input.password);
    const username = normalizeUsername(input.username);
    const user = await repo.findByEmail(email);
    if (user) {
        throw new Error("Email Already exists");
    }
    const pass = await bcrypt.hash(password, 10);
    const newUser = await repo.createUser(email, pass, username, 'user');
    if (emailConfig != null && verificationBaseUrl != null) {
        const verificationToken = crypto.randomUUID();
        const verificationTokenHash = hashToken(verificationToken);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await repo.setEmailVerificationToken(newUser.id, verificationTokenHash, expiresAt);
        const verificationUrl = `${verificationBaseUrl}?token=${verificationToken}`;
        await sendVerificationEmail(emailConfig, newUser.email, verificationUrl);
    }
    return sanitizeUser(newUser as unknown as Record<string, unknown>);
}

function hashRefreshToken(refreshToken: string) {
    return hashToken(refreshToken);
}

function hashToken(token: string) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

export async function issueAuthTokens(pool: db.Pool, user: { id: string; role: string; is_verified: boolean }, jwtSecret: string | (() => string), accessTokenExpiry: string, tenantId?: string): Promise<AuthTokens> {
    const { accessToken, refreshToken } = generateTokens(user.id, user.role, user.is_verified, jwtSecret, accessTokenExpiry, tenantId);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const hashedRefreshToken = hashRefreshToken(refreshToken);
    await storeRefreshToken(pool, user.id, hashedRefreshToken, expiresAt);
    return { accessToken, refreshToken };
}

export async function loginUser(repo: UserRepo, pool: db.Pool, input: loginInput, jwtSecret: string | (() => string), accessTokenExpiry: string) {
    const email = normalizeEmail(input.email);
    const pass = validateLoginPassword(input.password);
    const user = await repo.findByEmail(email);
    if (user == null) {
        await bcrypt.compare(pass, dummyHash);
        throw new Error(INVALID_LOGIN_MESSAGE);
    }
    if (user.password == null) {
        await bcrypt.compare(pass, dummyHash);
        throw new Error(INVALID_LOGIN_MESSAGE);
    }
    const comp = await bcrypt.compare(pass, user.password);
    if (!comp) {
        throw new Error(INVALID_LOGIN_MESSAGE);
    }
    const tokens = await issueAuthTokens(pool, user, jwtSecret, accessTokenExpiry, input.tenantId);
    return { user: sanitizeUser(user as unknown as Record<string, unknown>), tokens };
}

export async function verifyEmail(repo: UserRepo, token: string) {
    const tokenHash = hashToken(validateRequiredToken(token, "Email verification token is required"));
    const user = await repo.verifyByEmailToken(tokenHash);
    if (user == null) {
        throw new Error("Email verification token is invalid or expired");
    }
    return sanitizeUser(user as unknown as Record<string, unknown>);
}

export async function logoutUser(pool: db.Pool, input: LogoutInput) {
    const refreshToken = validateRequiredToken(input.refreshToken, "Refresh token is required");
    const hashedRefreshToken = hashRefreshToken(refreshToken);
    await deleteRefreshToken(pool, hashedRefreshToken);
    return { loggedOut: true };
}

export async function reAuthUser(repo: UserRepo, pool: db.Pool, input: RefreshInput, jwtSecret: string | (() => string), accessTokenExpiry: string) {
    const refreshToken = validateRequiredToken(input.refreshToken, "Refresh token is required");
    const hashedRefreshToken = hashRefreshToken(refreshToken);
    const consumedToken = await consumeRefreshToken(pool, hashedRefreshToken);
    if (!consumedToken) {
        throw new Error("Refresh Token Invalid");
    }
    const user = await repo.findById(consumedToken.user_id);
    if (user == null) {
        throw new Error("User does not exist");
    }
    return issueAuthTokens(pool, user, jwtSecret, accessTokenExpiry);
}

export async function forgotPassword(repo: UserRepo, input: ForgotPasswordInput, emailConfig: AuthConfig['email'], resetBaseUrl: string) {
    const email = normalizeEmail(input.email);
    const user = await repo.findByEmail(email);
    if (user == null) {
        return { message: "If an account exists then a reset password mail has been sent" }
    }
    const resetToken = crypto.randomUUID();
    const resetTokenHash = hashToken(resetToken);
    const expires_at = new Date(Date.now() + 15 * 60 * 1000);
    await repo.setPasswordResetToken(user.id, resetTokenHash, expires_at);
    const resetUrl = `${resetBaseUrl}?token=${resetToken}`;
    await sendPasswordResetEmail(emailConfig!, user.email, resetUrl);
    return { message: "If an account exists then a reset password mail has been sent" }
}

export async function resetPassword(repo: UserRepo, pool: db.Pool, input: ResetPasswordInput) {
    const tokenHash = hashToken(validateRequiredToken(input.token, "Password reset token is required"));
    const passwordHash = await bcrypt.hash(validatePassword(input.newPassword), 10);
    const user = await repo.resetPasswordByToken(tokenHash, passwordHash);
    if (user == null) {
        throw new Error("Password reset token is invalid or expired")
    }
    await deleteAllRefreshTokens(pool, user.id);
    return { passwordReset: true }
}

export async function oauthLoginUser(repo: UserRepo, pool: db.Pool, input: OAuthLoginInput, jwtSecret: string | (() => string), accessTokenExpiry: string) {
    const provider = validateRequiredToken(input.provider, "OAuth provider is required").trim().toLowerCase();
    const providerAccountId = validateRequiredToken(input.providerAccountId, "OAuth provider account id is required").trim();
    const email = normalizeEmail(input.email);
    const username = normalizeUsername(input.username);

    // Two-step lookup: auth_accounts → user_id → repo.findById (works with any table)
    const authAccount = await findAuthAccount(pool, provider, providerAccountId);
    if (authAccount) {
        const user = await repo.findById(authAccount.user_id);
        if (!user) throw new Error("User not found for OAuth account");
        const tokens = await issueAuthTokens(pool, user, jwtSecret, accessTokenExpiry);
        return { user: sanitizeUser(user as unknown as Record<string, unknown>), tokens };
    }

    const userByEmail = await repo.findByEmail(email);
    if (userByEmail) {
        await createAuthAccount(pool, userByEmail.id, provider, providerAccountId, email);
        const tokens = await issueAuthTokens(pool, userByEmail, jwtSecret, accessTokenExpiry);
        return { user: sanitizeUser(userByEmail as unknown as Record<string, unknown>), tokens };
    }

    const newUser = await repo.createUser(email, null, username, 'user', true);
    await createAuthAccount(pool, newUser.id, provider, providerAccountId, email);
    const tokens = await issueAuthTokens(pool, newUser, jwtSecret, accessTokenExpiry);
    return { user: sanitizeUser(newUser as unknown as Record<string, unknown>), tokens };
}

export function generateTokens(userId: string, role: string, isVerified: boolean, jwtSecret: string | (() => string), accessTokenExpiry: string, tenantId?: string) {
    const refreshToken = crypto.randomUUID();
    const payload = tenantId ? { userId, role, isVerified, tenantId } : { userId, role, isVerified };
    const accessToken = jwt.sign(payload, resolveSecret(jwtSecret), { expiresIn: accessTokenExpiry } as jwt.SignOptions);
    return { accessToken, refreshToken };
}

export function generateAccessTokens(userId: string, role: string, isVerified: boolean, jwtSecret: string | (() => string), accessTokenExpiry: string) {
    const accessToken = jwt.sign({ userId, role, isVerified }, resolveSecret(jwtSecret), { expiresIn: accessTokenExpiry } as jwt.SignOptions);
    return accessToken;
}
