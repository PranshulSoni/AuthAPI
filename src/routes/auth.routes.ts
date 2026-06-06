import * as db from 'pg'
import express from 'express'
import crypto from "crypto"
import { forgotPassword, loginUser, logoutUser, oauthLoginUser, reAuthUser, registerUser, resetPassword, verifyEmail } from '../services/auth.service.js'
import { AuthConfig } from '../types/index.js';
const noLimiter = (_req: any, _res: any, next: any) => next();
export function createAuthRouter(pool: db.Pool, jwtSecret: string, accessTokenExpiry: string, emailConfig?: AuthConfig['email'], limiters?: any, oauthConfig?: AuthConfig['oauth'], redisClient?: any) {
    const router = express.Router();
    router.post('/register', limiters?.registerLimiter ?? noLimiter, async (req, res) => {
        try {
            const { email, password, username } = req.body
            if (!email || !password || !username) {
                res.status(400).json({ error: "Email, password and username are required" });
                return;
            }
            const verificationBaseUrl = `${req.protocol}://${req.get('host')}${req.baseUrl}/verify-email`;
            const user = await registerUser(pool, { email, password, username }, emailConfig, verificationBaseUrl)
            res.status(201).json({ user })
        } catch (error: any) {
            res.status(400).json({ error: error.message })
        }
    })

    router.post('/login', limiters?.loginLimiter ?? noLimiter, async (req, res) => {
        try {
            const { email, password } = req.body
            if (!email || !password) {
                res.status(400).json({ error: "Email and password are required" });
                return;
            }
            const result = await loginUser(pool, { email, password }, jwtSecret, accessTokenExpiry)
            res.status(200).json(result)
        } catch (error: any) {
            res.status(400).json({ error: error.message })
        }
    })

    router.delete('/logout', async (req, res) => {
        try {
            const { refreshToken } = req.body
            if (!refreshToken) {
                res.status(400).json({ error: "Refresh token is required" });
                return;
            }
            const result = await logoutUser(pool, { refreshToken })
            res.status(200).json(result)
        } catch (error: any) {
            res.status(400).json({ error: error.message })
        }
    });
    router.post('/refresh', async (req, res) => {
        try {
            const { refreshToken } = req.body
            if (!refreshToken) {
                res.status(400).json({ error: "Refresh token is required" });
                return;
            }
            const result = await reAuthUser(pool, { refreshToken }, jwtSecret, accessTokenExpiry)
            res.status(200).json(result)
        } catch (error: any) {
            res.status(401).json({ error: error.message })
        }
    });
    router.get('/verify-email', async (req, res) => {
        try {
            const token = req.query.token;
            if (typeof token !== 'string' || !token) {
                res.status(400).json({ error: "Verification failed" });
                return;
            }
            const user = await verifyEmail(pool, token);
            res.status(200).json({ user });
        } catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    });
    router.post('/forgot-password', limiters?.forgotPasswordLimiter ?? noLimiter, async (req, res) => {
        try {
            const { email } = req.body;
            if (!email) {
                res.status(400).json({ error: "Email is required" });
                return;
            }
            if (emailConfig == null) {
                res.status(400).json({ error: "Email provider is not configured" });
                return;
            }
            const resetBaseUrl = `${req.protocol}://${req.get('host')}${req.baseUrl}/reset-password`;
            const result = await forgotPassword(pool, { email }, emailConfig, resetBaseUrl);
            res.status(200).json(result)
        }
        catch (error: any) {
            res.status(400).json({ error: error.message })
        }
    });
    router.post('/reset-password', limiters?.resetPasswordLimiter ?? noLimiter, async (req, res) => {
        try {
            const { token, newPassword } = req.body;
            if (!token || !newPassword) {
                res.status(400).json({ error: "Token and new password are required" });
                return;
            }
            const result = await resetPassword(pool, { token, newPassword });
            res.status(200).json(result);
        }
        catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    });
    router.get('/oauth/google', async (req, res) => {
        const googleConfig = oauthConfig?.google;
        if (googleConfig == null) {
            res.status(400).json({ error: "Google OAuth is not configured" });
            return;
        }
        if (redisClient == null) {
            res.status(400).json({ error: "Redis is required for OAuth state" })
            return
        }
        const state = crypto.randomUUID();
        await redisClient.set(`oauth_state:${state}`, "true", {
            EX: 300
        })
        const params = new URLSearchParams({
            client_id: googleConfig.clientId,
            redirect_uri: googleConfig.callbackUrl,
            response_type: 'code',
            scope: 'openid email profile',
            access_type: 'offline',
            prompt: 'consent',
            state
        });
        res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
    });
    router.get('/oauth/google/callback', async (req, res) => {
        try {
            if (redisClient == null) {
                res.status(400).json({ error: "Redis is required for OAuth state" });
                return;
            }
            const googleConfig = oauthConfig?.google;
            const state = req.query.state;
            if (typeof state !== "string" || !state) {
                res.status(400).json({ error: "OAuth state is required" });
                return;
            }
            const savedState = await redisClient.get(`oauth_state:${state}`);
            if (!savedState) {
                res.status(400).json({ error: "Invalid OAuth State" })
                return;
            }
            await redisClient.del(`oauth_state:${state}`);
            if (googleConfig == null) {
                res.status(400).json({ error: "Google OAuth is not configured" });
                return;
            }
            const code = req.query.code;
            if (typeof code !== 'string' || !code) {
                res.status(400).json({ error: "OAuth code is required" });
                return;
            }
            const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    code,
                    client_id: googleConfig.clientId,
                    client_secret: googleConfig.clientSecret,
                    redirect_uri: googleConfig.callbackUrl,
                    grant_type: 'authorization_code'
                })
            });
            const tokenData = await tokenResponse.json();
            if (!tokenResponse.ok) {
                res.status(400).json({ errorMessage: "Google OAuth token exchange failed" });
                return;
            }
            const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
                headers: { Authorization: `Bearer ${tokenData.access_token}` }
            });
            const profile = await profileResponse.json();
            if (!profileResponse.ok) {
                res.status(400).json({ error: "Failed to fetch Google profile" });
                return;
            }
            const result = await oauthLoginUser(pool, {
                provider: 'google',
                providerAccountId: profile.sub,
                email: profile.email,
                username: profile.name ?? profile.email
            }, jwtSecret, accessTokenExpiry);
            res.status(200).json(result);
        }
        catch (error: any) {
            res.status(400).json({ error: error.message });
        }
    });
    return router;
}
