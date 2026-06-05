import * as db from 'pg'
import express from 'express'
import { loginUser, logoutUser, reAuthUser, registerUser, verifyEmail } from '../services/auth.service.js'
import { AuthConfig } from '../types/index.js';
export function createAuthRouter(pool: db.Pool, jwtSecret: string, accessTokenExpiry: string,emailConfig?:AuthConfig['email']) {
    const router = express.Router();

    router.post('/register', async (req, res) => {
        try {
            const { email, password, username } = req.body
            if(!email || !password || !username){
                res.status(400).json({ error: "Email, password and username are required" });
                return;
            }
            const verificationBaseUrl=`${req.protocol}://${req.get('host')}${req.baseUrl}/verify-email`;
            const user = await registerUser(pool, { email, password, username },emailConfig,verificationBaseUrl)
            res.status(201).json({ user })
        } catch (error: any) {
            res.status(400).json({ error: error.message })
        }
    })

    router.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body
            if(!email || !password){
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
            if(!refreshToken){
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
            if(!refreshToken){
                res.status(400).json({ error: "Refresh token is required" });
                return;
            }
            const tokens = await reAuthUser(pool, { refreshToken }, jwtSecret, accessTokenExpiry)
            res.status(200).json({ tokens })
        } catch (error: any) {
            res.status(401).json({ error: error.message })
        }
    });
    router.get('/verify-email', async (req, res) => {
        try {
            const token=req.query.token;
            if(typeof token !== 'string' || !token){
                res.status(400).json({ error: "Verification failed" });
                return;
            }
            const user=await verifyEmail(pool,token);
            res.status(200).json({ user });
        } catch (error:any) {
            res.status(400).json({ error: error.message });
        }
    });
    return router;
}
