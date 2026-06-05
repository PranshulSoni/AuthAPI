import * as db from 'pg'
import express from 'express'
import { loginUser, logoutUser, registerUser } from '../services/auth.service.js'

export function createAuthRouter(pool: db.Pool, jwtSecret: string, accessTokenExpiry: string) {
    const router = express.Router();

    router.post('/register', async (req, res) => {
        try {
            const { email, password, username } = req.body
            const user = await registerUser(pool, { email, password, username })
            res.status(201).json({ user })
        } catch (error: any) {
            res.status(400).json({ error: error.message })
        }
    })

    router.post('/login', async (req, res) => {
        try {
            const {email,password} = req.body
            const result = await loginUser(pool,{ email, password},jwtSecret,accessTokenExpiry)
            res.status(200).json(result)
        } catch (error: any) {
            res.status(400).json({ error: error.message })
        }
    })
    
    router.delete('/logout',async (req,res)=>{
        try{
            const { refreshToken } = req.body
            const result = await logoutUser(pool,{ refreshToken })
            res.status(200).json(result)
        } catch (error:any) {
            res.status(400).json({ error: error.message })
        }
    });

    return router;
}