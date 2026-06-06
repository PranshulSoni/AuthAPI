import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken';
export function checkUser(jwtSecret: string) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers.authorization;
        if (authHeader == null) {
            res.status(400).send();
        } else {
            try {
                const token = authHeader.split(' ')[1];
                const ver = jwt.verify(token, jwtSecret);
                (req as any).user = ver
                next()
            } catch (error) {
                res.status(401).json({ error: "Unauthorized" })
            }
        }
    }
}