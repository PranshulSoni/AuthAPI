import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken';
import { AuthPayload, AuthenticatedRequest } from '../types/authenticated-request.js';

function resolveSecret(jwtSecret: string | (() => string)): string {
    return typeof jwtSecret === "function" ? jwtSecret() : jwtSecret
}

export function checkUser(jwtSecret: string | (() => string)) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers.authorization;
        if (authHeader == null) {
            res.status(401).json({ error: "Unauthorized" });
            return;
        }

        const [scheme, token] = authHeader.split(' ');
        if (scheme !== 'Bearer' || !token) {
            res.status(401).json({ error: "Unauthorized" });
            return;
        }

        try {
            const ver = jwt.verify(token, resolveSecret(jwtSecret)) as AuthPayload;
            (req as AuthenticatedRequest).user = ver;
            next();
        } catch (error) {
            res.status(401).json({ error: "Unauthorized" });
        }
    }
}
