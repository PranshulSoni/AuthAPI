import { Request, Response, NextFunction } from 'express'
import { AuthenticatedRequest } from '../types/authenticated-request.js';

export function requireRole(role:string) {
    return async (req:Request,res:Response,next:NextFunction)=>{
        const user=(req as AuthenticatedRequest).user;
        if(!user){
            res.status(401).json({ error: "Unauthorized" });
            return;
        }

        if(user.role !== role){
            res.status(403).json({ error: "Forbidden" });
            return;
        }
        next();
    }
}
