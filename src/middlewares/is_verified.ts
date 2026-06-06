import { Request, Response, NextFunction } from 'express'
export function requireVerifiedEmail() {
    return (req:Request,res:Response,next:NextFunction)=>{
        const user=(req as any).user;

        if(!user){
            res.status(401).json({ error: "Unauthorized" });
            return;
        }

        if(!user.isVerified){
            res.status(403).json({ error: "Email is not verified" });
            return;
        }

        next();
    }
}