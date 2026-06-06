import { Request, Response, NextFunction } from 'express'
interface RateLimitOptions {
    prefix: string
    max: number
    windowSeconds: number
}

export function authRateLimiter(redisClient:any,options:RateLimitOptions){
    return async (req: Request, res: Response, next: NextFunction) => {
        const key=`rate_limit:${options.prefix}:${req.ip}`
        const count=await redisClient.incr(key);
        if(count===1){
            await redisClient.expire(key,options.windowSeconds);
        }   
        if(count>options.max){
            res.status(429).json({error: "Too many requests. Please try again later."});
            return;
        }
        next();
    }
}



export function createAuthRateLimiters(redisClient:any) {
    return {
        registerLimiter: authRateLimiter(redisClient, {
            prefix:"register",
            max:10,
            windowSeconds:15*60
        }),

        loginLimiter: authRateLimiter(redisClient, {
            prefix:"login",
            max:5,
            windowSeconds:15*60
        }),

        forgotPasswordLimiter: authRateLimiter(redisClient, {
            prefix:"forgot_password",
            max:3,
            windowSeconds:15*60
        }),

        resetPasswordLimiter: authRateLimiter(redisClient, {
            prefix:"reset_password",
            max:5,
            windowSeconds: 15*60
        })
    }
}
