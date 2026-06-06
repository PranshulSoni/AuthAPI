import { AuthConfig } from "./types/index.js";
import { createPool } from "./db/client.js";
import { runMigrations } from "./repository/user.repository.js";
import { createAuthRouter } from "./routes/auth.routes.js";
import { checkUser } from "./middlewares/protect.js";
import { requireRole } from "./middlewares/requiredRole.js";
import { requireVerifiedEmail } from "./middlewares/is_verified.js";
import { createAuthRateLimiters } from "./middlewares/ratelimiting.js";
import { createClient } from 'redis';
export async function createAuth(config:AuthConfig){
    const pool=createPool(config.db);
    await runMigrations(pool);
    let limiter;
    let redisClient;
    if(config.rateLimit){
        redisClient=createClient({
            url:config.rateLimit?.redisUrl
        });
        await redisClient.connect();
        limiter=createAuthRateLimiters(redisClient);
    }
    const router=createAuthRouter(pool,config.jwtSecret,config.accessTokenExpiry ?? '15m',config.email,limiter,config.oauth,redisClient);
    const protect=checkUser(config.jwtSecret);

    return {router,protect,requireRole,requireVerifiedEmail};

}
