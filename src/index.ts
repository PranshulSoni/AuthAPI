import type { AuthConfig } from "./types/index.js";
import { createPool } from "./db/client.js";
import { runMigrations, runCustomUserMigrations, buildDefaultUserRepo, buildCustomUserRepo } from "./repository/user.repository.js";
import { createAuthRouter } from "./routes/auth.routes.js";
import { checkUser } from "./middlewares/protect.js";
import { requireRole } from "./middlewares/requiredRole.js";
import { requireVerifiedEmail } from "./middlewares/is_verified.js";
import { createAuthRateLimiters } from "./middlewares/ratelimiting.js";
import { createClient } from 'redis';

export async function createAuth(config: AuthConfig) {
    const pool = createPool(config.db);

    // Choose migration + repo strategy based on whether user has their own table
    let repo: ReturnType<typeof buildDefaultUserRepo>
    if (config.userTable) {
        await runCustomUserMigrations(pool)
        repo = buildCustomUserRepo(pool, config.userTable)
    } else {
        await runMigrations(pool)
        repo = buildDefaultUserRepo(pool)
    }

    let limiter: ReturnType<typeof createAuthRateLimiters> | undefined
    let redisClient: Awaited<ReturnType<typeof createClient>> | undefined
    if (config.rateLimit) {
        redisClient = createClient({ url: config.rateLimit.redisUrl });
        await redisClient.connect();
        limiter = createAuthRateLimiters(redisClient as any);
    }

    const router = createAuthRouter(
        repo,
        pool,
        config.jwtSecret,
        config.accessTokenExpiry ?? '15m',
        config.email,
        limiter,
        config.oauth,
        redisClient as any,
        config.urls
    );

    const protect = checkUser(config.jwtSecret);

    return { router, protect, requireRole, requireVerifiedEmail };
}

export type { AuthConfig, UserTableConfig, UserTableColumns, UserRepo, AuthUserRow } from "./types/index.js";
