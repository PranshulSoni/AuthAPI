import { AuthConfig } from "./types/index.js";
import { createPool } from "./db/client.js";
import { runMigrations } from "./repository/user.repository.js";
import { createAuthRouter } from "./routes/auth.routes.js";
import { checkUser } from "./middlewares/protect.js";
export async function createAuth(config:AuthConfig){
    const pool=createPool(config.db);
    await runMigrations(pool);
    const router=createAuthRouter(pool,config.jwtSecret,config.accessTokenExpiry ?? '15m');
    return {router,protect:checkUser(config.jwtSecret)};
}