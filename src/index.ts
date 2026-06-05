import { AuthConfig } from "./types/index.js";
import { createPool } from "./db/client.js";
import { runMigrations } from "./repository/user.repository.js";
import * as db from "pg";

export async function createAuth(config:AuthConfig){
    const pool=createPool(config.db);
    await runMigrations(pool);
}