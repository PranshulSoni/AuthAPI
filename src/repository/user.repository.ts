import * as db from 'pg';

export async function runMigrations(config: db.Pool) {
    await config.query(`CREATE TABLE IF NOT EXISTS auth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_verified BOOLEAN NOT NULL DEFAULT false,
    email_verification_token VARCHAR(255),
    email_verification_expires_at TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    );`);
    await config.query(`CREATE TABLE IF NOT EXISTS auth_token (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        refresh_token_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );`
    );
    await config.query(`CREATE TABLE IF NOT EXISTS auth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_account_id)
    );`);

    await config.query(`ALTER TABLE auth_users ALTER COLUMN password DROP NOT NULL;`);
}

export async function findUserByEmail(pool: db.Pool, email: string) {
    const results = await pool.query(`SELECT * FROM auth_users WHERE email = $1`, [email]);
    return results.rows[0] || null;
}

export async function findUserById(pool: db.Pool, id: string) {
    const results = await pool.query(`SELECT * FROM auth_users WHERE id = $1`, [id]);
    return results.rows[0] || null;
}

export async function createUser(pool: db.Pool, email: string, password: string, username: string, role: string) {
    const results = await pool.query(`INSERT INTO auth_users (username, email, password, role)
    VALUES ($1, $2, $3, $4)
    RETURNING *`, [username, email, password, role]);
    return results.rows[0];
}

export async function createOAuthUser(pool: db.Pool, email: string, username: string, role: string) {
    const results = await pool.query(
        `INSERT INTO auth_users (username, email, password, role, is_verified)
        VALUES ($1, $2, NULL, $3, true)
        RETURNING *`,
        [username, email, role]
    );
    return results.rows[0];
}

export async function findAuthAccount(pool: db.Pool, provider: string, providerAccountId: string) {
    const results = await pool.query(
        `SELECT * FROM auth_accounts
        WHERE provider = $1
          AND provider_account_id = $2`,
        [provider, providerAccountId]
    );
    return results.rows[0] || null;
}

export async function findUserByAuthAccount(pool: db.Pool, provider: string, providerAccountId: string) {
    const results = await pool.query(
        `SELECT auth_users.*
        FROM auth_accounts
        JOIN auth_users
          ON auth_accounts.user_id = auth_users.id
        WHERE auth_accounts.provider = $1
          AND auth_accounts.provider_account_id = $2`,
        [provider, providerAccountId]
    );
    return results.rows[0] || null;
}

export async function createAuthAccount(
    pool: db.Pool,
    userId: string,
    provider: string,
    providerAccountId: string,
    email?: string
) {
    const results = await pool.query(
        `INSERT INTO auth_accounts (user_id, provider, provider_account_id, email)
        VALUES ($1, $2, $3, $4)
        RETURNING *`,
        [userId, provider, providerAccountId, email ?? null]
    );
    return results.rows[0];
}

export async function setEmailVerificationToken(pool: db.Pool, userId: string, tokenHash: string, expiresAt: Date) {
    const results = await pool.query(
        `UPDATE auth_users
        SET email_verification_token=$1,
            email_verification_expires_at=$2
        WHERE id=$3
        RETURNING *`,
        [tokenHash, expiresAt, userId]
    );
    return results.rows[0] || null;
}

export async function verifyUserByEmailToken(pool:db.Pool, tokenHash:string) {
    const results=await pool.query(
        `UPDATE auth_users
        SET is_verified=true,
            email_verification_token=NULL,
            email_verification_expires_at=NULL
        WHERE email_verification_token=$1
          AND email_verification_expires_at > NOW()
        RETURNING *`,
        [tokenHash]
    );
    return results.rows[0] || null;
}

export async function setPasswordResetToken(pool:db.Pool,userId:string,tokenHash:string,expiresAt:Date){
    const results=await pool.query(`UPDATE auth_users
    SET password_reset_token = $1,
    password_reset_expires_at = $2
    WHERE id = $3
    RETURNING *`,[tokenHash,expiresAt,userId]);
    return results.rows[0]||null;
}

export async function resetPasswordByToken(pool:db.Pool,tokenHash:string,passwordHash:string) {
    const results=await pool.query(`UPDATE auth_users
    SET password = $1,
        password_reset_token = NULL,
        password_reset_expires_at = NULL
    WHERE password_reset_token = $2
      AND password_reset_expires_at > NOW()
    RETURNING *`,[passwordHash,tokenHash]);
    return results.rows[0];
}

export async function deleteRefreshToken(pool: db.Pool, refreshTokenHash: string) {
    const results = await pool.query(`DELETE FROM auth_token WHERE refresh_token_hash=$1`, [refreshTokenHash]);
    return results.rowCount;
}

export async function deleteAllRefreshTokens(pool: db.Pool, userId: string) {
    const results = await pool.query(`DELETE FROM auth_token WHERE user_id=$1`, [userId]);
    return results.rowCount;
}

export async function consumeRefreshToken(pool: db.Pool, refreshTokenHash: string) {
    const results = await pool.query(
        `DELETE FROM auth_token
        WHERE refresh_token_hash=$1
          AND expires_at > NOW()
        RETURNING user_id`,
        [refreshTokenHash]
    );
    return results.rows[0] || null;
}

export async function storeRefreshToken(pool: db.Pool, userId: string, refreshTokenHash: string, expiresAt: Date) {
    await pool.query(
        `INSERT INTO auth_token (user_id, refresh_token_hash, expires_at)
        VALUES ($1, $2, $3)`,
        [userId, refreshTokenHash, expiresAt]
    );
}

export async function findRefreshToken(pool: db.Pool, refreshTokenHash: string) {
    const result = await pool.query(`
    SELECT 
      auth_token.id,
      auth_token.user_id,c
      auth_token.refresh_token_hash,
      auth_token.expires_at,
      auth_users.role
    FROM auth_token
    JOIN auth_users 
      ON auth_token.user_id = auth_users.id
    WHERE auth_token.refresh_token_hash = $1
      AND auth_token.expires_at > NOW()
  `, [refreshTokenHash]);
    return result.rows[0];
}
