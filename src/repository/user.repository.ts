import * as db from 'pg';
import type { UserRepo, AuthUserRow, UserTableConfig } from '../types/index.js';

// ─── Default migrations (creates auth_users, auth_token, auth_accounts with FK) ───

export async function runMigrations(pool: db.Pool) {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

    await pool.query(`CREATE TABLE IF NOT EXISTS auth_users (
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

    await pool.query(`CREATE TABLE IF NOT EXISTS auth_token (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        refresh_token_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );`);

    await pool.query(`CREATE TABLE IF NOT EXISTS auth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_account_id)
    );`);

    await pool.query(`ALTER TABLE auth_users ALTER COLUMN password DROP NOT NULL;`);
}

// ─── Custom table migrations (no FK constraints, adds auth_meta for tokens) ───

export async function runCustomUserMigrations(pool: db.Pool) {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

    // auth_token without FK — works with any user table
    await pool.query(`CREATE TABLE IF NOT EXISTS auth_token (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id TEXT NOT NULL,
        refresh_token_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );`);

    // auth_accounts without FK — same
    await pool.query(`CREATE TABLE IF NOT EXISTS auth_accounts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id TEXT NOT NULL,
        provider VARCHAR(50) NOT NULL,
        provider_account_id VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        UNIQUE(provider, provider_account_id)
    );`);

    // auth_meta stores email/password reset tokens against the user's own table rows
    await pool.query(`CREATE TABLE IF NOT EXISTS auth_meta (
        user_id TEXT NOT NULL,
        email_verification_token VARCHAR(255),
        email_verification_expires_at TIMESTAMP,
        password_reset_token VARCHAR(255),
        password_reset_expires_at TIMESTAMP,
        PRIMARY KEY (user_id)
    );`);
}

// ─── Default repo (wraps existing auth_users queries) ───

export function buildDefaultUserRepo(pool: db.Pool): UserRepo {
    return {
        findByEmail: (email) => findUserByEmail(pool, email),
        findById: (id) => findUserById(pool, id),
        createUser: (email, password, username, _role, _isVerified) =>
            password === null
                ? createOAuthUser(pool, email, username, _role ?? 'user')
                : createUser(pool, email, password, username, _role ?? 'user'),
        setEmailVerificationToken: (userId, tokenHash, expiresAt) =>
            setEmailVerificationToken(pool, userId, tokenHash, expiresAt),
        verifyByEmailToken: (tokenHash) => verifyUserByEmailToken(pool, tokenHash),
        setPasswordResetToken: (userId, tokenHash, expiresAt) =>
            setPasswordResetToken(pool, userId, tokenHash, expiresAt),
        resetPasswordByToken: (tokenHash, passwordHash) =>
            resetPasswordByToken(pool, tokenHash, passwordHash),
    }
}

// ─── Custom table repo (queries user's own table, tokens go to auth_meta) ───

export function buildCustomUserRepo(pool: db.Pool, config: UserTableConfig): UserRepo {
    const t = config.name
    const c = {
        id: config.columns?.id ?? 'id',
        email: config.columns?.email ?? 'email',
        password: config.columns?.password ?? 'password',
        role: config.columns?.role ?? 'role',
        isVerified: config.columns?.isVerified ?? 'is_verified',
        username: config.columns?.username,   // undefined = no username column
    }

    // SELECT that always returns a normalized AuthUserRow shape
    function selectSql() {
        const usernameExpr = c.username ? `${c.username} AS username` : `${c.email} AS username`
        return `SELECT ${c.id} AS id, ${c.email} AS email, ${c.password} AS password, ${c.role} AS role, ${c.isVerified} AS is_verified, ${usernameExpr}`
    }

    function normalizeRow(row: Record<string, unknown>): AuthUserRow {
        return row as unknown as AuthUserRow
    }

    const repo: UserRepo = {
        async findByEmail(email) {
            const r = await pool.query(`${selectSql()} FROM ${t} WHERE ${c.email} = $1`, [email])
            return r.rows[0] ? normalizeRow(r.rows[0]) : null
        },

        async findById(id) {
            const r = await pool.query(`${selectSql()} FROM ${t} WHERE ${c.id} = $1`, [id])
            return r.rows[0] ? normalizeRow(r.rows[0]) : null
        },

        async createUser(email, password, username, role, isVerified = false) {
            const cols = [c.email, c.password, c.role, c.isVerified]
            const vals: unknown[] = [email, password, role, isVerified]

            if (c.username) {
                cols.push(c.username)
                vals.push(username)
            }

            const placeholders = vals.map((_, i) => `$${i + 1}`).join(', ')
            const r = await pool.query(
                `INSERT INTO ${t} (${cols.join(', ')}) VALUES (${placeholders}) RETURNING *`,
                vals
            )
            return normalizeRow({
                id: r.rows[0][c.id],
                email: r.rows[0][c.email],
                password: r.rows[0][c.password],
                role: r.rows[0][c.role],
                is_verified: r.rows[0][c.isVerified],
                username: c.username ? r.rows[0][c.username] : email,
            })
        },

        async setEmailVerificationToken(userId, tokenHash, expiresAt) {
            await pool.query(
                `INSERT INTO auth_meta (user_id, email_verification_token, email_verification_expires_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id) DO UPDATE
                SET email_verification_token = $2, email_verification_expires_at = $3`,
                [userId, tokenHash, expiresAt]
            )
            return repo.findById(userId)
        },

        async verifyByEmailToken(tokenHash) {
            const meta = await pool.query(
                `UPDATE auth_meta
                SET email_verification_token = NULL, email_verification_expires_at = NULL
                WHERE email_verification_token = $1 AND email_verification_expires_at > NOW()
                RETURNING user_id`,
                [tokenHash]
            )
            if (!meta.rows[0]) return null
            const userId = meta.rows[0].user_id as string
            await pool.query(`UPDATE ${t} SET ${c.isVerified} = true WHERE ${c.id} = $1`, [userId])
            return repo.findById(userId)
        },

        async setPasswordResetToken(userId, tokenHash, expiresAt) {
            await pool.query(
                `INSERT INTO auth_meta (user_id, password_reset_token, password_reset_expires_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id) DO UPDATE
                SET password_reset_token = $2, password_reset_expires_at = $3`,
                [userId, tokenHash, expiresAt]
            )
            return repo.findById(userId)
        },

        async resetPasswordByToken(tokenHash, passwordHash) {
            const meta = await pool.query(
                `UPDATE auth_meta
                SET password_reset_token = NULL, password_reset_expires_at = NULL
                WHERE password_reset_token = $1 AND password_reset_expires_at > NOW()
                RETURNING user_id`,
                [tokenHash]
            )
            if (!meta.rows[0]) return null
            const userId = meta.rows[0].user_id as string
            await pool.query(`UPDATE ${t} SET ${c.password} = $1 WHERE ${c.id} = $2`, [passwordHash, userId])
            return repo.findById(userId)
        },
    }

    return repo
}

// ─── Existing functions (unchanged — used by default repo and internal auth ops) ───

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

export async function verifyUserByEmailToken(pool: db.Pool, tokenHash: string) {
    const results = await pool.query(
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

export async function setPasswordResetToken(pool: db.Pool, userId: string, tokenHash: string, expiresAt: Date) {
    const results = await pool.query(`UPDATE auth_users
    SET password_reset_token = $1,
    password_reset_expires_at = $2
    WHERE id = $3
    RETURNING *`, [tokenHash, expiresAt, userId]);
    return results.rows[0] || null;
}

export async function resetPasswordByToken(pool: db.Pool, tokenHash: string, passwordHash: string) {
    const results = await pool.query(`UPDATE auth_users
    SET password = $1,
        password_reset_token = NULL,
        password_reset_expires_at = NULL
    WHERE password_reset_token = $2
      AND password_reset_expires_at > NOW()
    RETURNING *`, [passwordHash, tokenHash]);
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
      auth_token.user_id,
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
