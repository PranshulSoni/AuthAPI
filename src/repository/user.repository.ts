import * as db from 'pg';

export async function runMigrations(config:db.Pool){
    await config.query(`CREATE TABLE IF NOT EXISTS auth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_verified BOOLEAN NOT NULL DEFAULT false,
    email_verification_token VARCHAR(255),
    email_verification_expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    `);
    await config.query(`CREATE TABLE IF NOT EXISTS auth_token (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        refresh_token VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );`
    );
}   

export async function findUserByEmail(pool:db.Pool,email:string) {
    const results=await pool.query(`SELECT * FROM auth_users WHERE email = $1`, [email]);
    return results.rows[0]||null;
}

export async function createUser(pool:db.Pool,email:string,password:string,username:string,role:string){
    const results=await pool.query(`INSERT INTO auth_users (username, email, password, role)
    VALUES ($1, $2, $3, $4)
    RETURNING *`,[username,email,password,role]);
    return results.rows[0];
}

export async function deleteRefreshToken(pool:db.Pool,refreshToken:string) {
    const results=await pool.query(`DELETE FROM auth_token WHERE refresh_token=$1`,[refreshToken]);
    return results.rowCount;
}