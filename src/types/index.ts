import { PoolConfig } from 'pg'

export interface UserTableColumns {
    id?: string         // default: 'id'
    email?: string      // default: 'email'
    password?: string   // default: 'password'
    role?: string       // default: 'role'
    isVerified?: string // default: 'is_verified'
    username?: string   // default: 'username' — omit if your table has no username column
}

export interface UserTableConfig {
    name: string
    columns?: UserTableColumns
}

// Shape every user row must conform to internally
export interface AuthUserRow {
    id: string
    username?: string
    email: string
    password?: string | null
    role: string
    is_verified: boolean
    [key: string]: unknown
}

// What auth service functions depend on — implemented by default or custom repo
export interface UserRepo {
    findByEmail(email: string): Promise<AuthUserRow | null>
    findById(id: string): Promise<AuthUserRow | null>
    createUser(email: string, password: string | null, username: string, role: string, isVerified?: boolean): Promise<AuthUserRow>
    setEmailVerificationToken(userId: string, tokenHash: string, expiresAt: Date): Promise<AuthUserRow | null>
    verifyByEmailToken(tokenHash: string): Promise<AuthUserRow | null>
    setPasswordResetToken(userId: string, tokenHash: string, expiresAt: Date): Promise<AuthUserRow | null>
    resetPasswordByToken(tokenHash: string, passwordHash: string): Promise<AuthUserRow | null>
}

export interface AuthConfig {
    db: PoolConfig
    jwtSecret: string
    userTable?: UserTableConfig
    urls?: {
        apiBaseUrl: string
        frontendBaseUrl?: string
    }
    accessTokenExpiry?: string
    refreshTokenExpiry?: string
    rateLimit?: {
        redisUrl: string
    }
    email?: {
        provider: string
        apiKey: string
        from: string
    }
    oauth?: {
        google?: {
            clientId: string
            clientSecret: string
            callbackUrl: string
        }
    }
}
