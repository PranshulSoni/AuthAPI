import { PoolConfig } from 'pg' 

export interface AuthConfig {
  db: PoolConfig
  jwtSecret: string
  accessTokenExpiry?: string
  refreshTokenExpiry?: string
  email?: {
    provider: string
    apiKey: string
    from: string
  }
}