import { PoolConfig } from 'pg' 

export interface AuthConfig {
  db: PoolConfig
  jwtSecret: string
  accessTokenExpiry?: string
  refreshTokenExpiry?: string
  rateLimit?:{
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
