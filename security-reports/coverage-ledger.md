# Repository Coverage Ledger

| Row | Surface | Files | Disposition | Notes |
|---|---|---|---|---|
| R1 | Password registration/login/token issuing | src/routes/auth.routes.ts, src/services/auth.service.ts, src/repository/user.repository.ts | suppressed | Passwords are hashed, service tests cover sanitized responses and login. |
| R2 | Refresh-token rotation/logout/reset invalidation | src/services/auth.service.ts, src/repository/user.repository.ts | suppressed | Rotation consumes old token and tests cover replay rejection. |
| R3 | Password reset email URL generation | src/routes/auth.routes.ts, src/services/auth.service.ts, src/services/email.service.ts | reportable | CAND-001. |
| R4 | Email verification URL generation | src/routes/auth.routes.ts, src/services/auth.service.ts, src/services/email.service.ts | reportable | Covered by CAND-001 same root control with lower impact than reset. |
| R5 | Google OAuth URL/callback/profile exchange | src/routes/auth.routes.ts, src/services/oauth.service.ts | reportable | CAND-002. |
| R6 | OAuth account linking and OAuth-only creation | src/services/auth.service.ts, src/repository/user.repository.ts | reportable | CAND-002. |
| R7 | Middleware protect/role/verified-email | src/middlewares/protect.ts, src/middlewares/requiredRole.ts, src/middlewares/is_verified.ts | suppressed | Bearer parsing and typed payload were tightened during verification. |
| R8 | Redis rate limiting and OAuth state | src/middlewares/ratelimiting.ts, src/routes/auth.routes.ts | suppressed | OAuth state has expiry and one-time deletion; tests do not cover Redis integration. |
| R9 | SQL repository layer | src/repository/user.repository.ts | suppressed | Queries are parameterized; typo in findRefreshToken was fixed during review. |
| R10 | Email provider integration | src/services/email.service.ts | suppressed | No secret in response; HTML URL content depends on CAND-001 root-control. |
