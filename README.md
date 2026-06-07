# AuthAPI

Drop-in authentication system for Express.js backed by PostgreSQL. One function call gives you a full auth router, JWT middleware, and role/email-verification guards — without you writing any of it.

```bash
npm install authapi
```

**Requirements:** Node.js 22+, PostgreSQL 14+, Redis 7+ (optional — rate limiting and OAuth only)

---

## The problem

Every backend project needs the same auth plumbing: register, login, JWT, refresh tokens, forgot password, email verification, OAuth. It gets rebuilt from scratch every time, and the security mistakes are always the same — plaintext tokens stored in the DB, different error messages for "wrong password" vs "email not found", no timing protection, mass assignment letting users set `role: "admin"` on registration.

AuthAPI handles all of that correctly. You configure it, mount the router, use the middleware.

---

## Quick start

```js
import express from 'express';
import { createAuth } from 'authapi';

const app = express();
app.use(express.json());

const { router, protect, requireRole, requireVerifiedEmail } = await createAuth({
  db: {
    host: 'localhost',
    port: 5432,
    user: 'postgres',
    password: 'postgres',
    database: 'myapp',
  },
  jwtSecret: process.env.JWT_SECRET,
});

app.use('/auth', router);

app.get('/api/profile', protect, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

Tables (`auth_users`, `auth_token`, `auth_accounts`) are created automatically on startup. No manual migration needed.

---

## Configuration

```ts
await createAuth({
  // Required
  db: PoolConfig,           // any pg.PoolConfig — host, port, user, password, database, ssl...
  jwtSecret: string,        // min 32 chars, keep it in env

  // Optional
  accessTokenExpiry?: string,       // default '15m'. e.g. '1h', '7d'

  urls?: {
    apiBaseUrl: string,             // e.g. 'https://api.myapp.com'
    frontendBaseUrl?: string,       // if set, password reset links go here instead
  },

  email?: {
    provider: 'resend',
    apiKey: string,
    from: string,                   // e.g. 'noreply@myapp.com'
  },

  rateLimit?: {
    redisUrl: string,               // enables rate limiting + required for OAuth
  },

  oauth?: {
    google?: {
      clientId: string,
      clientSecret: string,
      callbackUrl: string,          // e.g. 'https://api.myapp.com/auth/oauth/google/callback'
    },
  },
});
```

---

## Routes

All routes mount under wherever you put `app.use('/auth', router)`.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Get access + refresh tokens |
| POST | `/auth/refresh` | Rotate refresh token, get new pair |
| DELETE | `/auth/logout` | Invalidate one session |
| GET | `/auth/verify-email?token=` | Confirm email address |
| POST | `/auth/forgot-password` | Send reset email |
| POST | `/auth/reset-password` | Set new password, invalidate all sessions |
| GET | `/auth/oauth/google` | Start Google OAuth flow |
| GET | `/auth/oauth/google/callback` | Google redirects here after consent |

### Register

```json
POST /auth/register
{ "email": "user@example.com", "password": "MyStr0ng!Pass", "username": "johndoe" }

201 { "user": { "id": "...", "email": "...", "username": "...", "role": "user", "is_verified": false } }
```

Password must be 8+ chars with at least one uppercase, one digit, one special character. Email is normalized to lowercase. Username rejects `<` and `>` to prevent stored XSS. The `role` and `is_verified` fields are always ignored from the request body — mass assignment is blocked at the service level.

If `email` config is set, a verification email is sent automatically.

### Login

```json
POST /auth/login
{ "email": "user@example.com", "password": "MyStr0ng!Pass" }

200 { "user": { ... }, "tokens": { "accessToken": "eyJ...", "refreshToken": "uuid" } }
```

Returns `"Invalid email or password"` for both wrong password and non-existent email. A dummy bcrypt comparison runs for non-existent users to equalize response time — the two cases are indistinguishable from the network.

### Refresh

```json
POST /auth/refresh
{ "refreshToken": "uuid" }

200 { "accessToken": "eyJ...", "refreshToken": "new-uuid" }
```

The old token is atomically consumed (deleted) and a new pair is issued. Using the same refresh token twice returns 401 on the second attempt.

### Forgot / reset password

`POST /auth/forgot-password` accepts an email and always returns the same message regardless of whether the account exists. Reset links expire after 15 minutes, are single-use, and clearing the token after use is handled by the UPDATE query itself. On successful reset, all refresh tokens for that user are deleted — forces re-login on every device.

### Google OAuth

`GET /auth/oauth/google` redirects to Google with a UUID state parameter stored in Redis (5-minute TTL). Google redirects back to `/auth/oauth/google/callback`, where the state is validated and deleted (single-use CSRF protection), the authorization code is exchanged, and the profile is fetched. Profiles with `email_verified: false` are rejected.

Account linking: if the Google `sub` already has an entry in `auth_accounts`, that user is logged in. If not but the email matches an existing user, the account is linked. Otherwise a new user is created with `is_verified: true` and no password.

---

## Middleware

```js
const { protect, requireRole, requireVerifiedEmail } = await createAuth(config);

// Require a valid JWT — adds req.user = { userId, role, isVerified, iat, exp }
app.get('/api/profile', protect, handler);

// Require a specific role (use after protect)
app.delete('/api/users/:id', protect, requireRole('admin'), handler);

// Require email to be verified (use after protect)
app.post('/api/posts', protect, requireVerifiedEmail(), handler);

// Chain them
app.post('/api/admin/thing', protect, requireRole('admin'), requireVerifiedEmail(), handler);
```

`protect` returns 401 if the header is missing, malformed, or the JWT is invalid/expired. `requireRole` returns 403 if the role doesn't match. `requireVerifiedEmail` returns 403 with `"Email is not verified"`.

---

## How tokens work

Access tokens are short-lived JWTs containing `{ userId, role, isVerified }`. They are never stored — verified on every request with `jwt.verify()`.

Refresh tokens are random UUIDs. Only a SHA-256 hash of the token is stored in `auth_token`. When a refresh is requested, the hash is looked up, the row is deleted in the same query, and a new pair is issued. This means stolen DB access doesn't give you usable tokens, and concurrent refresh attempts can't both succeed.

---

## Security

These aren't just documented — they're tested against 273 cases across 11 attack levels.

**Timing attack prevention.** Login runs `bcrypt.compare()` even when the email doesn't exist in the database (against a dummy hash). This equalizes response time so an attacker can't distinguish "email not found" from "wrong password" by measuring latency.

**Token hashing.** Refresh tokens and email/password reset tokens are stored as SHA-256 hashes. The raw token is never persisted. If your database is dumped, none of those tokens are usable.

**Atomic refresh token rotation.** The `DELETE ... RETURNING` query consumes and returns a refresh token in a single atomic operation. Two concurrent requests with the same token can't both succeed — the second one gets nothing back.

**Mass assignment.** `role` is hardcoded to `'user'` at the service layer regardless of what the client sends. `is_verified` and `id` are equally ignored. There's no path from user input to privilege escalation on registration.

**Session invalidation on password reset.** All rows in `auth_token` for that user are deleted when a password reset succeeds. If an attacker triggered the reset or you're locking a compromised account, all active sessions die immediately.

**Single-use tokens.** Both email verification and password reset tokens are NULLed in the same UPDATE that validates them. Replaying a token returns an error — the lookup finds nothing.

**OAuth CSRF protection.** The `state` parameter is a UUID stored in Redis with a 5-minute TTL. The callback handler deletes the key before doing anything else. Replaying the same state after the first callback returns `400 Invalid OAuth State`.

**User enumeration prevention.** Login, forgot-password, and register return generic error messages that don't distinguish between "this email exists" and "it doesn't". The response body and response time are both equalized.

**Input validation.** Email is lowercased and trimmed before any comparison or storage. Usernames reject `<` and `>` to block stored XSS at the input boundary. All SQL interactions use parameterized queries — the pg driver handles escaping.

**JWT algorithm enforcement.** Tokens are verified with `jwt.verify(token, secret)` — the secret string form, not a key object. The jsonwebtoken library enforces HS256. `alg:none`, `alg:None`, and RS256-with-public-key-as-HMAC attacks all fail.

**No password in tokens or responses.** The `sanitizeUser` function strips the password hash before returning any user object. JWT payload contains only `userId`, `role`, and `isVerified` — nothing that helps an attacker if a token is intercepted.

---


## Database schema

Three tables, created by `runMigrations` on startup:

**auth_users** — `id` (UUID PK), `username`, `email` (unique), `password` (nullable, bcrypt hash), `role` (default `'user'`), `is_verified` (default `false`), `email_verification_token`, `email_verification_expires_at`, `password_reset_token`, `password_reset_expires_at`, `created_at`, `updated_at`

**auth_token** — `id`, `user_id` (FK → auth_users, cascade delete), `refresh_token_hash`, `expires_at` (30 days), `created_at`

**auth_accounts** — `id`, `user_id` (FK), `provider`, `provider_account_id`, `email`, `created_at`. Unique on `(provider, provider_account_id)`.

---

## Rate limits

When `rateLimit.redisUrl` is set, the following limits apply per IP per 15-minute window:

| Endpoint | Limit |
|----------|-------|
| `/auth/login` | 5 |
| `/auth/register` | 10 |
| `/auth/forgot-password` | 3 |
| `/auth/reset-password` | 5 |

Returns `429` with `{ "error": "Too many requests. Please try again later." }`.

---

## Production checklist

**JWT secret** — generate a proper random secret, not a dictionary word:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
```

**Error handler** — add a global Express error middleware after your routes so body-parser errors (malformed JSON, oversized payloads) don't return HTML with stack traces:
```js
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500;
  res.status(status).json({ error: err.message || 'Something went wrong' });
});
```

**HTTPS** — access tokens travel in `Authorization` headers. TLS is not optional.

**OAuth requires Redis** — the CSRF state parameter needs somewhere to live. If you configure `oauth.google`, you must also set `rateLimit.redisUrl`.

**Email config requires `urls`** — if `email` is set, `urls.apiBaseUrl` is required so the package can construct verification links.

---

## Security test coverage

Tested against 273 cases across 11 levels: input validation, auth flows, JWT attacks (alg:none, key confusion, tampered payload), session management, password security, rate limiting, SQL injection, XSS, command injection, path traversal, prototype pollution, IDOR, authorization bypass, OAuth CSRF, account enumeration timing, credential stuffing, race conditions, HTTP verb tampering, large payload DoS.

All 273 pass.

---

## License

ISC
