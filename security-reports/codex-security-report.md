# Security Review: AuthAPI

## Scope

- Scan mode: repository-wide AuthAPI security scan.
- In-scope code: `src/**`, package scripts, and service tests.
- Threat model: generated during Phase 1 and saved at `artifacts/01_context/threat_model.md`.
- Validation mode: static code tracing plus local build/test/audit checks.
- Runtime checks run: `npm run typecheck`, `npm test`, `npm audit --json`.
- Limitations: live Google OAuth and Resend delivery were not exercised because credentials/callback infrastructure are not present.

### Scan Summary

| Field | Value |
|---|---|
| Reportable findings | 2 |
| Severity mix | 1 high, 1 medium |
| Confidence mix | 1 high, 1 medium |
| Coverage | 10 repository auth/security surfaces tracked in coverage ledger |
| Artifacts | `C:\Users\PRANSH~1\AppData\Local\Temp\codex-security-scans\AuthAPI\9cad2ab_20260607T025746` |

## Threat Model

AuthAPI is a Node.js/Express TypeScript authentication package. It exposes an Express router and middleware that downstream applications mount into their own server. The package manages local email/password authentication, JWT access tokens, database-backed refresh tokens, email verification, password reset, Redis-backed rate limiting and OAuth state, Google OAuth login, role checks, and verified-email checks.

Important assets are user credentials and hashes, JWT signing secret, access tokens, refresh tokens, password reset tokens, email verification tokens, OAuth account bindings, Redis OAuth state, Resend API keys, OAuth client secrets, and PostgreSQL integrity. Trust boundaries include public HTTP routes, middleware authorization boundaries, database queries, Redis state, Google OAuth responses, email provider calls, and package-consumer configuration.

Security invariants include: raw tokens/passwords must not be stored or returned; refresh token rotation must invalidate old tokens; logout/reset must invalidate refresh state; OAuth state must be one-time use; OAuth linking must bind by provider account ID first; repository queries must stay parameterized; and middleware authorization must trust only successfully verified JWT payloads.

High-impact failures include authentication bypass, account takeover through OAuth/reset weaknesses, refresh token replay, sensitive token leakage, SQL injection, role/verification bypass, brute force, and unsafe package defaults.

## Findings

| # | Severity | Confidence | Title |
|---|---|---|---|
| 1 | high | high | [Host header controls emailed password reset URLs](#1-host-header-controls-emailed-password-reset-urls) |
| 2 | medium | medium | [OAuth account linking ignores provider email verification](#2-oauth-account-linking-ignores-provider-email-verification) |

### Confidence Scale

| Label | Meaning |
|---|---|
| high | Direct source, configuration, or runtime evidence supports the finding, with no material unresolved reachability blocker. |
| medium | Source evidence supports a plausible issue, but live provider/runtime behavior still needs proof. |
| low | Weak or incomplete evidence; not used in this report. |

### [1] Host header controls emailed password reset URLs

| Field | Value |
|---|---|
| Severity | high |
| Confidence | high |
| Confidence rationale | Direct code trace shows unauthenticated Host header data flows into emailed reset links containing raw reset tokens. |
| Category | Host header poisoning / password reset token disclosure |
| CWE | CWE-601 Open Redirect; CWE-640 Weak Password Recovery Mechanism |
| Affected lines | `src/routes/auth.routes.ts:38`, `src/routes/auth.routes.ts:110`, `src/services/auth.service.ts:163-165` |

#### Summary

`/forgot-password` builds the reset URL from `req.protocol` and `req.get('host')`. Because Host is request-controlled unless the host application/proxy enforces a strict allowlist, an attacker can cause reset emails to contain attacker-domain links with valid reset tokens.

#### Validation

Validation used code tracing. The reset route constructs `resetBaseUrl` from request metadata, `forgotPassword` appends the raw reset token, stores only its hash, and sends the raw-token URL by email. No repository config provides a trusted public base URL.

#### Dataflow

`Host header` -> `req.get('host')` in `auth.routes.ts` -> `resetBaseUrl` -> `forgotPassword` -> `resetUrl?token=<raw token>` -> `sendPasswordResetEmail` email HTML.

#### Reachability

The endpoint is unauthenticated. An attacker who knows a victim email can trigger a reset email with a poisoned Host header. If the victim clicks the link, the token is sent to an attacker-controlled origin and can be replayed to the real reset endpoint.

#### Severity

High. The impact is account takeover, the route is unauthenticated, and the victim interaction is the normal password reset click. It is not critical because exploitation depends on Host handling and user click behavior.

#### Remediation

Add a trusted public base URL to package config and build reset/verification URLs from that value. Add tests proving hostile Host headers do not affect emailed security links.

### [2] OAuth account linking ignores provider email verification

| Field | Value |
|---|---|
| Severity | medium |
| Confidence | medium |
| Confidence rationale | Static evidence shows `email_verified` is modeled but ignored; live Google provider behavior was not reproduced. |
| Category | OAuth identity trust / account linking weakness |
| CWE | CWE-287 Improper Authentication; CWE-346 Origin Validation Error |
| Affected lines | `src/services/oauth.service.ts:58-63`, `src/routes/auth.routes.ts:175-181`, `src/services/auth.service.ts:201-205`, `src/repository/user.repository.ts:51-58` |

#### Summary

The OAuth callback accepts a Google profile when `sub` and `email` are present. It does not require `email_verified === true` before using the email to link an existing local account or create an OAuth-only user marked verified.

#### Validation

Validation used code tracing. `GoogleOAuthProfile` includes `email_verified`, but `getGoogleOAuthProfile` does not enforce it. The route passes `profile.email` to `oauthLoginUser`, which links by email or creates a verified OAuth user.

#### Dataflow

`Google userinfo profile` -> `getGoogleOAuthProfile` accepts `sub/email` -> callback passes `profile.email` -> `oauthLoginUser` checks existing provider account, then falls back to `findUserByEmail`, then links/creates account.

#### Reachability

The OAuth flow is public pre-login functionality. For Google-only normal Gmail accounts, likelihood is reduced because Google usually returns verified email. The package still crosses a provider trust boundary without enforcing the email verification assertion.

#### Severity

Medium. The consequence can be account trust confusion or takeover in provider scenarios where unverified email values are returned. The uncertainty around normal Google behavior keeps it below high.

#### Remediation

Reject provider profiles unless `email_verified === true` before calling `oauthLoginUser`. Add tests for rejected unverified profiles.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
|---|---|---|---|
| Password registration/login/token issuing | Credential handling | No issue found | Passwords are hashed and responses are sanitized in tests. |
| Refresh-token rotation | Replay/revocation | No issue found | Tests confirm replay rejection after rotation. |
| Password reset URLs | Account takeover | Reported | Finding 1. |
| Email verification URLs | Token leakage | Reported | Same root control as Finding 1, lower impact. |
| Google OAuth callback | Identity trust | Reported | Finding 2. |
| OAuth account linking | Account takeover/linking | Reported | Finding 2. |
| JWT middleware | Auth bypass | No issue found | Bearer parsing was tightened during scan. |
| Redis OAuth state | CSRF/OAuth replay | No issue found | State expires and is deleted after validation. |
| SQL repository | Injection | No issue found | Queries are parameterized; typo in `findRefreshToken` fixed. |
| Dependency tree | Known vulnerable deps | No issue found | `npm audit` reported zero vulnerabilities. |

## Open Questions And Follow Up

- Add integration tests with Express around Host header behavior after fixing Finding 1.
- Add OAuth service unit tests using mocked `fetch` for verified and unverified Google profiles.
- Consider making Redis configuration explicit for OAuth state rather than relying on rate-limit Redis config.
