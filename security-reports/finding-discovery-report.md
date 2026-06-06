# Finding Discovery Report

Scope: repository-wide AuthAPI scan.
Threat model: `artifacts/01_context/threat_model.md`.

## Candidate CAND-001: Host header controls password reset and verification URLs

- Affected locations:
  - `src/routes/auth.routes.ts:38` root_control: verification URL base is built from `req.protocol` and `req.get('host')`.
  - `src/routes/auth.routes.ts:110` root_control: password reset URL base is built from `req.protocol` and `req.get('host')`.
  - `src/services/auth.service.ts:163-165` sink: reset token is embedded into the generated reset URL and sent by email.
- Instance key: `host-header-reset-link:src/routes/auth.routes.ts:110`.
- Attacker-controlled source: HTTP Host header on unauthenticated register/forgot-password requests.
- Broken control: no configured trusted public base URL is used for security links.
- Impact: account takeover if an attacker triggers password reset for a victim with attacker-controlled Host and the victim clicks the emailed link, leaking the reset token to an attacker-controlled origin.
- Plausibility: the route uses request host directly, and forgot-password intentionally sends the reset token by email.
- Validation recommended: yes.
- Taxonomy: CWE-601, CWE-640.

## Candidate CAND-002: Google OAuth links accounts without requiring verified provider email

- Affected locations:
  - `src/services/oauth.service.ts:11-15` root_control: profile type includes optional `email_verified`.
  - `src/services/oauth.service.ts:58-63` sink/control: returned profile only requires `sub` and `email`, not `email_verified`.
  - `src/routes/auth.routes.ts:175-181` sink: profile email is passed into local OAuth login.
  - `src/services/auth.service.ts:201-205` sink: existing local account is linked by email when no provider account exists.
  - `src/repository/user.repository.ts:51-58` sink: OAuth-only users are created as verified.
- Instance key: `oauth-unverified-email-link:src/services/oauth.service.ts:58`.
- Attacker-controlled source: Google/OIDC profile email fields from an external provider response.
- Broken control: no check that provider asserted the email is verified before using it to link/create a verified local user.
- Impact: possible account takeover or creation of trusted verified accounts from unverified provider email assertions in providers/accounts where unverified email values can be returned.
- Plausibility: code explicitly models `email_verified` but does not enforce it before linking by email or creating `is_verified=true` users.
- Validation recommended: yes.
- Taxonomy: CWE-287, CWE-346.
