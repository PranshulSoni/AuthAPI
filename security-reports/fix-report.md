# Fix Report

## Fixed Findings

### CAND-001: Host header controls security email URLs

Fixed by adding `AuthConfig.appBaseUrl` and building verification/reset URLs from that configured trusted base URL instead of `req.get('host')`.

Regression coverage: `tests/security-fixes.test.js` verifies a hostile Host header does not affect the verification email URL.

### CAND-002: OAuth account linking ignores provider email verification

Fixed by requiring `profile.email_verified === true` in `getGoogleOAuthProfile` before returning the profile to the route/account-linking layer.

Regression coverage: `tests/security-fixes.test.js` verifies unverified Google profiles are rejected and verified profiles are accepted.

## Verification

- `npm run typecheck`: passed
- `npm test`: passed, 9/9 tests
- `npm audit --json`: 0 vulnerabilities
