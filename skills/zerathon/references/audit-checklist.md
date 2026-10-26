# Zerathon Audit Checklist

## Contents
1. Secrets and config
2. Authentication and sessions
3. Authorization
4. Input handling
5. AI / LLM features
6. Transport and headers
7. Infrastructure
8. Detection, response, recovery

## 1. Secrets and config
- [ ] No API keys, tokens, or passwords in source, frontend bundles, or git history (run `scan_secrets`, and a tool like gitleaks).
- [ ] Secrets come from environment variables or a secret manager; `.env` is git-ignored.
- [ ] Any exposed secret is rotated, not just deleted.
- [ ] Separate keys for dev and prod; least-privilege scopes.
- [ ] BYOK apps: user-supplied keys are encrypted at rest or kept client-side only, never logged.

## 2. Authentication and sessions
- [ ] Passwords hashed with argon2id or bcrypt; never stored or logged in plain text.
- [ ] Login and password reset are rate limited; generic error messages (no user enumeration).
- [ ] 2FA available (TOTP or passkeys); required for admin.
- [ ] Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax/Strict`; short expiry; rotate on login and privilege change.
- [ ] Logout and "log out all devices" invalidate server-side.
- [ ] JWTs: verify signature and algorithm, short TTL, refresh-token rotation.

## 3. Authorization
- [ ] Every endpoint checks the user's permission server-side (not just hides a button).
- [ ] No IDOR: object IDs are checked against the owner, not trusted from the request.
- [ ] Admin routes are separated and protected; default role is least privilege.

## 4. Input handling
- [ ] Parameterized queries / ORM only; no string-built SQL.
- [ ] Output encoding / framework auto-escaping; no `innerHTML` or `dangerouslySetInnerHTML` with user data.
- [ ] File uploads: allowlist type by content (not just extension), size limit, random filename, stored outside web root, never executed.
- [ ] SSRF: block requests to internal IPs (127.0.0.1, 169.254.169.254, 10/8, 172.16/12, 192.168/16) in any URL-fetching feature.
- [ ] CSRF protection on state-changing requests (tokens or SameSite + origin check).
- [ ] Request body size limits and JSON schema validation.

## 5. AI / LLM features
- [ ] System prompt contains no secrets; assume it can leak.
- [ ] User text and retrieved web/file content wrapped as data, never concatenated into instructions.
- [ ] Tool/agent permissions are least-privilege; confirm destructive actions with the user.
- [ ] LLM output is treated as untrusted (escape before rendering, validate before executing).
- [ ] Per-user rate limits and spend caps to stop wallet-draining abuse.
- [ ] Prompt-injection scan on inputs (`scan_prompt`) plus logging of blocked attempts.

## 6. Transport and headers
- [ ] HTTPS everywhere; HSTS on.
- [ ] CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy (see `SECURITY_HEADERS`).
- [ ] CORS: explicit origin allowlist, never `*` with credentials.

## 7. Infrastructure
- [ ] Put Cloudflare (or similar WAF/CDN) in front; enable bot protection and DDoS mitigation.
- [ ] Origin server only accepts traffic from the CDN.
- [ ] Dependencies pinned and scanned (`npm audit`, `pip-audit`, Dependabot).
- [ ] Database not publicly reachable; backups encrypted and tested.
- [ ] Admin panels not exposed on default paths (use honeypots on the fake ones).

## 8. Detection, response, recovery
- [ ] Audit log of logins, bans, challenges, admin actions (JSONL from the guard).
- [ ] Real-time alerts to Telegram/email for permanent bans and lockdown.
- [ ] Kill switch (`enable_lockdown`) tested.
- [ ] Incident plan: rotate secrets, revoke sessions, restore from backup, notify users if data leaked.
