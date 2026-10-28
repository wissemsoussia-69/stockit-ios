# StockIT iOS — Security notes

Companion to [`THREAT_MODEL.md`](THREAT_MODEL.md). Lists what the app enforces, what still needs
server-side work, and the operational runbooks.

## Enforced in the app (covered by tests)

| Area | Behaviour | Threats | Tests |
|------|-----------|---------|-------|
| Local login | No built-in or seeded account. Local login is off in Release (`StockItConfig.localLoginEnabled`, enabled only in Debug). Passwords are PBKDF2-HMAC-SHA256 (120 000 iterations, random salt). 5 failures lock the name for 5 min. Attempts are audited. | T-01, T-02, T-20 | `AuthSecurityTest`, `CryptoTest`, `FullTests.test0` |
| SSO identity | Accounts are keyed on the Auth0 `sub`, never the display name. Local accounts are never modified by an SSO login. Unknown roles become `USER`. | T-05 | `AuthSecurityTest`, `MigrationTest` |
| Role mapping | Exact group names only (`stockit-admin`, `stockit-manager`, `stockit-technicien` / `-tech` / `-technician`, or `ADMIN`/`MANAGER`/`TECHNICIEN` in `https://vista.com/roles`). The default role can only be `USER` or `TECHNICIEN`. | T-05 | `AuthSecurityTest` |
| ID token | Auth0.swift verifies the signature. The app re-checks `iss`, `aud`, `exp` (60 s leeway) and `sub`. No `offline_access` (no refresh token). Sign-out revokes and clears the Keychain. | T-06 | `AuthSecurityTest` |
| Permissions | `USER` = read-only. `TECHNICIEN` = stock movements, exits to tickets, receptions, shipping. `MANAGER` = + catalogue and audit log. `ADMIN` = + users, test mode. Checked in the shared repository, not only in the UI. | T-04 | `AuthorizationTest`, `FullTests.test4` |
| Jira Assets sync | Requires a signed-in user. A truncated or empty CMDB result never sets stock to 0. Before/after values are audited. Only ADMIN/MANAGER push local products to Jira. | T-09 | `AuthorizationTest` |
| AI / OCR output | Ticket IDs returned by the model must be among those sent. Label quantity is bounded (1–500). Stock deltas are bounded (±1 000). OCR text is capped (8 000 chars). Ticket text is delimited as data in prompts. | T-10, T-22 | `IntegrationSecurityTest`, `DataHandlingTest` |
| Jira keys | `^[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]{0,8}$` checked before any request or stock exit. | T-12 | `IntegrationSecurityTest`, `AuthorizationTest` |
| Claims backend | No token → no request. HTTPS required (HTTP only to localhost). | T-13 | `IntegrationSecurityTest` |
| n8n webhooks | The secret is never stored in the outbox. Each request is signed (see below) and carries an `event_id`. Retries back off (30 s → 6 h). Legacy outbox rows are purged of the secret. | T-08 | `IntegrationSecurityTest`, `MigrationTest` |
| Output encoding | CSV cells are quoted and formula-neutralised. Slack text escapes `& < >` (no `<!channel>`). Slack webhooks must be HTTPS. Barcodes are validated, with restricted symbologies. | T-14, T-15, T-18 | `DataHandlingTest`, `IntegrationSecurityTest` |
| Errors | Raw model output and raw Jira bodies are not shown. Only the HTTP status and Jira's functional messages are. | T-17 | `IntegrationSecurityTest` |
| Audit log | Hash-chained (`verifyAuditChain()`). No fake IP address. Test mode is admin-only, audited, and switched off at sign-out. | T-16 | `AuthorizationTest` |
| Device storage | Session identity and role are in memory only (purged from NSUserDefaults). The DB folder is excluded from backups and uses `NSFileProtectionCompleteUnlessOpen`. CSV export is deleted when leaving the screen. | T-07, T-21 | `IosStorageTest` (simulator) |
| Supply chain | JitPack removed, Google repository content-filtered, Gradle dependency verification (`gradle/verification-metadata.xml`). Secret values are no longer Gradle task inputs (hash only). Signing files are ignored. gitleaks pre-commit hook. | T-24, T-26 | build |
| Dead code | Hugging Face, Gemini, Portkey and SendGrid paths and keys removed. Unused Android libraries removed. | T-11, T-30 | build |

Run the tests:

```bash
./gradlew :shared:testAndroidHostTest      # JVM
./gradlew :shared:iosSimulatorArm64Test    # iOS simulator (includes IosStorageTest)
# UI (Debug): xcodebuild test -scheme StockIT -destination 'platform=iOS Simulator,name=iPhone 17'
```

UI tests provision their own local account with a random password per run (`STOCKIT_UITEST_*` launch environment, Debug builds only).

## Still requires a backend (cannot be solved inside the app)

1. **Secrets in the binary (T-03, T-23, T-25).** The AI gateway key, Jira API token, Slack bot token and n8n secret are still compiled into `Shared.framework`, because the app calls those services directly. The fix is a StockIT backend that holds the credentials, authenticates the user's Auth0 access token, and proxies the AI, Jira, Slack and n8n calls. Until then, treat every shipped key as public.
2. **Server-side authorization (T-04).** The permission checks above stop a normal user, but not someone who modifies the app binary. Jira, Jira Assets and n8n must enforce roles from the verified Auth0 token.
3. **Central audit and monitoring (T-16, T-29).** The local audit chain detects tampering but can be rebuilt by someone with full device access. Send security events to a server or SIEM.
4. **Certificate pinning (T-18).** Not implemented on purpose: Auth0, Atlassian and the Cimpress gateway rotate certificates, and wrong pins lock every user out. Revisit once traffic goes through a single StockIT backend whose keys the team controls.
5. **CI (T-27).** No pipeline exists yet. Run the commands above plus `gitleaks git` on every merge request.

## Runbook — rotate the shipped secrets

Every key that was ever in `.env.sh` while building a distributed binary must be considered leaked.

1. Rotate: `CIMPRESS_GATEWAY_KEY`, `CLAUDE_API_KEY`, `JIRA_API_TOKEN` (Atlassian account → Security → API tokens), `SLACK_BOT_TOKEN` and `SLACK_WEBHOOK_URL`, `STOCKIT_WEBHOOK_SECRET` (n8n). Revoke and delete the old `PORTKEY_API_KEY`, `GEMINI_API_KEY`, `HUGGING_FACE_TOKEN` and `SENDGRID_API_KEY`, which are no longer used.
2. Update `.env.sh` on the build machine only, rebuild, and redistribute.
3. Check the old keys are rejected (Jira returns 401, n8n refuses the old signature).
4. Record the rotation date.

## n8n — verify the webhook signature

Every call carries `X-StockIT-Timestamp` (Unix seconds) and `X-StockIT-Signature: sha256=<hex>`, where the hex is `HMAC-SHA256(STOCKIT_WEBHOOK_SECRET, "<timestamp>.<raw body>")`. In a Code node:

```js
const crypto = require('crypto');
const ts = $json.headers['x-stockit-timestamp'];
const sig = $json.headers['x-stockit-signature'] || '';
const body = $json.rawBody;                         // raw request body, as received
const expected = 'sha256=' + crypto.createHmac('sha256', $env.STOCKIT_WEBHOOK_SECRET).update(`${ts}.${body}`).digest('hex');
const fresh = Math.abs(Date.now() / 1000 - Number(ts)) < 300;
if (!fresh || sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
  throw new Error('invalid signature');
}
// Deduplicate replays with $json.body.event_id.
```

Once every workflow checks the signature, build with `STOCKIT_WEBHOOK_LEGACY_BODY_SECRET=false`. The app then stops sending `secret` in the JSON body. Until then, it is still added for compatibility, but never written to disk.
