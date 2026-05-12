# SAST Scorecard

**Tool:** Semgrep OSS 1.161.0  
**SARIF:** `results-semgrep.sarif`  
**Ground truth:** `juice-shop-ground-truth.yml`  

## Headline metrics

| Metric | Value |
|--------|-------|
| Total findings | 23 |
| Excluded (path filter) | 0 |
| Informational (CWE filter) | 0 |
| In-scope findings | 23 |
| SAST-detectable challenges | 51 |
| TP | 9 |
| FP | 20 |
| FN | 42 |
| TN | 42 |
| Precision | 0.3103 |
| Recall | 0.1765 |
| F1 | 0.2250 |
| Youden's J | -0.1461 |

> **TN formula:** For each FN challenge, each (vulnerable_file, CWE) pair where no finding was emitted counts as one TN (per OWASP Benchmark convention).

## Per-CWE breakdown

| CWE | TP | FP | FN | Precision | Recall | F1 |
|-----|----|----|----|-----------|--------|----|
| CWE-200 | 0 | 0 | 2 | n/a | 0.0000 | n/a |
| CWE-22 | 0 | 0 | 2 | n/a | 0.0000 | n/a |
| CWE-23 | 0 | 0 | 6 | n/a | 0.0000 | n/a |
| CWE-284 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-347 | 0 | 0 | 3 | n/a | 0.0000 | n/a |
| CWE-352 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-400 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-434 | 0 | 0 | 2 | n/a | 0.0000 | n/a |
| CWE-548 | 0 | 4 | 0 | 0.0000 | n/a | n/a |
| CWE-601 | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| CWE-611 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-620 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-639 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-73 | 0 | 4 | 0 | 0.0000 | n/a | n/a |
| CWE-776 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-78 | 0 | 5 | 0 | 0.0000 | n/a | n/a |
| CWE-79 | 0 | 1 | 9 | 0.0000 | 0.0000 | n/a |
| CWE-798 | 0 | 1 | 3 | 0.0000 | 0.0000 | n/a |
| CWE-89 | 7 | 4 | 0 | 0.6364 | 1.0000 | 0.7778 |
| CWE-916 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-918 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-94 | 0 | 0 | 3 | n/a | 0.0000 | n/a |
| CWE-943 | 0 | 0 | 3 | n/a | 0.0000 | n/a |
| CWE-95 | 0 | 1 | 0 | 0.0000 | n/a | n/a |

## True Positives

### TP: Christmas Special (`christmasSpecialChallenge`)

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/search.ts` L23  CWEs: CWE-89

### TP: Database Schema (`dbSchemaChallenge`)

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/search.ts` L23  CWEs: CWE-89

### TP: Ephemeral Accountant (`ephemeralAccountantChallenge`)

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Login Admin (`loginAdminChallenge`)

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Login Bender (`loginBenderChallenge`)

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Login Jim (`loginJimChallenge`)

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Allowlist Bypass (`redirectChallenge`)

- `javascript.express.security.audit.express-open-redirect.express-open-redirect` → `routes/redirect.ts` L19  CWEs: CWE-601

### TP: Outdated Allowlist (`redirectCryptoCurrencyChallenge`)

- `javascript.express.security.audit.express-open-redirect.express-open-redirect` → `routes/redirect.ts` L19  CWEs: CWE-601

### TP: User Credentials (`unionSqlInjectionChallenge`)

- `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/search.ts` L23  CWEs: CWE-89

## False Positives

Findings that matched no SAST-detectable challenge (by file + CWE).

| Rule | File | Line | CWEs |
|------|------|------|------|
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | `.github/workflows/update-challenges-ebook.yml` | 22 | CWE-78 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | `.github/workflows/update-challenges-www-legacy.yml` | 27 | CWE-78 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | `.github/workflows/update-challenges-www-legacy.yml` | 36 | CWE-78 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | `.github/workflows/update-challenges-www.yml` | 27 | CWE-78 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | `.github/workflows/update-challenges-www.yml` | 36 | CWE-78 |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `data/static/codefixes/dbSchemaChallenge_1.ts` | 5 | CWE-89 |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `data/static/codefixes/dbSchemaChallenge_3.ts` | 11 | CWE-89 |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `data/static/codefixes/unionSqlInjectionChallenge_1.ts` | 6 | CWE-89 |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `data/static/codefixes/unionSqlInjectionChallenge_3.ts` | 10 | CWE-89 |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | `lib/insecurity.ts` | 56 | CWE-798 |
| `javascript.express.security.injection.raw-html-format.raw-html-format` | `routes/chatbot.ts` | 205 | CWE-79 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `routes/fileServer.ts` | 33 | CWE-73 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `routes/keyServer.ts` | 14 | CWE-73 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `routes/logfileServer.ts` | 14 | CWE-73 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `routes/quarantineServer.ts` | 14 | CWE-73 |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | `routes/userProfile.ts` | 62 | CWE-95 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | `server.ts` | 269 | CWE-548 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | `server.ts` | 273 | CWE-548 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | `server.ts` | 277 | CWE-548 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | `server.ts` | 281 | CWE-548 |

## False Negatives

SAST-detectable challenges with zero matching findings.

| Challenge | Category | CWE | Vulnerable files | Confidence |
|-----------|----------|-----|-----------------|------------|
| Password Hash Leak | Sensitive Data Exposure | 200 | `routes/currentUser.ts` | medium |
| API-only XSS | XSS | 79 | `frontend/src/app/search-result/search-result.component.ts` | medium |
| Access Log | Observability Failures | 23 | `routes/logfileServer.ts` | high |
| Arbitrary File Write | Vulnerable Components | 22 | `routes/fileUpload.ts` | high |
| Blocked RCE DoS | Insecure Deserialization | 94 | `routes/b2bOrder.ts` | high |
| Change Bender's Password | Broken Authentication | 620 | `routes/changePassword.ts` | high |
| CSP Bypass | XSS | 79 | `routes/userProfile.ts` | medium |
| Client-side XSS Protection | XSS | 79 | `models/user.ts` | medium |
| DOM XSS | XSS | 79 | `frontend/src/app/search-result/search-result.component.ts` | high |
| Easter Egg | Broken Access Control | 23 | `routes/fileServer.ts` | medium |
| Email Leak | Sensitive Data Exposure | 200 | `routes/currentUser.ts` | medium |
| Forged Coupon | Cryptographic Issues | 347 | `lib/insecurity.ts` | medium |
| Forged Review | Broken Access Control | 284 | `routes/updateProductReviews.ts` | medium |
| Forged Signed JWT | Vulnerable Components | 347 | `lib/insecurity.ts` | high |
| Forgotten Developer Backup | Sensitive Data Exposure | 23 | `routes/fileServer.ts` | high |
| Forgotten Sales Backup | Sensitive Data Exposure | 23 | `routes/fileServer.ts` | high |
| HTTP-Header XSS | XSS | 79 | `frontend/src/app/last-login-ip/last-login-ip.component.ts`, `routes/saveLoginIp.ts` | high |
| Login Support Team | Security Misconfiguration | 798 | `routes/login.ts` | high |
| Misplaced Signature File | Observability Failures | 23 | `routes/fileServer.ts` | medium |
| NoSQL DoS | Injection | 943 | `routes/showProductReviews.ts` | high |
| NoSQL Exfiltration | Injection | 943 | `routes/trackOrder.ts` | high |
| NoSQL Manipulation | Injection | 943 | `routes/updateProductReviews.ts` | high |
| Reflected XSS | XSS | 79 | `frontend/src/app/track-result/track-result.component.ts` | high |
| SSRF | Broken Access Control | 918 | `routes/profileImageUrlUpload.ts` | high |
| SSTi | Injection | 94 | `routes/userProfile.ts` | medium |
| Server-side XSS Protection | XSS | 79 | `models/feedback.ts` | medium |
| Successful RCE DoS | Insecure Deserialization | 94 | `routes/b2bOrder.ts` | high |
| Unsigned JWT | Vulnerable Components | 347 | `lib/insecurity.ts` | medium |
| Upload Size | Improper Input Validation | 434 | `routes/fileUpload.ts` | high |
| Upload Type | Improper Input Validation | 434 | `routes/fileUpload.ts` | high |
| Video XSS | XSS | 79 | `routes/videoHandler.ts` | medium |
| View Basket | Broken Access Control | 639 | `routes/basket.ts` | high |
| Weird Crypto | Cryptographic Issues | 916 | `lib/insecurity.ts` | high |
| XXE Data Access | XXE | 611 | `routes/fileUpload.ts` | high |
| XXE DoS | XXE | 776 | `routes/fileUpload.ts` | high |
| Memory Bomb | Insecure Deserialization | 400 | `routes/fileUpload.ts` | medium |
| CSRF | Broken Access Control | 352 | `server.ts` | medium |
| Bonus Payload | XSS | 79 | `frontend/src/app/search-result/search-result.component.ts` | medium |
| Poison Null Byte | Improper Input Validation | 23 | `routes/fileServer.ts` | medium |
| Local File Read | Vulnerable Components | 22 | `routes/dataErasure.ts` | high |
| Exposed credentials | Sensitive Data Exposure | 798 | `routes/login.ts` | high |
| Leaked API Key | Sensitive Data Exposure | 798 | _none_ | low |

## Informational Findings

These 0 findings have only informational CWEs (CWE-319, CWE-547) and are excluded from scoring.


## Exclusion summary

0 findings excluded by path filters (per-pattern counts may overlap):

- `test/`: 0
- `cypress/`: 0
- `*.spec.ts`: 0
- `*.test.ts`: 0
- `frontend/src/assets/`: 0
