# SAST Scorecard

**Tool:** SnykCode 1.1300.2  
**SARIF:** `results.sarif`  
**Ground truth:** `juice-shop-ground-truth.yml`  

## Headline metrics

| Metric | Value |
|--------|-------|
| Total findings | 253 |
| Excluded (path filter) | 203 |
| Informational (CWE filter) | 5 |
| In-scope findings | 45 |
| SAST-detectable challenges | 51 |
| TP | 25 |
| FP | 32 |
| FN | 26 |
| TN | 25 |
| Precision | 0.4386 |
| Recall | 0.4902 |
| F1 | 0.4630 |
| Youden's J | -0.0712 |

> **TN formula:** For each FN challenge, each (vulnerable_file, CWE) pair where no finding was emitted counts as one TN (per OWASP Benchmark convention).

## Per-CWE breakdown

| CWE | TP | FP | FN | Precision | Recall | F1 |
|-----|----|----|----|-----------|--------|----|
| CWE-1287 | 0 | 12 | 0 | 0.0000 | n/a | n/a |
| CWE-1321 | 0 | 2 | 0 | 0.0000 | n/a | n/a |
| CWE-200 | 0 | 0 | 2 | n/a | 0.0000 | n/a |
| CWE-22 | 0 | 0 | 2 | n/a | 0.0000 | n/a |
| CWE-23 | 6 | 3 | 0 | 0.6667 | 1.0000 | 0.8000 |
| CWE-259 | 0 | 1 | 0 | 0.0000 | n/a | n/a |
| CWE-284 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-347 | 0 | 1 | 3 | 0.0000 | 0.0000 | n/a |
| CWE-352 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| CWE-400 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-434 | 0 | 0 | 2 | n/a | 0.0000 | n/a |
| CWE-601 | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| CWE-611 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-620 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-639 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-770 | 0 | 7 | 0 | 0.0000 | n/a | n/a |
| CWE-776 | 0 | 0 | 1 | n/a | 0.0000 | n/a |
| CWE-79 | 6 | 1 | 3 | 0.8571 | 0.6667 | 0.7500 |
| CWE-798 | 0 | 1 | 3 | 0.0000 | 0.0000 | n/a |
| CWE-89 | 7 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| CWE-916 | 1 | 1 | 0 | 0.5000 | 1.0000 | 0.6667 |
| CWE-918 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| CWE-94 | 0 | 0 | 3 | n/a | 0.0000 | n/a |
| CWE-943 | 1 | 4 | 2 | 0.2000 | 0.3333 | 0.2500 |

## True Positives

### TP: Access Log (`accessLogDisclosureChallenge`)

- `javascript/PT` → `routes/logfileServer.ts` L14  CWEs: CWE-23

### TP: Christmas Special (`christmasSpecialChallenge`)

- `javascript/Sqli` → `routes/search.ts` L23  CWEs: CWE-89

### TP: CSRF (`csrfChallenge`)

- `javascript/UseCsurfForExpress` → `server.ts` L129  CWEs: CWE-352

### TP: Database Schema (`dbSchemaChallenge`)

- `javascript/Sqli` → `routes/search.ts` L23  CWEs: CWE-89

### TP: Easter Egg (`easterEggLevelOneChallenge`)

- `javascript/PT` → `routes/fileServer.ts` L33  CWEs: CWE-23

### TP: Ephemeral Accountant (`ephemeralAccountantChallenge`)

- `javascript/Sqli` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Forgotten Sales Backup (`forgottenBackupChallenge`)

- `javascript/PT` → `routes/fileServer.ts` L33  CWEs: CWE-23

### TP: Forgotten Developer Backup (`forgottenDevBackupChallenge`)

- `javascript/PT` → `routes/fileServer.ts` L33  CWEs: CWE-23

### TP: HTTP-Header XSS (`httpHeaderXssChallenge`)

- `javascript/XSS` → `frontend/src/app/last-login-ip/last-login-ip.component.ts` L39  CWEs: CWE-79

### TP: DOM XSS (`localXssChallenge`)

- `javascript/XSS` → `frontend/src/app/search-result/search-result.component.ts` L170  CWEs: CWE-79

### TP: Login Admin (`loginAdminChallenge`)

- `javascript/Sqli` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Login Bender (`loginBenderChallenge`)

- `javascript/Sqli` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Login Jim (`loginJimChallenge`)

- `javascript/Sqli` → `routes/login.ts` L34  CWEs: CWE-89

### TP: Misplaced Signature File (`misplacedSignatureFileChallenge`)

- `javascript/PT` → `routes/fileServer.ts` L33  CWEs: CWE-23

### TP: NoSQL Manipulation (`noSqlReviewsChallenge`)

- `javascript/NoSqli` → `routes/updateProductReviews.ts` L17  CWEs: CWE-943

### TP: Poison Null Byte (`nullByteChallenge`)

- `javascript/PT` → `routes/fileServer.ts` L33  CWEs: CWE-23

### TP: Allowlist Bypass (`redirectChallenge`)

- `javascript/OR` → `routes/redirect.ts` L19  CWEs: CWE-601

### TP: Outdated Allowlist (`redirectCryptoCurrencyChallenge`)

- `javascript/OR` → `routes/redirect.ts` L19  CWEs: CWE-601

### TP: Reflected XSS (`reflectedXssChallenge`)

- `javascript/XSS` → `frontend/src/app/track-result/track-result.component.ts` L48  CWEs: CWE-79

### TP: API-only XSS (`restfulXssChallenge`)

- `javascript/XSS` → `frontend/src/app/search-result/search-result.component.ts` L170  CWEs: CWE-79

### TP: SSRF (`ssrfChallenge`)

- `javascript/Ssrf` → `routes/profileImageUrlUpload.ts` L24  CWEs: CWE-918

### TP: User Credentials (`unionSqlInjectionChallenge`)

- `javascript/Sqli` → `routes/search.ts` L23  CWEs: CWE-89

### TP: CSP Bypass (`usernameXssChallenge`)

- `javascript/XSS` → `routes/userProfile.ts` L98  CWEs: CWE-79

### TP: Weird Crypto (`weirdCryptoChallenge`)

- `javascript/InsecureHash` → `lib/insecurity.ts` L43  CWEs: CWE-916

### TP: Bonus Payload (`xssBonusChallenge`)

- `javascript/XSS` → `frontend/src/app/search-result/search-result.component.ts` L170  CWEs: CWE-79

## False Positives

Findings that matched no SAST-detectable challenge (by file + CWE).

| Rule | File | Line | CWEs |
|------|------|------|------|
| `javascript/HTTPSourceWithUncheckedType` | `routes/currentUser.ts` | 23 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `routes/profileImageUrlUpload.ts` | 20 | CWE-1287 |
| `javascript/InsecureHash` | `Gruntfile.js` | 77 | CWE-916 |
| `javascript/JwtDecodeMethod` | `routes/authenticatedUsers.ts` | 20 | CWE-347 |
| `javascript/NoHardcodedPasswords` | `models/index.ts` | 30 | CWE-259, CWE-798 |
| `javascript/HTTPSourceWithUncheckedType` | `routes/profileImageUrlUpload.ts` | 28 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `routes/profileImageUrlUpload.ts` | 28 | CWE-1287 |
| `javascript/NoRateLimitingForExpensiveWebOperation` | `routes/dataErasure.ts` | 18 | CWE-770 |
| `javascript/NoRateLimitingForExpensiveWebOperation` | `routes/dataErasure.ts` | 54 | CWE-770 |
| `javascript/NoRateLimitingForExpensiveWebOperation` | `routes/easterEgg.ts` | 12 | CWE-770 |
| `javascript/NoRateLimitingForExpensiveWebOperation` | `routes/premiumReward.ts` | 12 | CWE-770 |
| `javascript/NoRateLimitingForExpensiveWebOperation` | `routes/privacyPolicyProof.ts` | 12 | CWE-770 |
| `javascript/NoRateLimitingForExpensiveWebOperation` | `routes/profileImageUrlUpload.ts` | 17 | CWE-770 |
| `javascript/NoRateLimitingForExpensiveWebOperation` | `routes/videoHandler.ts` | 52 | CWE-770 |
| `javascript/NoSqli` | `routes/likeProductReviews.ts` | 25 | CWE-943 |
| `javascript/NoSqli` | `routes/likeProductReviews.ts` | 43 | CWE-943 |
| `javascript/NoSqli` | `routes/likeProductReviews.ts` | 35 | CWE-943 |
| `javascript/NoSqli` | `routes/likeProductReviews.ts` | 50 | CWE-943 |
| `javascript/PT` | `routes/keyServer.ts` | 14 | CWE-23 |
| `javascript/PT` | `routes/quarantineServer.ts` | 14 | CWE-23 |
| `javascript/PT` | `routes/profileImageUrlUpload.ts` | 29 | CWE-23 |
| `javascript/PrototypePollution` | `routes/vulnCodeFixes.ts` | 92 | CWE-1321 |
| `javascript/PrototypePollution` | `routes/vulnCodeSnippet.ts` | 110 | CWE-1321 |
| `javascript/HTTPSourceWithUncheckedType` | `routes/vulnCodeSnippet.ts` | 63 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `server.ts` | 409 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `server.ts` | 409 | CWE-1287 |
| `javascript/XSS` | `routes/recycles.ts` | 17 | CWE-79 |
| `javascript/HTTPSourceWithUncheckedType` | `routes/vulnCodeSnippet.ts` | 64 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `routes/vulnCodeSnippet.ts` | 66 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `server.ts` | 410 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `server.ts` | 411 | CWE-1287 |
| `javascript/HTTPSourceWithUncheckedType` | `server.ts` | 412 | CWE-1287 |

## False Negatives

SAST-detectable challenges with zero matching findings.

| Challenge | Category | CWE | Vulnerable files | Confidence |
|-----------|----------|-----|-----------------|------------|
| Password Hash Leak | Sensitive Data Exposure | 200 | `routes/currentUser.ts` | medium |
| Arbitrary File Write | Vulnerable Components | 22 | `routes/fileUpload.ts` | high |
| Blocked RCE DoS | Insecure Deserialization | 94 | `routes/b2bOrder.ts` | high |
| Change Bender's Password | Broken Authentication | 620 | `routes/changePassword.ts` | high |
| Client-side XSS Protection | XSS | 79 | `models/user.ts` | medium |
| Email Leak | Sensitive Data Exposure | 200 | `routes/currentUser.ts` | medium |
| Forged Coupon | Cryptographic Issues | 347 | `lib/insecurity.ts` | medium |
| Forged Review | Broken Access Control | 284 | `routes/updateProductReviews.ts` | medium |
| Forged Signed JWT | Vulnerable Components | 347 | `lib/insecurity.ts` | high |
| Login Support Team | Security Misconfiguration | 798 | `routes/login.ts` | high |
| NoSQL DoS | Injection | 943 | `routes/showProductReviews.ts` | high |
| NoSQL Exfiltration | Injection | 943 | `routes/trackOrder.ts` | high |
| SSTi | Injection | 94 | `routes/userProfile.ts` | medium |
| Server-side XSS Protection | XSS | 79 | `models/feedback.ts` | medium |
| Successful RCE DoS | Insecure Deserialization | 94 | `routes/b2bOrder.ts` | high |
| Unsigned JWT | Vulnerable Components | 347 | `lib/insecurity.ts` | medium |
| Upload Size | Improper Input Validation | 434 | `routes/fileUpload.ts` | high |
| Upload Type | Improper Input Validation | 434 | `routes/fileUpload.ts` | high |
| Video XSS | XSS | 79 | `routes/videoHandler.ts` | medium |
| View Basket | Broken Access Control | 639 | `routes/basket.ts` | high |
| XXE Data Access | XXE | 611 | `routes/fileUpload.ts` | high |
| XXE DoS | XXE | 776 | `routes/fileUpload.ts` | high |
| Memory Bomb | Insecure Deserialization | 400 | `routes/fileUpload.ts` | medium |
| Local File Read | Vulnerable Components | 22 | `routes/dataErasure.ts` | high |
| Exposed credentials | Sensitive Data Exposure | 798 | `routes/login.ts` | high |
| Leaked API Key | Sensitive Data Exposure | 798 | _none_ | low |

## Informational Findings

These 5 findings have only informational CWEs (CWE-319, CWE-547) and are excluded from scoring.

| Rule | File | Line | CWEs |
|------|------|------|------|
| `javascript/HardcodedSecret` | `lib/insecurity.ts` | 22 | CWE-547 |
| `javascript/HardcodedSecret` | `lib/insecurity.ts` | 23 | CWE-547 |
| `javascript/HardcodedSecret` | `lib/insecurity.ts` | 44 | CWE-547 |
| `javascript/HardcodedNonCryptoSecret` | `lib/insecurity.ts` | 23 | CWE-547 |
| `javascript/HardcodedNonCryptoSecret` | `lib/insecurity.ts` | 54 | CWE-547 |

## Exclusion summary

203 findings excluded by path filters (per-pattern counts may overlap):

- `test/`: 193
- `cypress/`: 41
- `*.spec.ts`: 48
- `*.test.ts`: 0
- `frontend/src/assets/`: 0
- `data/static/codefixes/`: 3
