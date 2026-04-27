# OWASP Juice Shop SAST Scorer

Measures how well a SAST tool finds OWASP Juice Shop vulnerabilities and
produces precision / recall / F1 / Youden's J metrics from any SARIF v2.1.0
output.  The scorer is tool-agnostic: Snyk Code is the first tool tested, but
any scanner that emits standard SARIF works without code changes.

---

## Quick start

```bash
# Install the only non-stdlib dependency
pip install pyyaml

# Score a SARIF file and produce Markdown + JSON + HTML reports
python score_sarif.py \
  --sarif results.sarif \
  --ground-truth juice-shop-ground-truth.yml \
  --out scorecard/ \
  --html
```

The summary is printed to stdout.  Full details land in `scorecard/scorecard.md`,
`scorecard/scorecard.json`, and (with `--html`) a self-contained
`scorecard/scorecard.html` report you can open in any browser or share as a
single file.

---

## CLI reference

```
python score_sarif.py
  --sarif <path>            SARIF v2.1.0 file to score
  --ground-truth <path>     Ground-truth YAML (default: juice-shop-ground-truth.yml)
  --out <dir>               Output directory (default: scorecard/)
  [--html]                  Also write a self-contained scorecard.html report
  [--exclude-paths <list>]  Comma-separated path prefixes/globs to drop entirely
                            (default: test/,cypress/,*.spec.ts,*.test.ts,
                                      frontend/src/assets/)
  [--informational-cwes <list>]
                            Comma-separated CWEs treated as informational/noise,
                            excluded from precision/recall
                            (default: CWE-547,CWE-319)
```

### HTML report

Pass `--html` to generate a self-contained `scorecard.html` alongside the
Markdown and JSON outputs:

```bash
python score_sarif.py \
  --sarif results.sarif \
  --ground-truth juice-shop-ground-truth.yml \
  --html
```

The report requires no server or internet connection — open it directly in a
browser or attach it to a ticket.  It includes:

- **Headline metrics** — Precision, Recall, F1, and Youden's J with
  colour-coded thresholds (green ≥ 0.7, amber ≥ 0.5, red below)
- **Finding counts** — TP / FP / FN / TN with an SVG donut chart
- **Volume breakdown** — total, excluded, informational, and in-scope counts
- **Per-CWE table** — TP / FP / FN per weakness class with inline stacked bars
  and row-level colour coding (green = perfect precision+recall, red = all FP,
  amber = all FN)
- **Collapsible detail tables** — True Positives (open by default), False
  Positives, and False Negatives with file paths and line numbers

### Exclusion logic

Findings whose `uri` matches any exclusion pattern are dropped from all
calculations — they are not counted as TP, FP, or FN.  This removes
test-fixture findings (e.g. hardcoded passwords inside API specs) that would
otherwise dominate FP counts.

Informational CWEs (CWE-547 = hardcoded non-crypto secrets,
CWE-319 = cleartext HTTP) are also excluded from precision/recall but reported
separately so a human can audit them.

---

## Adding a new SAST tool

Zero code changes required.  Run the new tool against Juice Shop at the pinned
commit (`3b178fd07b9f754c9d444d818448cfe58168943f`), export as SARIF v2.1.0,
and point `--sarif` at the new file:

```bash
python score_sarif.py \
  --sarif semgrep-output.sarif \
  --ground-truth juice-shop-ground-truth.yml \
  --out scorecard-semgrep/
```

The scorer reads CWEs exclusively from the SARIF rules table
(`runs[*].tool.driver.rules[*].properties.cwe`), so tool-specific rule IDs do
not matter.

---

## Extending the ground truth

When Juice Shop adds new challenges:

1. Open `juice-shop-ground-truth.yml` in any text editor.
2. Find the new challenge entry (copied from `data/static/challenges.yml`).
3. Fill in the four added fields:

   ```yaml
   cwe: 89                   # int or list; most specific CWE for the mechanism
   sast_detectable: true     # true only if source-to-sink taint analysis applies
   vulnerable_files:         # repo-relative paths to the root-cause code
     - routes/newRoute.ts
   confidence: high          # high | medium | low
   ```

4. Set `sast_detectable: false` and `vulnerable_files: []` for challenges that
   require runtime knowledge (brute-force, OSINT, business-logic flaws, etc.).

5. Re-run the scorer to update the scorecard.

Rules of thumb for the four new fields:

| Field | Guidance |
|-------|----------|
| `cwe` | Use the most specific CWE for the **code-level** mechanism, not the business impact. SQL injection → 89. Weak hash → 916. |
| `sast_detectable` | `true` only if a taint analysis from attacker-controlled source to dangerous sink can find it without runtime data. |
| `vulnerable_files` | Where the root-cause code lives in the **pinned commit**. Verify paths with `git ls-files` on the repo. |
| `confidence` | Be honest. `low` is fine and tells readers to double-check before trusting the mapping. |

---

## How scoring works

### Matching

A SARIF finding is a **True Positive (TP)** for a challenge when:

- The finding's file path is in the challenge's `vulnerable_files` list, **and**
- The finding's CWE tags (from the SARIF rules table) overlap with the
  challenge's `cwe` field.

Both conditions must hold.  File path alone is not enough — different
vulnerabilities share the same file (e.g. `routes/login.ts` hosts SQL injection
and hardcoded credentials), and CWE alone is not enough — the same CWE class
can appear in many files.

A single finding that matches multiple challenges produces one TP per challenge
(all challenges count for recall).  Multiple findings matching the same
challenge count as one TP for recall, but all are recorded in the finding
cluster for auditing.

### Precision

*Of all in-scope findings the tool emitted, what fraction pointed to a real
Juice Shop vulnerability?*

```
Precision = TP / (TP + FP)
```

A high-precision tool has few false alarms.  A low-precision tool makes
developers wade through noise.

### Recall

*Of all SAST-detectable Juice Shop vulnerabilities, what fraction did the tool
find?*

```
Recall = TP / (TP + FN)
```

A high-recall tool misses few real bugs.  Low recall means the tool has
blind spots.

### F1

The harmonic mean of precision and recall — a single number that balances both.
Useful for comparing tools when you care equally about false positives and false
negatives.

```
F1 = 2 × Precision × Recall / (Precision + Recall)
```

### Youden's J (informedness)

Measures how well the tool separates real vulnerabilities from non-vulnerabilities,
accounting for the base rate.

```
Youden's J = Recall + Specificity − 1
           = TPR + TNR − 1
```

`Specificity = TN / (TN + FP)`.  A value of 1 means perfect discrimination;
0 means no better than chance.

**TN definition (OWASP Benchmark convention):** for each False Negative
challenge, each `(vulnerable_file, CWE)` pair where the tool emitted *no*
finding counts as one True Negative.  This reflects the intuition that a
correct absence of a finding at a specific location is also useful signal.

---

## Interpreting the results

The FN list typically includes:

- **Broken Access Control** challenges (e.g. View Basket, Forged Feedback) —
  SAST cannot detect missing authorisation checks without a policy model.
- **Business-logic flaws** (e.g. Payback Time, Expired Coupon) — no static
  taint path to flag.
- **RCE via sandboxed eval** (routes/b2bOrder.ts) — Snyk does not flag
  `vm.runInContext` / `notevil`.
- **XXE / Memory Bomb** (routes/fileUpload.ts) — Snyk misses the libxmljs2
  call in a `vm.runInContext` sandbox.

These are expected gaps.  A tool that claims 100% recall on Juice Shop should
be viewed with suspicion.

The FP list is useful for understanding tool noise:

- `data/static/codefixes/` — code snippets displayed in the UI for a coding
  mini-game; exclude with `--exclude-paths data/static/codefixes/` if desired.
- `routes/vulnCodeSnippet.ts` / `routes/vulnCodeFixes.ts` — prototype pollution
  in the coding-challenge app scaffolding, not in the application itself.
- `routes/likeProductReviews.ts` — flagged as NoSQL injection but the
  `_id` query there does not create a command injection path (the real
  `$where` injections are in `showProductReviews.ts` and `trackOrder.ts`,
  which Snyk misses).
