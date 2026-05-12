# OWASP Juice Shop SAST Scorer

Measures how well a SAST tool finds OWASP Juice Shop vulnerabilities and
produces precision / recall / F1 / Youden's J metrics from any SARIF v2.1.0
output. The scorer is tool-agnostic — Snyk Code, Semgrep, Opengrep (Aikido),
and any other scanner that emits standard SARIF works without code changes.

A separate `compare_scorecards.py` script consumes the JSON output from two or
more scorer runs and produces a single side-by-side HTML report.

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

The summary is printed to stdout. Full details land in `scorecard/scorecard.md`,
`scorecard/scorecard.json`, and (with `--html`) a self-contained
`scorecard/scorecard.html` you can open in any browser or share as a single file.

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
  [--min-severity {info,low,medium,high,critical}]
                            Drop findings strictly below this severity before
                            scoring (default: low — no filtering)
```

### Severity filtering

`--min-severity` lets you ignore noisy low-severity findings before scoring.
Severity is extracted in this priority order from the SARIF:

1. `result.properties["security-severity"]` — numeric CVSS-style score
2. `result.properties["severity"]` / `["problem.severity"]` — free-form bucket
3. The same fields on the rule (`rules[].properties.*`)
4. `rule.defaultConfiguration.level`
5. `result.level` (`error` → high, `warning` → medium, `note` → low, `none` → info)

CVSS bucketing matches the GitHub / Snyk convention: ≥ 9 critical, ≥ 7 high,
≥ 4 medium, > 0 low.

Example — score only medium-and-above:

```bash
python score_sarif.py --sarif results.sarif \
  --ground-truth juice-shop-ground-truth.yml \
  --min-severity medium --html
```

Filtered findings are reported in `totals.severity_filtered` and the chosen
threshold in `min_severity`.

### Multi-tool SARIF support

The scorer extracts CWE tags from every place common emitters stash them, so it
works out of the box with Snyk Code, Semgrep, Opengrep / Aikido, CodeQL, and
others. The extraction order is:

1. `rule.properties.cwe` / `cwes` (list of `"CWE-NNN"` strings — Snyk)
2. `rule.properties.tags` (descriptive strings like `"CWE-79: XSS"` — Semgrep)
3. `rule.relationships[].target.id` with `toolComponent.name == "CWE"`
   (taxonomy refs — CodeQL)
4. `result.taxa[]` and `result.properties.*` as result-level overrides

Both `ruleId` and `ruleIndex` references are honoured, and rules registered in
`tool.extensions[]` are picked up too.

### HTML report

Pass `--html` to generate a self-contained `scorecard.html` alongside the
Markdown and JSON outputs. The report requires no server or internet
connection — open it directly in a browser or attach it to a ticket. It
includes:

- **Headline metrics** — Precision, Recall, F1, and Youden's J with
  colour-coded thresholds (green ≥ 0.7, amber ≥ 0.5, red below)
- **Finding counts** — TP / FP / FN / TN with an SVG donut chart
- **Volume breakdown** — total, excluded, severity-filtered, informational, and
  in-scope counts
- **Per-CWE table** — TP / FP / FN per weakness class with inline stacked bars
- **Collapsible detail tables** — True Positives (open by default), False
  Positives, and False Negatives with file paths and line numbers

### Exclusion logic

Findings whose `uri` matches any exclusion pattern are dropped from all
calculations — they are not counted as TP, FP, or FN. This removes
test-fixture findings (e.g. hardcoded passwords inside API specs) that would
otherwise dominate FP counts.

Informational CWEs (CWE-547 = hardcoded non-crypto secrets, CWE-319 = cleartext
HTTP) are also excluded from precision/recall but reported separately so a
human can audit them.

Pipeline order: `path exclusion → severity filter → informational-CWE filter
→ scoring`.

---

## Comparing multiple tools

`compare_scorecards.py` takes two or more `scorecard.json` files and writes a
single side-by-side HTML report:

```bash
python compare_scorecards.py \
  --scorecard Snyk=scorecard-snyk/scorecard.json \
  --scorecard Semgrep=scorecard-semgrep/scorecard.json \
  --scorecard Aikido=scorecard-aikido/scorecard.json \
  --out comparison.html
```

Each `--scorecard LABEL=path` flag adds one tool to the report. The HTML
output shows:

- Headline metrics side-by-side, with the leading cell highlighted per row
- Per-tool snapshot cards (TP / FP / Precision / Recall / F1 / Youden J)
- Coverage panels — caught by all, only by each tool, missed by all
- A per-challenge matrix (challenge × tool) showing exactly who caught what

The report shows only **post-filter** numbers — whatever filtering was applied
when each `scorecard.json` was generated is honoured, and the severity floor
is surfaced in the header.

---

## How scoring works

### Matching

A SARIF finding **matches** a challenge when:

- The finding's file path is in the challenge's `vulnerable_files` list, **and**
- The finding's CWE tags overlap with the challenge's `cwe` field.

Both conditions must hold. File path alone is not enough — different
vulnerabilities share the same file (e.g. `routes/login.ts` hosts SQL injection
and hardcoded credentials), and CWE alone is not enough — the same CWE class
can appear in many files.

### True Positive (finding-level)

**TP = unique findings that match at least one challenge.**

A single finding that matches multiple overlapping challenges still counts as
one TP. For example, one path-traversal finding at `routes/fileServer.ts:33`
can satisfy five different Juice Shop challenges (forgotten backup, easter egg,
null byte, etc.) — that's one TP, five challenges covered.

This is a **finding-level** count, so `TP + FP = in-scope findings` cleanly.

### False Positive

**FP = findings that don't match any challenge.** Same units as TP.

### Challenges covered / missed

Tracked separately from TP/FP so that ground-truth coverage stays visible:

- **`challenges_detected`** — distinct challenges with ≥1 matching finding
- **`FN`** — challenges with zero matching findings

`challenges_detected + FN = total SAST-detectable challenges`.

### Precision

*Of the in-scope findings the tool emitted, what fraction pointed to a real
Juice Shop vulnerability?*

```
Precision = TP / (TP + FP)        # both finding-level
```

### Recall

*Of all SAST-detectable Juice Shop challenges, what fraction had at least one
matching finding?*

```
Recall = challenges_detected / total_detectable_challenges
```

### F1

The harmonic mean of precision and recall — a single number that balances
finding-quality (precision) and ground-truth coverage (recall).

```
F1 = 2 × Precision × Recall / (Precision + Recall)
```

### Youden's J (informedness)

```
Youden's J = Recall + Specificity − 1
Specificity = TN / (TN + FP)
```

A value of 1 means perfect discrimination; 0 means no better than chance.

**TN definition (OWASP Benchmark convention):** for each FN challenge, each
`(vulnerable_file, CWE)` pair where the tool emitted *no* finding counts as
one TN.

### Why TP isn't `challenges_detected`

Older versions of this scorer set `TP = challenges_detected`, which made
`TP + FP` arithmetically meaningless (different units). The current convention
keeps TP/FP in finding units (for a consistent precision) and reports ground-
truth coverage as a separate pair (`challenges_detected` / `FN`) for recall.
A documentation block in `metrics.TP_formula` and `metrics.recall_formula`
inside each `scorecard.json` records the convention used.

---

## Adding a new SAST tool

Zero code changes required. Run the new tool against Juice Shop at the pinned
commit (`3b178fd07b9f754c9d444d818448cfe58168943f`), export as SARIF v2.1.0,
and point `--sarif` at the new file:

```bash
python score_sarif.py \
  --sarif semgrep-output.sarif \
  --ground-truth juice-shop-ground-truth.yml \
  --out scorecard-semgrep/ --html
```

The scorer auto-detects CWE conventions used by different tools (see
*Multi-tool SARIF support* above), so tool-specific rule IDs do not matter.

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

| Field | Guidance |
|-------|----------|
| `cwe` | Most specific CWE for the **code-level** mechanism, not the business impact. SQL injection → 89. Weak hash → 916. |
| `sast_detectable` | `true` only if taint analysis from attacker-controlled source to dangerous sink can find it without runtime data. |
| `vulnerable_files` | Where the root-cause code lives in the **pinned commit**. Verify paths with `git ls-files`. |
| `confidence` | Be honest. `low` is fine and tells readers to double-check before trusting the mapping. |

---

## Interpreting the results

The FN list typically includes:

- **Broken Access Control** challenges (e.g. View Basket, Forged Feedback) —
  SAST cannot detect missing authorisation checks without a policy model.
- **Business-logic flaws** (e.g. Payback Time, Expired Coupon) — no static
  taint path to flag.
- **RCE via sandboxed eval** (`routes/b2bOrder.ts`) — most tools do not flag
  `vm.runInContext` / `notevil`.
- **XXE / Memory Bomb** (`routes/fileUpload.ts`) — libxmljs2 in a sandbox.

These are expected gaps. A tool that claims 100% recall on Juice Shop should
be viewed with suspicion.

The FP list is useful for understanding tool noise:

- `data/static/codefixes/` — code snippets displayed in the UI for a coding
  mini-game; exclude with `--exclude-paths data/static/codefixes/` if desired.
- `routes/vulnCodeSnippet.ts` / `routes/vulnCodeFixes.ts` — prototype pollution
  in the coding-challenge app scaffolding, not in the application itself.
- `routes/likeProductReviews.ts` — sometimes flagged as NoSQL injection but the
  `_id` query there does not create a command injection path.
