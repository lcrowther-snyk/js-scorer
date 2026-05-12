#!/usr/bin/env python3
"""
Compare two or more scorecard.json files produced by score_sarif.py and
write a self-contained HTML report.

Usage:
    python3 compare_scorecards.py \
        --scorecard Snyk=scorecard-snyk/scorecard.json \
        --scorecard Semgrep=scorecard-semgrep/scorecard.json \
        --scorecard Aikido=scorecard-aikido/scorecard.json \
        --out comparison.html
"""
from __future__ import annotations

import argparse
import html as _htm
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def esc(v) -> str:
    return _htm.escape(str(v)) if v is not None else "—"


def fmt(v, d: int = 3) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "—"
    return f"{float(v):.{d}f}"


_SAFE_ROOT = os.path.realpath(os.path.abspath(os.getcwd()))


def _confine_to_root(path: str, kind: str) -> str:
    """Resolve a CLI-supplied path and confine it under the working directory.

    Rejects null bytes and any resolved path that escapes the safe root via
    symlinks or '..' traversal. Returns the canonical, validated path.
    """
    if not path or "\x00" in path:
        sys.exit(f"Invalid {kind} path.")
    resolved = os.path.realpath(os.path.abspath(path))
    try:
        common = os.path.commonpath([_SAFE_ROOT, resolved])
    except ValueError:
        sys.exit(f"{kind.capitalize()} path is not valid: {path!r}")
    if common != _SAFE_ROOT:
        sys.exit(f"{kind.capitalize()} path escapes the working directory: {path!r}")
    return resolved


def _safe_input_path(path: str) -> str:
    """Validate a CLI-supplied input path: confined + must exist as a file."""
    resolved = _confine_to_root(path, "input")
    if not os.path.isfile(resolved):
        sys.exit(f"scorecard not found: {resolved}")
    return resolved


def _safe_output_path(path: str) -> str:
    """Validate a CLI-supplied output path: confined + parent dir must exist."""
    resolved = _confine_to_root(path, "output")
    parent = os.path.dirname(resolved) or _SAFE_ROOT
    if not os.path.isdir(parent):
        sys.exit(f"Output directory does not exist: {parent}")
    return resolved


def load(path: str) -> dict:
    safe = _safe_input_path(path)
    # Read via pathlib after explicit containment + existence checks above.
    return json.loads(Path(safe).read_text(encoding="utf-8"))


def metric_tone(v, allow_negative: bool = False) -> str:
    if v is None:
        return ""
    if not allow_negative:
        return "tone-success" if v >= 0.7 else "tone-warning" if v >= 0.5 else "tone-danger"
    return "tone-success" if v >= 0.3 else "tone-warning" if v >= 0.0 else "tone-danger"


def best_idx(values: list, allow_negative: bool = False, higher_better: bool = True) -> int | None:
    """Index of the leader column, or None if tied / no numeric values."""
    nums = [(i, v) for i, v in enumerate(values) if isinstance(v, (int, float))]
    if not nums:
        return None
    nums.sort(key=lambda kv: kv[1], reverse=higher_better)
    if len(nums) > 1 and nums[0][1] == nums[1][1]:
        return None
    return nums[0][0]


CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
  font-size: 14px; line-height: 1.5; color: #111827; background: #f8fafc;
  padding: 32px 24px; }
.page { max-width: 1180px; margin: 0 auto; }
.hdr-title { font-size: 24px; font-weight: 700; }
.hdr-meta { color: #6b7280; font-size: 13px; margin-top: 4px; }
.tool-chips { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
.chip { background:#fff; border:1px solid #e5e7eb; border-radius:999px;
  padding: 4px 12px; font-size: 12px; color: #374151; }
.chip b { color: #111827; }
h2 { font-size: 15px; font-weight: 600; color: #111; margin: 32px 0 14px;
  padding-bottom: 6px; border-bottom: 1px solid #e5e7eb; }
.card { background:#fff; border:1px solid #e5e7eb; border-radius:8px;
  padding: 18px 20px; }
.summary { display: grid; gap: 14px; }
.summary table { width: 100%; border-collapse: collapse; font-size: 13px; }
.summary th, .summary td { text-align: right; padding: 10px 12px;
  border-bottom: 1px solid #f1f5f9; }
.summary th:first-child, .summary td:first-child { text-align: left;
  font-weight: 500; color: #374151; }
.summary thead th { font-size: 11px; text-transform: uppercase;
  letter-spacing: 0.05em; color: #6b7280; font-weight: 600;
  border-bottom: 1px solid #e5e7eb; background: #f8fafc; }
.summary td.lead { font-weight: 700; color: #15803d;
  background: linear-gradient(0deg, rgba(22,163,74,.08), rgba(22,163,74,.08)); }
.legend { font-size: 12px; color: #6b7280; margin-top: 8px; }
.tone-success { color: #16a34a; }
.tone-warning { color: #d97706; }
.tone-danger  { color: #dc2626; }
.tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 14px; }
.tool-card { background:#fff; border:1px solid #e5e7eb; border-radius:10px;
  padding: 18px 20px; }
.tool-card .tname { font-size: 16px; font-weight: 700; }
.tool-card .tdriver { font-size: 12px; color:#6b7280; margin-top: 2px; }
.tool-card .stats { display:grid; grid-template-columns: repeat(2, 1fr);
  gap: 10px; margin-top: 14px; }
.tool-card .stat { background:#f8fafc; border:1px solid #f1f5f9;
  border-radius: 6px; padding: 10px 12px; }
.tool-card .stat .v { font-size: 18px; font-weight: 700; }
.tool-card .stat .l { font-size: 10px; color: #6b7280; text-transform: uppercase;
  letter-spacing: 0.05em; font-weight: 600; margin-top: 2px; }
.coverage { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 14px; }
.coverage .card h3 { font-size: 13px; font-weight: 600; color: #111;
  margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
.coverage .badge { font-size: 11px; background:#eef2ff; color:#3730a3;
  border-radius:999px; padding: 2px 8px; font-weight:600; }
.coverage ul { list-style: none; max-height: 360px; overflow-y: auto; }
.coverage li { padding: 6px 0; border-bottom: 1px solid #f8fafc;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px; color: #374151; }
.matrix { width: 100%; border-collapse: collapse; font-size: 12px;
  background:#fff; border:1px solid #e5e7eb; border-radius: 8px;
  overflow: hidden; }
.matrix th, .matrix td { padding: 8px 10px; text-align: center;
  border-bottom: 1px solid #f1f5f9; }
.matrix th { background:#f8fafc; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; }
.matrix td.k { text-align: left; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  color: #374151; font-size: 12px; }
.matrix td.hit { background: #dcfce7; color: #166534; font-weight: 600; }
.matrix td.miss { color: #cbd5e1; }
.foot { margin-top: 30px; color: #9ca3af; font-size: 12px; text-align: center; }
"""


def render(tools: list[tuple[str, dict]], out_path: str) -> None:
    # ── per-tool detected & missed sets ─────────────────────────────────────
    detected = {label: {tp["challenge_key"] for tp in d["true_positives"]}
                for label, d in tools}
    missed = {label: {fn["challenge_key"] for fn in d["false_negatives"]}
              for label, d in tools}
    all_challenges: set[str] = set()
    for s in detected.values(): all_challenges |= s
    for s in missed.values(): all_challenges |= s

    caught_any = set().union(*detected.values()) if detected else set()
    caught_all = set.intersection(*detected.values()) if detected else set()

    # All scorecards in a single report should use the same severity floor.
    sev_floors = {d.get("min_severity", "low") for _, d in tools}
    min_sev = next(iter(sev_floors)) if len(sev_floors) == 1 else "mixed"
    sev_label = "all severities" if min_sev in {"low", "info"} else f"≥ {min_sev}"

    # ── summary table rows ──────────────────────────────────────────────────
    # Only post-filter (in-scope) numbers — the report honours whatever
    # filtering produced each scorecard JSON.
    METRIC_ROWS = [
        ("Findings",        lambda d: d["totals"]["in_scope"],               0, False, True),
        ("True positives",  lambda d: d["metrics"]["TP"],                    0, False, True),
        ("False positives", lambda d: d["metrics"]["FP"],                    0, False, False),
        ("False negatives", lambda d: d["metrics"]["FN"],                    0, False, False),
        ("Precision",       lambda d: d["metrics"]["precision"],             3, False, True),
        ("Recall",          lambda d: d["metrics"]["recall"],                3, False, True),
        ("F1",              lambda d: d["metrics"]["f1"],                    3, False, True),
        ("Youden J",        lambda d: d["metrics"]["youden_j"],              3, True,  True),
        ("Specificity",     lambda d: d["metrics"]["specificity"],           3, False, True),
    ]

    head_cells = "".join(f"<th>{esc(label)}</th>" for label, _ in tools)
    rows_html: list[str] = []
    for name, fn, dp, allow_neg, higher_better in METRIC_ROWS:
        vals = []
        for _, d in tools:
            try: vals.append(fn(d))
            except Exception: vals.append(None)
        HIGHLIGHT = {"Precision", "Recall", "F1", "Youden J", "Specificity",
                     "True positives"}
        lead = best_idx(vals, allow_neg, higher_better) if name in HIGHLIGHT else None
        cells = []
        for i, v in enumerate(vals):
            cls = "lead" if lead == i else ""
            text = fmt(v, dp) if dp else (esc(v) if v is not None else "—")
            cells.append(f'<td class="{cls}">{text}</td>')
        rows_html.append(f"<tr><td>{esc(name)}</td>{''.join(cells)}</tr>")

    # ── per-tool cards ──────────────────────────────────────────────────────
    tool_cards = []
    for label, d in tools:
        m, t = d["metrics"], d["totals"]
        tool_cards.append(f"""
        <div class="tool-card">
          <div class="tname">{esc(label)}</div>
          <div class="tdriver">{esc(d.get('tool'))} v{esc(d.get('tool_version'))}</div>
          <div class="stats">
            <div class="stat"><div class="v">{m['TP']}</div><div class="l">True positives</div></div>
            <div class="stat"><div class="v">{m['FP']}</div><div class="l">False positives</div></div>
            <div class="stat"><div class="v {metric_tone(m['precision'])}">{fmt(m['precision'])}</div><div class="l">Precision</div></div>
            <div class="stat"><div class="v {metric_tone(m['recall'])}">{fmt(m['recall'])}</div><div class="l">Recall</div></div>
            <div class="stat"><div class="v {metric_tone(m['f1'])}">{fmt(m['f1'])}</div><div class="l">F1</div></div>
            <div class="stat"><div class="v {metric_tone(m['youden_j'], True)}">{fmt(m['youden_j'])}</div><div class="l">Youden J</div></div>
          </div>
        </div>""")

    # ── coverage panels ─────────────────────────────────────────────────────
    panels: list[str] = []
    panels.append(f"""
      <div class="card">
        <h3>Caught by all <span class="badge">{len(caught_all)}</span></h3>
        <ul>{''.join(f'<li>{esc(k)}</li>' for k in sorted(caught_all)) or '<li>—</li>'}</ul>
      </div>""")

    for label, _ in tools:
        others = set().union(*[detected[l] for l, _ in tools if l != label])
        only = detected[label] - others
        panels.append(f"""
        <div class="card">
          <h3>Only by {esc(label)} <span class="badge">{len(only)}</span></h3>
          <ul>{''.join(f'<li>{esc(k)}</li>' for k in sorted(only)) or '<li>—</li>'}</ul>
        </div>""")

    missed_all = set()
    if detected:
        missed_all = set.intersection(*[missed[l] for l, _ in tools])
    panels.append(f"""
      <div class="card">
        <h3>Missed by all <span class="badge">{len(missed_all)}</span></h3>
        <ul>{''.join(f'<li>{esc(k)}</li>' for k in sorted(missed_all)) or '<li>—</li>'}</ul>
      </div>""")

    # ── per-challenge matrix ────────────────────────────────────────────────
    matrix_head = "<th>Challenge</th>" + "".join(f"<th>{esc(l)}</th>" for l, _ in tools)
    matrix_rows: list[str] = []
    for k in sorted(all_challenges):
        cells = []
        for label, _ in tools:
            if k in detected[label]:
                cells.append('<td class="hit">●</td>')
            else:
                cells.append('<td class="miss">○</td>')
        matrix_rows.append(f'<tr><td class="k">{esc(k)}</td>{"".join(cells)}</tr>')

    # ── chips: tool, version, sarif ─────────────────────────────────────────
    chips: list[str] = []
    for label, d in tools:
        chips.append(f'<span class="chip"><b>{esc(label)}</b> · '
                     f'{esc(d.get("tool"))} v{esc(d.get("tool_version"))} · '
                     f'{esc(os.path.basename(d.get("sarif", "")))}</span>')

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    gt = tools[0][1].get("ground_truth", "") if tools else ""

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>SAST Tool Comparison</title>
<style>{CSS}</style>
</head>
<body>
<div class="page">
  <div>
    <div class="hdr-title">SAST Tool Comparison</div>
    <div class="hdr-meta">Generated {esc(ts)} · ground truth: {esc(os.path.basename(gt))} ·
      severity floor: <b>{esc(sev_label)}</b> ·
      {len(all_challenges)} SAST-detectable challenges · {len(caught_any)} caught by at least one tool</div>
    <div class="tool-chips">{''.join(chips)}</div>
  </div>

  <h2>Headline metrics</h2>
  <div class="card summary">
    <table>
      <thead><tr><th>Metric</th>{head_cells}</tr></thead>
      <tbody>{''.join(rows_html)}</tbody>
    </table>
    <div class="legend">Highlighted cell = clear winner for that metric (ties not highlighted).
      Tone colours apply to per-tool cards below: green ≥ 0.7, amber ≥ 0.5, red &lt; 0.5
      (Youden J: green ≥ 0.3, amber ≥ 0, red &lt; 0).</div>
  </div>

  <h2>Per-tool snapshot</h2>
  <div class="tools-grid">{''.join(tool_cards)}</div>

  <h2>Challenge coverage</h2>
  <div class="coverage">{''.join(panels)}</div>

  <h2>Per-challenge matrix</h2>
  <table class="matrix">
    <thead><tr>{matrix_head}</tr></thead>
    <tbody>{''.join(matrix_rows)}</tbody>
  </table>

  <div class="foot">score_sarif.py · compare_scorecards.py</div>
</div>
</body>
</html>"""

    safe_out = _safe_output_path(out_path)
    with open(safe_out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"wrote {safe_out}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare two or more scorecard.json files.")
    ap.add_argument("--scorecard", action="append", required=True,
                    help="LABEL=path/to/scorecard.json (repeatable)")
    ap.add_argument("--out", default="comparison.html", help="Output HTML path")
    args = ap.parse_args()

    tools: list[tuple[str, dict]] = []
    for spec in args.scorecard:
        if "=" not in spec:
            sys.exit(f"--scorecard expects LABEL=path, got: {spec}")
        label, path = spec.split("=", 1)
        tools.append((label.strip(), load(path.strip())))
    if len(tools) < 2:
        sys.exit("Need at least two scorecards to compare.")
    render(tools, args.out)


if __name__ == "__main__":
    main()
