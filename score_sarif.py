#!/usr/bin/env python3
"""
SAST scorer: measures how well a SARIF-emitting tool finds OWASP Juice Shop
vulnerabilities.  Works with any tool that emits SARIF v2.1.0 – Snyk Code is
just the first tool tested.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import logging
import math
import os
import re
import sys
from collections import defaultdict
from typing import Any

import yaml

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_EXCLUDE_PATTERNS = [
    "test/",
    "cypress/",
    "*.spec.ts",
    "*.test.ts",
    "frontend/src/assets/",
]

DEFAULT_INFORMATIONAL_CWES = {"CWE-547", "CWE-319"}

# Severity model — ordered low → critical.  "info" is reserved for findings
# the tool itself classifies as informational (SARIF level "none"/"note" with
# no CVSS score).  "low" is the default minimum, i.e. no filtering.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# SARIF result.level → severity bucket fallback when no numeric score present.
_LEVEL_TO_SEVERITY = {
    "error":   "high",
    "warning": "medium",
    "note":    "low",
    "none":    "info",
    "":        "info",
}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _norm_cwe(raw: Any) -> set[str]:
    """Normalise a CWE value (int, str, list, dict) to a set of 'CWE-NNN' strings.

    Tolerates the various ways different SARIF emitters encode CWEs:
      - Snyk: list of "CWE-79" strings under rule.properties.cwe
      - Semgrep / Opengrep / Aikido: tag strings like "CWE-79: Improper ..."
        or a single descriptive string under rule.properties.cwe
      - Taxonomy refs with bare numeric id ("79") under result.taxa[].id
    """
    if raw is None:
        return set()
    if isinstance(raw, bool):
        return set()
    if isinstance(raw, int):
        return {f"CWE-{raw}"}
    if isinstance(raw, str):
        s = raw.strip()
        # Extract every CWE-NNN occurrence from the string (handles
        # "CWE-79: Improper Neutralization ..." style tags).
        matches = _CWE_RE.findall(s)
        if matches:
            return {f"CWE-{m}" for m in matches}
        # Bare numeric string like "79" — only accept if it looks like an ID.
        if s.isdigit():
            return {f"CWE-{s}"}
        return set()
    if isinstance(raw, list):
        result: set[str] = set()
        for item in raw:
            result |= _norm_cwe(item)
        return result
    if isinstance(raw, dict):
        # e.g. {"id": "79"} or {"id": "CWE-79"}
        return _norm_cwe(raw.get("id"))
    return set()


def _extract_rule_cwes(rule: dict) -> set[str]:
    """Pull CWEs from every place known SARIF emitters stash them on a rule."""
    cwes: set[str] = set()
    props = rule.get("properties", {}) or {}
    # Direct fields (Snyk, some Semgrep configs)
    cwes |= _norm_cwe(props.get("cwe"))
    cwes |= _norm_cwe(props.get("cwes"))
    # Tags (Semgrep / Opengrep / Aikido) — strings like "CWE-79: ..."
    cwes |= _norm_cwe(props.get("tags"))
    # SARIF relationships referencing the CWE taxonomy
    for rel in rule.get("relationships", []) or []:
        target = (rel.get("target") or {})
        tc = (target.get("toolComponent") or {}).get("name", "")
        if "cwe" in str(tc).lower():
            cwes |= _norm_cwe(target.get("id"))
    return cwes


def _cvss_to_severity(score: float) -> str:
    """CVSS-style 0–10 score → severity bucket (matches GitHub/Snyk convention)."""
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0:  return "low"
    return "info"


def _severity_from_props(props: dict) -> str | None:
    """Pull a severity bucket out of a SARIF properties bag.

    Recognises (in priority order):
      - properties["security-severity"]  (numeric CVSS, GitHub/Snyk/Semgrep)
      - properties["severity"]            (free-form: critical/high/medium/low/info)
      - properties["problem.severity"]    (CodeQL: error/warning/note)
    Returns None if nothing usable was found, so the caller can fall back.
    """
    if not props:
        return None
    raw = props.get("security-severity") or props.get("securitySeverity")
    if raw is not None:
        try:
            return _cvss_to_severity(float(raw))
        except (TypeError, ValueError):
            pass
    sev = props.get("severity") or props.get("problem.severity")
    if isinstance(sev, str):
        s = sev.strip().lower()
        if s.startswith("crit"):   return "critical"
        if s == "high" or s == "error":   return "high"
        if s == "medium" or s == "moderate" or s == "warning": return "medium"
        if s == "low":             return "low"
        if s in {"info", "informational", "note", "none"}: return "info"
    return None


def _extract_result_cwes(result: dict) -> set[str]:
    """Pull CWEs declared on an individual result (taxa, properties)."""
    cwes: set[str] = set()
    props = result.get("properties", {}) or {}
    cwes |= _norm_cwe(props.get("cwe"))
    cwes |= _norm_cwe(props.get("cwes"))
    cwes |= _norm_cwe(props.get("tags"))
    for tx in result.get("taxa", []) or []:
        tc = (tx.get("toolComponent") or {}).get("name", "")
        if "cwe" in str(tc).lower() or tx.get("toolComponent") is None:
            cwes |= _norm_cwe(tx.get("id"))
    return cwes


def _path_excluded(uri: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if pat.endswith("/"):
            if uri.startswith(pat) or ("/" + pat) in uri:
                return True
        elif fnmatch.fnmatch(uri, pat) or fnmatch.fnmatch(os.path.basename(uri), pat):
            return True
    return False


def _fmt_pct(num: float | None) -> str:
    if num is None or math.isnan(num):
        return "n/a"
    return f"{num:.4f}"


# ──────────────────────────────────────────────────────────────────────────────
# SARIF parsing
# ──────────────────────────────────────────────────────────────────────────────

def _safe_open_read(path: str) -> str:
    """Resolve and validate a CLI-supplied input path before opening."""
    if not path or "\x00" in path:
        log.error("Invalid input path.")
        sys.exit(1)
    resolved = os.path.realpath(os.path.abspath(path))
    if not os.path.isfile(resolved):
        log.error("Input file not found: %s", resolved)
        sys.exit(1)
    return resolved


def _safe_output_dir(path: str) -> str:
    """Resolve and validate a CLI-supplied output directory path."""
    if not path or "\x00" in path:
        log.error("Invalid output directory.")
        sys.exit(1)
    return os.path.realpath(os.path.abspath(path))


def parse_sarif(path: str) -> tuple[str, str, list[dict]]:
    """
    Returns (tool_name, tool_version, findings).

    Each finding dict has keys:
      rule_id, uri, start_line, end_line, level, cwes (set[str])
    """
    with open(_safe_open_read(path), encoding="utf-8") as fh:
        doc = json.load(fh)

    runs = doc.get("runs", [])
    if not runs:
        log.error("No runs found in SARIF")
        sys.exit(1)

    all_findings: list[dict] = []
    tool_name = tool_version = "unknown"

    for run in runs:
        driver = run.get("tool", {}).get("driver", {})
        tool_name = driver.get("name", tool_name)
        tool_version = driver.get("version", driver.get("semanticVersion", tool_version))

        # Build rule_id -> [cwes] lookup once per run. Also index by rule
        # array position to support results that reference rules via
        # `ruleIndex` instead of `ruleId` (common in Semgrep/Opengrep output).
        rules = driver.get("rules", []) or []
        # Pull rules from extensions too (Semgrep registers some rules there).
        for ext in run.get("tool", {}).get("extensions", []) or []:
            rules += ext.get("rules", []) or []
        rule_cwes: dict[str, set[str]] = {}
        rule_cwes_by_idx: list[set[str]] = []
        rule_sev: dict[str, str | None] = {}
        rule_sev_by_idx: list[str | None] = []
        for rule in rules:
            rid = rule.get("id", "")
            cwes = _extract_rule_cwes(rule)
            sev = _severity_from_props(rule.get("properties", {}) or {})
            # Try defaultConfiguration.level if properties had nothing.
            if sev is None:
                dc_level = (rule.get("defaultConfiguration") or {}).get("level")
                if dc_level:
                    sev = _LEVEL_TO_SEVERITY.get(dc_level.lower())
            if rid:
                rule_cwes[rid] = cwes
                rule_sev[rid] = sev
            rule_cwes_by_idx.append(cwes)
            rule_sev_by_idx.append(sev)

        for result in run.get("results", []):
            locs = result.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            rule_id = result.get("ruleId", "")
            rule_idx = result.get("ruleIndex")
            cwes = set(rule_cwes.get(rule_id, set()))
            if not cwes and isinstance(rule_idx, int) and 0 <= rule_idx < len(rule_cwes_by_idx):
                cwes |= rule_cwes_by_idx[rule_idx]
            # Fallback: CWEs declared on the result itself.
            cwes |= _extract_result_cwes(result)

            # Severity: prefer per-result props, then rule props, then SARIF level.
            level = result.get("level", "") or ""
            severity = _severity_from_props(result.get("properties", {}) or {})
            if severity is None:
                severity = rule_sev.get(rule_id)
            if severity is None and isinstance(rule_idx, int) and 0 <= rule_idx < len(rule_sev_by_idx):
                severity = rule_sev_by_idx[rule_idx]
            if severity is None:
                severity = _LEVEL_TO_SEVERITY.get(level.lower(), "info")

            all_findings.append(
                {
                    "rule_id": rule_id,
                    "uri": uri,
                    "start_line": region.get("startLine"),
                    "end_line": region.get("endLine"),
                    "level": level,
                    "severity": severity,
                    "cwes": cwes,
                }
            )

    return tool_name, tool_version, all_findings


# ──────────────────────────────────────────────────────────────────────────────
# Ground-truth loading
# ──────────────────────────────────────────────────────────────────────────────

def load_ground_truth(path: str) -> list[dict]:
    with open(_safe_open_read(path), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    challenges = []
    for c in (data or []):
        if not isinstance(c, dict):
            continue
        c["_cwes"] = _norm_cwe(c.get("cwe"))
        c["_vuln_files"] = set(c.get("vulnerable_files") or [])
        challenges.append(c)
    return challenges


# ──────────────────────────────────────────────────────────────────────────────
# HTML report writer
# ──────────────────────────────────────────────────────────────────────────────

def _write_html(result: dict, out_dir: str) -> str:
    """Write a self-contained HTML scorecard and return the output path."""
    out_dir = _safe_output_dir(out_dir)
    import html as _htm
    from datetime import datetime, timezone

    def esc(v: Any) -> str:
        return _htm.escape(str(v)) if v is not None else "\u2014"

    def fmt(v: Any, d: int = 3) -> str:
        if v is None or (isinstance(v, float) and math.isnan(v)):
            return "\u2014"
        return f"{float(v):.{d}f}"

    def metric_tone(v: Any, allow_negative: bool = False) -> str:
        if v is None:
            return ""
        if not allow_negative:
            return "tone-success" if v >= 0.7 else "tone-warning" if v >= 0.5 else "tone-danger"
        return "tone-success" if v >= 0.3 else "tone-warning" if v >= 0.0 else "tone-danger"

    metrics  = result["metrics"]
    totals   = result["totals"]
    TP, FP, FN, TN = metrics["TP"], metrics["FP"], metrics["FN"], metrics["TN"]
    precision, recall, f1 = metrics["precision"], metrics["recall"], metrics["f1"]
    youden_j = metrics["youden_j"]

    # ── SVG donut ────────────────────────────────────────────────────────────
    def svg_donut(segs: list[tuple[int, str]], size: int = 148, sw: int = 20) -> str:
        r   = (size - sw) / 2
        cx  = cy = size / 2
        C   = 2 * math.pi * r
        tot = sum(v for v, _ in segs)
        if tot == 0:
            return ""
        parts: list[str] = []
        cum = 0.0
        for val, color in segs:
            if val <= 0:
                continue
            seg = val / tot * C
            parts.append(
                f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="none"'
                f' stroke="{color}" stroke-width="{sw}"'
                f' stroke-dasharray="{seg:.3f} {C - seg:.3f}"'
                f' stroke-dashoffset="{C - cum:.3f}"'
                f' transform="rotate(-90 {cx:.1f} {cy:.1f})"/>'
            )
            cum += seg
        return (
            f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
            + "".join(parts) + "</svg>"
        )

    donut = svg_donut(
        [(TP, "#16a34a"), (FP, "#dc2626"), (FN, "#d97706"), (TN, "#0369a1")]
    )

    # ── CSS (plain string — no brace-escaping needed here) ───────────────────
    css = "\n".join([
        "*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }",
        "body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;"
        " font-size: 14px; line-height: 1.5; color: #111827; background: #f8fafc;"
        " padding: 32px 24px; }",
        ".page { max-width: 1100px; margin: 0 auto; }",
        ".hdr-title { font-size: 22px; font-weight: 700; }",
        ".hdr-meta { color: #6b7280; font-size: 13px; margin-top: 3px; }",
        "h2 { font-size: 15px; font-weight: 600; color: #111; margin: 28px 0 12px;"
        " padding-bottom: 6px; border-bottom: 1px solid #e5e7eb; }",
        ".stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;"
        " margin-top: 20px; }",
        ".stat-card { background: #fff; border: 1px solid #e5e7eb;"
        " border-radius: 8px; padding: 16px 18px; }",
        ".stat-value { font-size: 30px; font-weight: 700; line-height: 1.1; }",
        ".stat-label { font-size: 11px; color: #6b7280; margin-top: 5px;"
        " text-transform: uppercase; letter-spacing: 0.05em; font-weight: 500; }",
        ".tone-success { color: #16a34a; }",
        ".tone-danger  { color: #dc2626; }",
        ".tone-warning { color: #d97706; }",
        ".tone-info    { color: #0369a1; }",
        ".callout { border-left: 3px solid #d97706; background: #fffbeb;"
        " padding: 10px 16px; border-radius: 0 6px 6px 0; font-size: 13px; margin: 16px 0; }",
        ".callout strong { color: #92400e; }",
        ".counts-row { display: grid; grid-template-columns: 1fr 220px; gap: 24px;"
        " align-items: start; margin-top: 4px; }",
        ".counts-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }",
        ".donut-wrap { display: flex; flex-direction: column; align-items: center; gap: 10px; }",
        ".donut-legend { display: flex; flex-direction: column; gap: 5px; font-size: 12px; }",
        ".legend-row { display: flex; align-items: center; gap: 6px; }",
        ".legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }",
        ".vol-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;"
        " margin-top: 4px; }",
        ".vol-card { background: #fff; border: 1px solid #e5e7eb;"
        " border-radius: 8px; padding: 12px 16px; }",
        ".vol-value { font-size: 22px; font-weight: 700; }",
        ".vol-label { font-size: 11px; color: #6b7280; margin-top: 3px;"
        " text-transform: uppercase; letter-spacing: 0.04em; }",
        "table { width: 100%; border-collapse: collapse; background: #fff;"
        " border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; font-size: 12.5px; }",
        "thead th { background: #f9fafb; font-weight: 600; text-align: left;"
        " padding: 8px 12px; border-bottom: 1px solid #e5e7eb; white-space: nowrap; font-size: 12px; }",
        "td { padding: 7px 12px; border-bottom: 1px solid #f3f4f6; vertical-align: middle; }",
        "tr:last-child td { border-bottom: none; }",
        "tr:hover td { background: #f9fafb; }",
        ".num { text-align: right; font-variant-numeric: tabular-nums; }",
        "code { background: #f3f4f6; padding: 1px 5px; border-radius: 3px;"
        " font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;"
        " font-size: 11px; word-break: break-all; }",
        ".row-success td { background: #f0fdf4; }",
        ".row-danger  td { background: #fef2f2; }",
        ".row-warning td { background: #fffbeb; }",
        ".bar-cell { min-width: 100px; padding: 7px 12px; }",
        ".bar-track { height: 8px; background: #f3f4f6; border-radius: 4px;"
        " overflow: hidden; display: flex; }",
        ".bar-tp { background: #16a34a; }",
        ".bar-fp { background: #dc2626; }",
        ".bar-fn { background: #d97706; }",
        "details { border: 1px solid #e5e7eb; border-radius: 8px; background: #fff;"
        " margin-top: 12px; overflow: hidden; }",
        "summary { padding: 12px 16px; font-weight: 600; font-size: 13.5px; cursor: pointer;"
        " user-select: none; display: flex; align-items: center; gap: 8px; list-style: none; }",
        "summary::-webkit-details-marker { display: none; }",
        r"summary::before { content: '\25B6'; font-size: 9px; color: #9ca3af;"
        " display: inline-block; transition: transform 0.15s; min-width: 10px; }",
        "details[open] summary::before { transform: rotate(90deg); }",
        ".badge { display: inline-block; border-radius: 99px; padding: 1px 8px;"
        " font-size: 11px; font-weight: 600; }",
        ".badge-green  { background: #dcfce7; color: #15803d; }",
        ".badge-red    { background: #fee2e2; color: #b91c1c; }",
        ".badge-amber  { background: #fef9c3; color: #92400e; }",
        ".ml-auto { margin-left: auto; }",
        ".footer { margin-top: 40px; font-size: 12px; color: #9ca3af;"
        " border-top: 1px solid #e5e7eb; padding-top: 12px; }",
    ])

    # ── per-CWE rows ─────────────────────────────────────────────────────────
    per_cwe = result["per_cwe"]
    max_bar = max((r["TP"] + r["FP"] + r["FN"]) for r in per_cwe) if per_cwe else 1

    def bar(tp: int, fp: int, fn: int) -> str:
        if max_bar == 0:
            return '<div class="bar-track"></div>'
        return (
            '<div class="bar-track">'
            f'<div class="bar-tp" style="width:{tp / max_bar * 100:.1f}%"></div>'
            f'<div class="bar-fp" style="width:{fp / max_bar * 100:.1f}%"></div>'
            f'<div class="bar-fn" style="width:{fn / max_bar * 100:.1f}%"></div>'
            "</div>"
        )

    def cwe_cls(r: dict) -> str:
        if r["TP"] > 0 and r["FP"] == 0 and r["FN"] == 0:
            return "row-success"
        if r["TP"] == 0 and r["FP"] > 0 and r["FN"] == 0:
            return "row-danger"
        if r["TP"] == 0 and r["FP"] == 0 and r["FN"] > 0:
            return "row-warning"
        return ""

    cwe_rows = "".join(
        f'<tr class="{cwe_cls(r)}">'
        f'<td><code>{esc(r["cwe"])}</code></td>'
        f'<td class="num">{r["TP"]}</td>'
        f'<td class="num">{r["FP"]}</td>'
        f'<td class="num">{r["FN"]}</td>'
        f'<td class="num">{fmt(r["precision"])}</td>'
        f'<td class="num">{fmt(r["recall"])}</td>'
        f'<td class="num">{fmt(r["f1"])}</td>'
        f'<td class="bar-cell">{bar(r["TP"], r["FP"], r["FN"])}</td>'
        "</tr>"
        for r in per_cwe
    )

    # ── TP rows ───────────────────────────────────────────────────────────────
    tp_rows = "".join(
        f'<tr><td>{esc(tp["challenge_name"])}</td>'
        f'<td><code>{esc(f["rule_id"])}</code></td>'
        f'<td><code>{esc(f["uri"])}</code></td>'
        f'<td class="num">{esc(f["line"])}</td>'
        f'<td><code>{esc(", ".join(f["cwes"]) if isinstance(f["cwes"], list) else str(f["cwes"]))}</code></td>'
        "</tr>"
        for tp in result["true_positives"]
        for f in tp["findings"]
    )

    # ── FP rows ───────────────────────────────────────────────────────────────
    def cwes_str(cwes: Any) -> str:
        if isinstance(cwes, (list, set)):
            return ", ".join(sorted(cwes))
        return str(cwes)

    fp_rows = "".join(
        f'<tr><td><code>{esc(f["rule_id"])}</code></td>'
        f'<td><code>{esc(f["uri"])}</code></td>'
        f'<td class="num">{esc(f["line"])}</td>'
        f'<td><code>{esc(cwes_str(f["cwes"]))}</code></td>'
        "</tr>"
        for f in result["false_positives"]
    )

    # ── FN rows ───────────────────────────────────────────────────────────────
    def conf_badge(c: str) -> str:
        if c == "high":
            return f'<span class="badge badge-amber">{esc(c)}</span>'
        return esc(c)

    fn_rows = "".join(
        f'<tr><td>{esc(c["challenge_name"])}</td>'
        f'<td>{esc(c.get("category", ""))}</td>'
        f'<td><code>CWE-{esc(c.get("cwe", ""))}</code></td>'
        f'<td><code>{esc(", ".join(c.get("vulnerable_files") or []) or chr(8212))}</code></td>'
        f'<td>{conf_badge(c.get("confidence", ""))}</td>'
        "</tr>"
        for c in result["false_negatives"]
    )

    # ── assemble HTML ─────────────────────────────────────────────────────────
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tool_str  = f"{esc(result['tool'])} {esc(result['tool_version'])}"
    p_cls = metric_tone(precision)
    r_cls = metric_tone(recall)
    f_cls = metric_tone(f1)
    j_cls = metric_tone(youden_j, allow_negative=True)

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="utf-8">',
        '  <meta name="viewport" content="width=device-width,initial-scale=1">',
        f'  <title>SAST Scorecard \u2014 {esc(result["tool"])} {esc(result["tool_version"])}</title>',
        f"  <style>\n{css}\n  </style>",
        "</head>",
        "<body>",
        '<div class="page">',
        f'<div class="hdr-title">SAST Scorecard</div>',
        f'<div class="hdr-meta">{tool_str}&nbsp;&nbsp;&middot;&nbsp;&nbsp;'
        f'<code>{esc(result["sarif"])}</code> vs <code>{esc(result["ground_truth"])}</code></div>',
        f'<div class="callout"><strong>Results summary</strong>&nbsp;&mdash;&nbsp;'
        f'Precision&nbsp;{fmt(precision)}, Recall&nbsp;{fmt(recall)}, '
        f"F1&nbsp;{fmt(f1)}, Youden's&nbsp;J&nbsp;{fmt(youden_j)}. "
        f'{totals["sast_detectable_challenges"]} SAST-detectable challenges in ground truth.</div>',
        '<div class="stat-grid">',
        f'  <div class="stat-card"><div class="stat-value {p_cls}">{fmt(precision)}</div>'
        f'<div class="stat-label">Precision</div></div>',
        f'  <div class="stat-card"><div class="stat-value {r_cls}">{fmt(recall)}</div>'
        f'<div class="stat-label">Recall</div></div>',
        f'  <div class="stat-card"><div class="stat-value {f_cls}">{fmt(f1)}</div>'
        f'<div class="stat-label">F1 Score</div></div>',
        f'  <div class="stat-card"><div class="stat-value {j_cls}">{fmt(youden_j)}</div>'
        f"<div class=\"stat-label\">Youden's J</div></div>",
        "</div>",
        "<h2>Finding Counts</h2>",
        '<div class="counts-row">',
        "  <div>",
        '    <div class="counts-grid">',
        f'      <div class="stat-card"><div class="stat-value tone-success">{TP}</div>'
        f'<div class="stat-label">True Positives</div></div>',
        f'      <div class="stat-card"><div class="stat-value tone-danger">{FP}</div>'
        f'<div class="stat-label">False Positives</div></div>',
        f'      <div class="stat-card"><div class="stat-value tone-warning">{FN}</div>'
        f'<div class="stat-label">False Negatives</div></div>',
        f'      <div class="stat-card"><div class="stat-value tone-info">{TN}</div>'
        f'<div class="stat-label">True Negatives</div></div>',
        "    </div>",
        '    <p style="font-size:11px;color:#9ca3af;margin-top:8px;">TN: for each FN challenge, '
        "each (vulnerable_file,&nbsp;CWE) pair with no finding = 1&nbsp;TN "
        "(OWASP Benchmark convention).</p>",
        "  </div>",
        '  <div class="donut-wrap">',
        f"    {donut}",
        '    <div class="donut-legend">',
        f'      <div class="legend-row"><div class="legend-dot" style="background:#16a34a"></div>TP ({TP})</div>',
        f'      <div class="legend-row"><div class="legend-dot" style="background:#dc2626"></div>FP ({FP})</div>',
        f'      <div class="legend-row"><div class="legend-dot" style="background:#d97706"></div>FN ({FN})</div>',
        f'      <div class="legend-row"><div class="legend-dot" style="background:#0369a1"></div>TN ({TN})</div>',
        "    </div>",
        "  </div>",
        "</div>",
        "<h2>Volume Breakdown</h2>",
        '<div class="vol-strip">',
        f'  <div class="vol-card"><div class="vol-value">{totals["total_findings"]}</div>'
        '<div class="vol-label">Total findings</div></div>',
        f'  <div class="vol-card"><div class="vol-value">{totals["excluded"]}</div>'
        '<div class="vol-label">Excluded</div></div>',
        f'  <div class="vol-card"><div class="vol-value">{totals["informational"]}</div>'
        '<div class="vol-label">Informational</div></div>',
        f'  <div class="vol-card"><div class="vol-value">{totals["in_scope"]}</div>'
        '<div class="vol-label">In-scope</div></div>',
        "</div>",
        f'<p style="font-size:11px;color:#9ca3af;margin-top:8px;">Excluded patterns: '
        f'{esc(", ".join(result.get("excluded_patterns", [])))}</p>',
        "<h2>Per-CWE Breakdown</h2>",
        "<table>",
        "  <thead><tr>",
        '    <th>CWE</th><th class="num">TP</th><th class="num">FP</th><th class="num">FN</th>',
        '    <th class="num">Precision</th><th class="num">Recall</th><th class="num">F1</th>',
        "    <th>TP / FP / FN</th>",
        "  </tr></thead>",
        f"  <tbody>{cwe_rows}</tbody>",
        "</table>",
        "<h2>Details</h2>",
        "<details open>",
        f'  <summary>True Positives<span class="badge badge-green ml-auto">{TP} matched</span></summary>',
        "  <table><thead><tr>",
        '    <th>Challenge</th><th>Rule</th><th>File</th><th class="num">Line</th><th>CWE</th>',
        f"  </tr></thead><tbody>{tp_rows}</tbody></table>",
        "</details>",
        "<details>",
        f'  <summary>False Positives<span class="badge badge-red ml-auto">{FP} noise</span></summary>',
        "  <table><thead><tr>",
        '    <th>Rule</th><th>File</th><th class="num">Line</th><th>CWE(s)</th>',
        f"  </tr></thead><tbody>{fp_rows}</tbody></table>",
        "</details>",
        "<details>",
        f'  <summary>False Negatives<span class="badge badge-amber ml-auto">{FN} missed</span></summary>',
        "  <table><thead><tr>",
        "    <th>Challenge</th><th>Category</th><th>CWE</th><th>Vulnerable File</th><th>Confidence</th>",
        f"  </tr></thead><tbody>{fn_rows}</tbody></table>",
        "</details>",
        f'<div class="footer">Generated {generated}&nbsp;&middot;&nbsp;'
        f"OWASP Juice Shop ground truth&nbsp;&middot;&nbsp;{tool_str}</div>",
        "</div>",
        "</body>",
        "</html>",
    ]

    html_out  = "\n".join(parts)
    html_path = os.path.join(out_dir, "scorecard.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    return html_path


# ──────────────────────────────────────────────────────────────────────────────
# Scoring engine
# ──────────────────────────────────────────────────────────────────────────────

def score(
    sarif_path: str,
    gt_path: str,
    out_dir: str,
    exclude_patterns: list[str],
    informational_cwes: set[str],
    write_html: bool = False,
    min_severity: str = "low",
) -> None:
    tool_name, tool_version, raw_findings = parse_sarif(sarif_path)
    challenges = load_ground_truth(gt_path)

    total = len(raw_findings)

    # ── Step 1: exclude out-of-scope paths ──────────────────────────────────
    excluded: list[dict] = []
    in_scope_candidates: list[dict] = []
    for f in raw_findings:
        if _path_excluded(f["uri"], exclude_patterns):
            excluded.append(f)
        else:
            in_scope_candidates.append(f)

    log.info("Total findings: %d", total)
    log.info("Excluded (path filter): %d", len(excluded))

    # ── Step 1b: drop anything below the requested severity threshold ──────
    min_rank = SEVERITY_RANK[min_severity]
    severity_filtered: list[dict] = []
    if min_rank > 0:
        keep: list[dict] = []
        for f in in_scope_candidates:
            if SEVERITY_RANK.get(f.get("severity", "info"), 0) < min_rank:
                severity_filtered.append(f)
            else:
                keep.append(f)
        in_scope_candidates = keep
        log.info("Filtered below severity %s: %d", min_severity, len(severity_filtered))

    # ── Step 2: split informational vs. real ────────────────────────────────
    informational: list[dict] = []
    scored_findings: list[dict] = []
    for f in in_scope_candidates:
        # Informational = ALL cwes are in the informational set (or no cwes)
        if f["cwes"] and f["cwes"].issubset(informational_cwes):
            informational.append(f)
        else:
            scored_findings.append(f)

    log.info("Informational (CWE filter): %d", len(informational))
    log.info("In-scope findings to score: %d", len(scored_findings))

    # ── Step 3: detectable challenges ───────────────────────────────────────
    detectable = [c for c in challenges if c.get("sast_detectable") is True]
    log.info("SAST-detectable challenges in ground truth: %d", len(detectable))

    # ── Step 4: match findings to challenges ─────────────────────────────────
    # A finding f matches challenge c when:
    #   f["uri"] ∈ c["_vuln_files"]  AND  f["cwes"] ∩ c["_cwes"] ≠ ∅
    #
    # TP is finding-based: each unique finding that hits ≥1 challenge counts
    # once, even when that single finding covers several overlapping Juice
    # Shop challenges (e.g. one fileServer.ts:33 path-traversal finding spans
    # 5 challenges). The per-challenge cluster is still recorded so we can
    # report `challenges_detected` separately for ground-truth coverage.

    tp_challenges: dict[str, list[dict]] = defaultdict(list)  # challenge key -> [findings]
    tp_finding_ids: set[int] = set()
    fp_findings: list[dict] = []

    for f in scored_findings:
        matched_any = False
        for c in detectable:
            if f["uri"] in c["_vuln_files"] and (f["cwes"] & c["_cwes"]):
                tp_challenges[c["key"]].append(f)
                matched_any = True
        if matched_any:
            tp_finding_ids.add(id(f))
        else:
            fp_findings.append(f)

    # ── Step 5: identify FNs ────────────────────────────────────────────────
    fn_challenges = [c for c in detectable if c["key"] not in tp_challenges]

    # Finding-level for precision; challenge-level for recall (OWASP convention).
    TP = len(tp_finding_ids)
    FP = len(fp_findings)
    FN = len(fn_challenges)
    challenges_detected = len(tp_challenges)
    total_detectable = len(detectable)

    # For TN (OWASP Benchmark convention):
    # A TN for a (file, CWE) pair = a detectable challenge whose (file,CWE)
    # combination produced no finding AND there is no other challenge that maps
    # to that (file,CWE).  We implement this as: for every detectable challenge
    # that is a FN, count each of its (file,CWE) pairs as one TN if no finding
    # was emitted at that (file,CWE) pair.
    emitted_file_cwe: set[tuple[str, str]] = set()
    for f in scored_findings:
        for cwe in f["cwes"]:
            emitted_file_cwe.add((f["uri"], cwe))

    TN = 0
    for c in fn_challenges:
        for vf in c["_vuln_files"]:
            for cwe in c["_cwes"]:
                if (vf, cwe) not in emitted_file_cwe:
                    TN += 1

    # ── Step 6: metrics ──────────────────────────────────────────────────────
    # Precision is finding-based: of the findings emitted, how many were real?
    precision = TP / (TP + FP) if (TP + FP) > 0 else None
    # Recall is coverage-based: of the ground-truth challenges, how many had
    # at least one matching finding?
    recall = (challenges_detected / total_detectable
              if total_detectable > 0 else None)
    f1 = (2 * precision * recall / (precision + recall)
          if (precision is not None and recall is not None
              and (precision + recall) > 0) else None)
    specificity = TN / (TN + FP) if (TN + FP) > 0 else None
    youden_j = ((recall + specificity - 1)
                if (recall is not None and specificity is not None) else None)

    # ── Per-CWE metrics ──────────────────────────────────────────────────────
    # Per-CWE uses the same convention: TP = unique findings whose match CWE
    # was this CWE; recall denominator = challenges with this CWE that had ≥1
    # matching finding vs. those that didn't.
    cwe_tp_findings: dict[str, set[int]] = defaultdict(set)  # cwe -> {id(finding)}
    cwe_challenges_detected: dict[str, set[str]] = defaultdict(set)  # cwe -> {challenge_keys}
    cwe_fp: dict[str, list] = defaultdict(list)
    cwe_fn: dict[str, list] = defaultdict(list)

    for ck, flist in tp_challenges.items():
        c = next(x for x in detectable if x["key"] == ck)
        for f in flist:
            for cwe in (f["cwes"] & c["_cwes"]):
                cwe_tp_findings[cwe].add(id(f))
                cwe_challenges_detected[cwe].add(ck)

    for f in fp_findings:
        for cwe in f["cwes"]:
            cwe_fp[cwe].append(f)

    for c in fn_challenges:
        for cwe in c["_cwes"]:
            cwe_fn[cwe].append(c)

    all_cwes = sorted(set(list(cwe_tp_findings) + list(cwe_fp) + list(cwe_fn)))

    per_cwe: list[dict] = []
    for cwe in all_cwes:
        ct = len(cwe_tp_findings.get(cwe, set()))         # TP findings for this CWE
        chd = len(cwe_challenges_detected.get(cwe, set()))  # challenges with this CWE detected
        cf = len(cwe_fp.get(cwe, []))
        cn = len(cwe_fn.get(cwe, []))
        p = ct / (ct + cf) if (ct + cf) > 0 else None
        r = chd / (chd + cn) if (chd + cn) > 0 else None
        f1c = (2 * p * r / (p + r) if (p is not None and r is not None and (p + r) > 0) else None)
        per_cwe.append({"cwe": cwe, "TP": ct, "challenges_detected": chd,
                         "FP": cf, "FN": cn,
                         "precision": p, "recall": r, "f1": f1c})

    # ── Assemble result dict ─────────────────────────────────────────────────
    result = {
        "tool": tool_name,
        "tool_version": tool_version,
        "sarif": os.path.basename(sarif_path),
        "ground_truth": os.path.basename(gt_path),
        "totals": {
            "total_findings": total,
            "excluded": len(excluded),
            "severity_filtered": len(severity_filtered),
            "informational": len(informational),
            "in_scope": len(scored_findings),
            "sast_detectable_challenges": len(detectable),
        },
        "min_severity": min_severity,
        "metrics": {
            "TP": TP, "FP": FP, "FN": FN, "TN": TN,
            "challenges_detected": challenges_detected,
            "challenges_total": total_detectable,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "youden_j": youden_j,
            "specificity": specificity,
            "TP_formula": (
                "TP = unique findings (file+line+rule) that match ≥1 "
                "ground-truth challenge. A single finding covering multiple "
                "overlapping challenges still counts as 1 TP."
            ),
            "recall_formula": (
                "recall = challenges_detected / challenges_total — coverage "
                "of the ground-truth challenge set."
            ),
            "TN_formula": (
                "For each FN challenge, each (vulnerable_file, CWE) pair "
                "where no finding was emitted counts as one TN "
                "(per OWASP Benchmark convention)."
            ),
        },
        "per_cwe": per_cwe,
        "true_positives": [
            {
                "challenge_key": ck,
                "challenge_name": next(c["name"] for c in detectable if c["key"] == ck),
                "findings": [
                    {"rule_id": f["rule_id"], "uri": f["uri"],
                     "line": f["start_line"], "cwes": sorted(f["cwes"])}
                    for f in flist
                ],
            }
            for ck, flist in sorted(tp_challenges.items())
        ],
        "false_positives": [
            {"rule_id": f["rule_id"], "uri": f["uri"],
             "line": f["start_line"], "level": f["level"],
             "severity": f.get("severity", "info"),
             "cwes": sorted(f["cwes"])}
            for f in fp_findings
        ],
        "false_negatives": [
            {"challenge_key": c["key"], "challenge_name": c["name"],
             "category": c.get("category", ""),
             "cwe": c.get("cwe"),
             "vulnerable_files": list(c.get("_vuln_files", [])),
             "confidence": c.get("confidence", "")}
            for c in fn_challenges
        ],
        "informational_findings": [
            {"rule_id": f["rule_id"], "uri": f["uri"],
             "line": f["start_line"], "cwes": sorted(f["cwes"])}
            for f in informational
        ],
        "excluded_findings_count": len(excluded),
        "excluded_patterns": exclude_patterns,
    }

    resolved_out = _safe_output_dir(out_dir)
    os.makedirs(resolved_out, exist_ok=True)

    # ── Write JSON ───────────────────────────────────────────────────────────
    json_path = os.path.join(resolved_out, "scorecard.json")

    def _default(obj: Any) -> Any:
        if isinstance(obj, set):
            return sorted(obj)
        raise TypeError(type(obj))

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=_default)
    log.info("Wrote %s", json_path)

    # ── Write Markdown ───────────────────────────────────────────────────────
    md_path = os.path.join(resolved_out, "scorecard.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        w = fh.write

        w("# SAST Scorecard\n\n")
        w(f"**Tool:** {tool_name} {tool_version}  \n")
        w(f"**SARIF:** `{os.path.basename(sarif_path)}`  \n")
        w(f"**Ground truth:** `{os.path.basename(gt_path)}`  \n\n")

        w("## Headline metrics\n\n")
        w("| Metric | Value |\n|--------|-------|\n")
        w(f"| Total findings | {total} |\n")
        w(f"| Excluded (path filter) | {len(excluded)} |\n")
        w(f"| Informational (CWE filter) | {len(informational)} |\n")
        w(f"| In-scope findings | {len(scored_findings)} |\n")
        w(f"| SAST-detectable challenges | {len(detectable)} |\n")
        w(f"| TP | {TP} |\n")
        w(f"| FP | {FP} |\n")
        w(f"| FN | {FN} |\n")
        w(f"| TN | {TN} |\n")
        w(f"| Precision | {_fmt_pct(precision)} |\n")
        w(f"| Recall | {_fmt_pct(recall)} |\n")
        w(f"| F1 | {_fmt_pct(f1)} |\n")
        w(f"| Youden's J | {_fmt_pct(youden_j)} |\n\n")

        w("> **TN formula:** For each FN challenge, each (vulnerable_file, CWE) pair "
          "where no finding was emitted counts as one TN "
          "(per OWASP Benchmark convention).\n\n")

        w("## Per-CWE breakdown\n\n")
        w("| CWE | TP | FP | FN | Precision | Recall | F1 |\n")
        w("|-----|----|----|----|-----------|--------|----|\n")
        for row in per_cwe:
            w(f"| {row['cwe']} | {row['TP']} | {row['FP']} | {row['FN']} "
              f"| {_fmt_pct(row['precision'])} | {_fmt_pct(row['recall'])} "
              f"| {_fmt_pct(row['f1'])} |\n")

        w("\n## True Positives\n\n")
        if tp_challenges:
            for ck, flist in sorted(tp_challenges.items()):
                cname = next(c["name"] for c in detectable if c["key"] == ck)
                w(f"### TP: {cname} (`{ck}`)\n\n")
                for f in flist:
                    w(f"- `{f['rule_id']}` → `{f['uri']}` L{f['start_line']}  "
                      f"CWEs: {', '.join(sorted(f['cwes']))}\n")
                w("\n")
        else:
            w("_None_\n\n")

        w("## False Positives\n\n")
        w("Findings that matched no SAST-detectable challenge (by file + CWE).\n\n")
        if fp_findings:
            w("| Rule | File | Line | CWEs |\n|------|------|------|------|\n")
            for f in fp_findings:
                w(f"| `{f['rule_id']}` | `{f['uri']}` | {f['start_line']} "
                  f"| {', '.join(sorted(f['cwes']))} |\n")
        else:
            w("_None_\n")
        w("\n")

        w("## False Negatives\n\n")
        w("SAST-detectable challenges with zero matching findings.\n\n")
        if fn_challenges:
            w("| Challenge | Category | CWE | Vulnerable files | Confidence |\n")
            w("|-----------|----------|-----|-----------------|------------|\n")
            for c in fn_challenges:
                files = ", ".join(f"`{p}`" for p in sorted(c["_vuln_files"])) or "_none_"
                w(f"| {c['name']} | {c.get('category','')} | {c.get('cwe','')} "
                  f"| {files} | {c.get('confidence','')} |\n")
        else:
            w("_None_\n")
        w("\n")

        w("## Informational Findings\n\n")
        w(f"These {len(informational)} findings have only informational CWEs "
          f"({', '.join(sorted(informational_cwes))}) and are excluded from scoring.\n\n")
        if informational:
            w("| Rule | File | Line | CWEs |\n|------|------|------|------|\n")
            for f in informational:
                w(f"| `{f['rule_id']}` | `{f['uri']}` | {f['start_line']} "
                  f"| {', '.join(sorted(f['cwes']))} |\n")
        w("\n")

        w("## Exclusion summary\n\n")
        w(f"{len(excluded)} findings excluded by path filters "
          f"(per-pattern counts may overlap):\n\n")
        for pat in exclude_patterns:
            cnt = sum(1 for f in excluded if _path_excluded(f["uri"], [pat]))
            w(f"- `{pat}`: {cnt}\n")

    log.info("Wrote %s", md_path)

    # ── Write HTML ───────────────────────────────────────────────────────────
    if write_html:
        html_path = _write_html(result, resolved_out)
        log.info("Wrote %s", html_path)

    # ── Print one-screen summary ─────────────────────────────────────────────
    print()
    print(f"Tool:                 {tool_name} {tool_version}")
    print(f"SARIF:                {os.path.basename(sarif_path)}")
    print(f"Total findings:       {total}")
    print(f"Excluded (test/etc):  {len(excluded)}")
    print(f"Informational:        {len(informational)}")
    print(f"In-scope:             {len(scored_findings)}")
    print()
    print(f"SAST-detectable challenges: {len(detectable)}")
    print(f"TP: {TP}   FP: {FP}   FN: {FN}")
    print(
        f"Precision: {_fmt_pct(precision)}   "
        f"Recall: {_fmt_pct(recall)}   "
        f"F1: {_fmt_pct(f1)}   "
        f"Youden's J: {_fmt_pct(youden_j)}"
    )
    print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score a SARIF file against the OWASP Juice Shop ground truth."
    )
    parser.add_argument("--sarif", required=True, help="Path to SARIF v2.1.0 file")
    parser.add_argument("--ground-truth", required=True,
                        help="Path to juice-shop-ground-truth.yml")
    parser.add_argument("--out", default="scorecard/",
                        help="Output directory for scorecard.md / scorecard.json")
    parser.add_argument(
        "--exclude-paths",
        default=",".join(DEFAULT_EXCLUDE_PATTERNS),
        help=(
            "Comma-separated path prefixes / globs to exclude entirely "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--html", action="store_true",
        help="Also write a self-contained scorecard.html to the output directory",
    )
    parser.add_argument(
        "--informational-cwes",
        default=",".join(sorted(DEFAULT_INFORMATIONAL_CWES)),
        help=(
            "Comma-separated CWEs to treat as informational and exclude from "
            "precision/recall (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="low",
        help=(
            "Drop findings strictly below this severity before scoring. "
            "Severity is taken from SARIF properties.security-severity / "
            "properties.severity / level (default: %(default)s — no filtering)."
        ),
    )
    args = parser.parse_args()

    exclude = [p.strip() for p in args.exclude_paths.split(",") if p.strip()]
    info_cwes = {c.strip().upper() for c in args.informational_cwes.split(",") if c.strip()}
    # Normalise e.g. "547" -> "CWE-547"
    info_cwes = {c if c.startswith("CWE-") else f"CWE-{c}" for c in info_cwes}

    score(
        sarif_path=args.sarif,
        gt_path=args.ground_truth,
        out_dir=args.out,
        exclude_patterns=exclude,
        informational_cwes=info_cwes,
        write_html=args.html,
        min_severity=args.min_severity,
    )


if __name__ == "__main__":
    main()
