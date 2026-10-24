"""Command line: evaluate a local checkout against a golden baseline (CI/CD gate).

    python -m guardrails check --path . --baseline agent-baseline.json --fail-on high

Exit codes: 0 compliant at the chosen threshold, 1 drift at/above --fail-on, 2 usage or baseline error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .baseline import SEVERITIES, BaselineError, load_baseline_bytes
from .checks import FAIL
from .engine import evaluate, failing_at_or_above
from .snapshot import snapshot_from_directory

_STATUS_MARK = {"pass": "PASS", "fail": "FAIL", "not_evaluated": "N/A "}


def _escape_annotation(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_text(report: dict[str, Any]) -> str:
    lines = [
        f"ADCM guardrails: {report['repository']} against {report['baseline']['id']} {report['baseline']['version']}",
        f"Score {report['score'] if report['score'] is not None else 'n/a'} | risk {report['risk']} | "
        f"{report['counts']['fail']} failed, {report['counts']['pass']} passed, {report['counts']['not_evaluated']} not evaluated",
        "",
    ]
    for finding in sorted(report["findings"], key=lambda f: (f["status"] != FAIL, f["rule_id"])):
        lines.append(f"[{_STATUS_MARK[finding['status']]}] {finding['rule_id']} {finding['severity']:<6} {finding['category']:<10} {finding['title']}: {finding['message']}")
        for item in finding["evidence"][:5]:
            lines.append(f"         - {item}")
        if finding["status"] == FAIL:
            lines.append(f"         fix: {finding['remediation']}")
    for note in report["coverage_notes"]:
        lines.append(f"note: {note}")
    return "\n".join(lines)


def render_github(report: dict[str, Any], fail_on: str) -> str:
    gating = {f["rule_id"] for f in failing_at_or_above(report, fail_on)}
    lines = []
    for finding in report["findings"]:
        if finding["status"] != FAIL:
            continue
        level = "error" if finding["rule_id"] in gating else "warning"
        title = _escape_annotation(f"{finding['rule_id']} {finding['title']} ({finding['severity']} {finding['category']})")
        body = _escape_annotation(f"{finding['message']}. Fix: {finding['remediation']}")
        lines.append(f"::{level} title={title}::{body}")
    return "\n".join(lines)


def render_markdown(report: dict[str, Any], fail_on: str) -> str:
    rows = [
        f"### ADCM guardrails: {report['baseline']['id']} {report['baseline']['version']}",
        "",
        f"**Score {report['score'] if report['score'] is not None else 'n/a'}**, risk **{report['risk']}**. "
        f"PRs fail on **{fail_on}** severity drift or higher.",
        "",
        "| Status | Rule | Severity | Category | Result |",
        "|---|---|---|---|---|",
    ]
    for finding in sorted(report["findings"], key=lambda f: (f["status"] != FAIL, f["rule_id"])):
        message = finding["message"].replace("|", "\\|")
        rows.append(f"| {finding['status']} | {finding['rule_id']} {finding['title']} | {finding['severity']} | {finding['category']} | {message} |")
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardrails", description="ADCM golden-baseline drift check")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Evaluate a repository checkout")
    check.add_argument("--path", default=".", help="Repository root (default: current directory)")
    check.add_argument("--baseline", required=True, help="Path to agent-baseline.json")
    check.add_argument("--fail-on", choices=SEVERITIES, default="high", help="Lowest severity that fails the run")
    check.add_argument("--format", choices=("text", "json", "github"), default="text")
    check.add_argument("--output", help="Also write the JSON report to this file")
    check.add_argument("--name", help="Repository name to report (default: GITHUB_REPOSITORY or folder name)")
    args = parser.parse_args(argv)

    try:
        baseline = load_baseline_bytes(Path(args.baseline).read_bytes())
    except (OSError, BaselineError) as exc:
        print(f"guardrails: cannot load baseline: {exc}", file=sys.stderr)
        return 2
    try:
        snapshot = snapshot_from_directory(
            args.path, baseline.settings.manifest_paths, name=args.name or os.environ.get("GITHUB_REPOSITORY"),
        )
    except ValueError as exc:
        print(f"guardrails: {exc}", file=sys.stderr)
        return 2
    snapshot.commit = os.environ.get("GITHUB_SHA") or None
    report = evaluate(snapshot, baseline)
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "github":
        print(render_text(report))
        annotations = render_github(report, args.fail_on)
        if annotations:
            print(annotations)
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write(render_markdown(report, args.fail_on))
    else:
        print(render_text(report))
    return 1 if failing_at_or_above(report, args.fail_on) else 0
