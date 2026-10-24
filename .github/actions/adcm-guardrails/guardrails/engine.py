"""Evaluate one repository snapshot against a golden baseline."""

from __future__ import annotations

import hashlib
from typing import Any

from . import ENGINE_VERSION
from .baseline import SEVERITY_RANK, Baseline
from .checks import CHECKS, FAIL, NOT_EVALUATED, PASS, CheckContext, Outcome, deployed_auth_outcome, deployed_outcome
from .manifest import INVOCATIONS, MAX_TOOLS, TOOL_AUTH, Manifest, ManifestError, https_origin, parse_manifest
from .snapshot import RepoSnapshot

RISK_LEVELS = ("none", "low", "medium", "high")


def fingerprint(repository: str, rule_id: str) -> str:
    return hashlib.sha256(f"{repository.lower()}|{rule_id}".encode("utf-8")).hexdigest()[:16]


def find_manifest(snapshot: RepoSnapshot, baseline: Baseline) -> tuple[Manifest | None, str | None]:
    for path in baseline.settings.manifest_paths:
        if path not in snapshot.path_set:
            continue
        text = snapshot.files.get(path)
        if text is None:
            return None, f"{path} could not be read (binary, oversized or outside the scan budget)"
        try:
            return parse_manifest(path, text), None
        except ManifestError as exc:
            return None, f"{path}: {exc}"
    return None, None


def risk_level(findings: list[dict[str, Any]]) -> str:
    """Security drift drives risk; governance drift is capped one level lower."""
    level = 0
    for finding in findings:
        if finding["status"] != FAIL:
            continue
        rank = SEVERITY_RANK[finding["severity"]]
        if finding["category"] == "governance":
            rank = max(1, rank - 1)
        level = max(level, rank)
    return RISK_LEVELS[level]


def _declared(manifest: Manifest | None) -> dict[str, Any] | None:
    """The parts of the manifest ADCM compares against the deployed inventory."""
    if manifest is None:
        return None
    model = manifest.get("model", "deployment")
    identity = manifest.get("identity", "type")
    return {
        "model": model if isinstance(model, str) else None,
        "identity_type": identity if isinstance(identity, str) else None,
        "invocation": manifest.data.get("invocation") if manifest.data.get("invocation") in INVOCATIONS else None,
        "tools": [
            {
                "name": str(tool.get("name"))[:100],
                "type": str(tool.get("type"))[:40],
                "endpoint": https_origin(tool.get("endpoint")),
                "approval": tool.get("approval") if tool.get("approval") in ("required", "none") else None,
                "write": tool.get("write") is True,
                "auth": tool.get("auth") if tool.get("auth") in TOOL_AUTH else None,
            }
            for tool in manifest.tools[:MAX_TOOLS] if isinstance(tool.get("name"), str)
        ],
        "deployments": manifest.summary()["deployments"],
    }


def _summarize(report: dict[str, Any]) -> dict[str, Any]:
    findings = report["findings"]
    passed = sum(1 for f in findings if f["status"] == PASS)
    failed = [f for f in findings if f["status"] == FAIL]
    evaluated = passed + len(failed)
    report["counts"] = {
        "pass": passed, "fail": len(failed),
        "not_evaluated": sum(1 for f in findings if f["status"] == NOT_EVALUATED),
        "fail_high": sum(1 for f in failed if f["severity"] == "high"),
        "fail_security": sum(1 for f in failed if f["category"] == "security"),
        "fail_governance": sum(1 for f in failed if f["category"] == "governance"),
    }
    report["score"] = round(100 * passed / evaluated) if evaluated else None
    report["risk"] = risk_level(findings)
    return report


def evaluate(
    snapshot: RepoSnapshot,
    baseline: Baseline,
    *,
    deployed: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    manifest, manifest_error = find_manifest(snapshot, baseline)
    ctx = CheckContext(snapshot=snapshot, baseline=baseline, manifest=manifest, manifest_error=manifest_error, deployed=deployed)
    findings: list[dict[str, Any]] = []
    for rule in baseline.rules:
        try:
            outcome = CHECKS[rule.check](ctx, rule)
        except Exception as exc:  # a defective check must not hide the other results
            outcome_status, message, evidence = NOT_EVALUATED, f"Check failed to run ({type(exc).__name__})", []
        else:
            outcome_status, message, evidence = outcome.status, outcome.message, outcome.evidence
        findings.append({
            "rule_id": rule.id, "title": rule.title, "category": rule.category, "severity": rule.severity,
            "check": rule.check, "status": outcome_status, "message": message, "evidence": evidence,
            "rationale": rule.rationale, "remediation": rule.remediation,
            "fingerprint": fingerprint(snapshot.name, rule.id),
        })
    return _summarize({
        "repository": snapshot.name,
        "url": snapshot.url,
        "commit": snapshot.commit,
        "default_branch": snapshot.default_branch,
        "engine_version": ENGINE_VERSION,
        "baseline": {"id": baseline.id, "version": baseline.version},
        "manifest": manifest.summary() if manifest else None,
        "manifest_error": manifest_error,
        "declared": _declared(manifest),
        "branch_rules": snapshot.branch_rules.to_dict() if snapshot.branch_rules else None,
        "findings": findings,
        "coverage_notes": list(snapshot.coverage_notes)[:20],
    })


def apply_deployed(report: dict[str, Any], deployed: list[dict[str, Any]]) -> dict[str, Any]:
    """Re-evaluate declared-vs-deployed rules once the deployed inventory is known."""
    has_manifest = report.get("manifest") is not None and not report.get("manifest_error")
    outcomes = {
        "deployed_drift": deployed_outcome(deployed, has_manifest),
        "deployed_auth": deployed_auth_outcome(deployed, (report.get("declared") or {}).get("invocation")) if has_manifest
        else Outcome(NOT_EVALUATED, "No valid manifest declares deployments", []),
    }
    for finding in report["findings"]:
        outcome = outcomes.get(finding.get("check"))
        if outcome is not None:
            finding.update(status=outcome.status, message=outcome.message, evidence=outcome.evidence)
    report["deployed"] = deployed
    return _summarize(report)


def failing_at_or_above(report: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    floor = SEVERITY_RANK[severity]
    return [f for f in report["findings"] if f["status"] == FAIL and SEVERITY_RANK[f["severity"]] >= floor]
