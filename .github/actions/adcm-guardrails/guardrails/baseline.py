"""Versioned golden baseline (policy pack) loading and strict validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "adcm.guardrails.baseline/v1"
MAX_BASELINE_BYTES = 256 * 1024
MAX_RULES = 200
CATEGORIES = ("security", "governance")
SEVERITIES = ("high", "medium", "low")
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

_SEMVER = re.compile(r"(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})")
_RULE_ID = re.compile(r"GR-[A-Z]{2,8}-\d{3}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_PACKAGE = re.compile(r"(@[A-Za-z0-9][A-Za-z0-9._-]{0,49}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_PATH = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./-]{0,199}")
_ACTION = re.compile(r"(\*/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+")
_HOST = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+")
_VERSION = re.compile(r"\d{1,6}(\.\d{1,6}){0,3}((a|b|rc)\d{1,9})?")
_CHECK_NAME = re.compile(r"[A-Za-z0-9 _./:()-]{1,100}")


class BaselineError(ValueError):
    """The baseline document is malformed; it must not be partially applied."""


def _strings(value: Any, name: str, pattern: re.Pattern[str] | None = None, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty) or len(value) > 100:
        raise BaselineError(f"{name} must be a {'possibly empty ' if allow_empty else 'non-empty '}list of at most 100 strings")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item or (pattern and not pattern.fullmatch(item)):
            raise BaselineError(f"{name} contains an invalid value")
        if item in seen:
            raise BaselineError(f"{name} contains a duplicate value")
        seen.add(item)
    return list(value)


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise BaselineError(f"{name} must be true or false")
    return value


def _approvals(value: Any, name: str) -> int:
    if type(value) is not int or not 0 <= value <= 10:
        raise BaselineError(f"{name} must be an integer 0-10")
    return value


def _identity_type(value: Any, name: str) -> str:
    if value not in ("entra_agent_id", "managed_identity"):
        raise BaselineError(f"{name} must be entra_agent_id or managed_identity")
    return value


def _directory(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _PATH.fullmatch(value) or not value.endswith("/") or ".." in value:
        raise BaselineError(f"{name} must be a relative directory path ending with /")
    return value


def _regexes(value: Any, name: str) -> list[str]:
    for pattern in _strings(value, name):
        _compile(pattern, name)
    return value


def _packages(value: Any, name: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 50:
        raise BaselineError(f"{name} must be a non-empty list")
    rows = []
    for item in value:
        if not isinstance(item, dict) or set(item) - {"name", "min_version"} or "name" not in item:
            raise BaselineError(f"{name} entries need name and optional min_version only")
        if not isinstance(item["name"], str) or not _PACKAGE.fullmatch(item["name"]):
            raise BaselineError(f"{name} has an invalid package name")
        if "min_version" in item and (not isinstance(item["min_version"], str) or not _VERSION.fullmatch(item["min_version"])):
            raise BaselineError(f"{name} has an invalid min_version")
        rows.append(dict(item))
    return rows


# check type -> {param: validator}; unknown params are rejected.
_PARAM_SPECS: dict[str, dict[str, Any]] = {
    "file_exists": {"any_of": lambda v, n: _strings(v, n, _PATH)},
    "workflow_uses_action": {"any_of": lambda v, n: _strings(v, n, _ACTION)},
    "workflow_actions_pinned": {},
    "workflow_permissions": {},
    "workflow_no_long_lived_secrets": {"secret_names": lambda v, n: _strings(v, n, re.compile(r"[A-Z][A-Z0-9_]{1,99}"))},
    "lockfile_present": {},
    "branch_rules": {
        "min_approvals": _approvals,
        "code_owner_review": _bool,
        "required_checks": lambda v, n: _strings(v, n, _CHECK_NAME, allow_empty=True),
        "block_force_push": _bool,
        "block_deletion": _bool,
        "signed_commits": _bool,
    },
    "head_commit_signed": {},
    "dependency_required": {"any_of": _packages},
    "dependency_forbidden": {"names": lambda v, n: _strings(v, n, _PACKAGE)},
    "dependency_any": {"any_of": lambda v, n: _strings(v, n, _PACKAGE)},
    "secrets_absent": {},
    "pattern_absent": {
        "patterns": _regexes,
        "extensions": lambda v, n: _strings(v, n, re.compile(r"\.[a-z0-9]{1,10}")),
    },
    "manifest_valid": {},
    "manifest_identity": {"type": _identity_type},
    "manifest_models": {},
    "manifest_content_safety": {},
    "manifest_tools": {},
    "manifest_baseline_pin": {},
    "evals_in_ci": {"path": _directory},
    "deployed_drift": {},
}
CHECK_TYPES = frozenset(_PARAM_SPECS)
_REQUIRED_PARAMS = {
    "file_exists": {"any_of"}, "workflow_uses_action": {"any_of"}, "dependency_required": {"any_of"},
    "dependency_forbidden": {"names"}, "dependency_any": {"any_of"}, "pattern_absent": {"patterns", "extensions"},
    "manifest_identity": {"type"}, "evals_in_ci": {"path"},
}


def _compile(pattern: str, name: str) -> re.Pattern[str]:
    if len(pattern) > 200:
        raise BaselineError(f"{name} pattern is too long")
    try:
        return re.compile(pattern)
    except re.error:
        raise BaselineError(f"{name} contains an invalid regular expression") from None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    check: str
    params: dict[str, Any]
    rationale: str
    remediation: str


@dataclass(frozen=True)
class Settings:
    manifest_paths: tuple[str, ...]
    approved_models: tuple[str, ...]
    data_classifications: tuple[str, ...]
    approved_tool_types: tuple[str, ...]
    approved_mcp_hosts: tuple[str, ...]


@dataclass(frozen=True)
class Baseline:
    id: str
    version: str
    released: str
    description: str
    derived_from: str
    settings: Settings
    rules: tuple[Rule, ...] = field(default_factory=tuple)

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        return version_tuple(self.version)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "version": self.version, "released": self.released,
            "description": self.description, "derived_from": self.derived_from, "rule_count": len(self.rules),
        }


def version_tuple(value: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(value or "")
    if not match:
        raise BaselineError("version must be MAJOR.MINOR.PATCH")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _text(data: dict[str, Any], key: str, cap: int, *, required: bool = True) -> str:
    value = data.get(key, "" if not required else None)
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > cap:
        raise BaselineError(f"{key} must be a {'non-empty ' if required else ''}string of at most {cap} characters")
    return value.strip()


def _settings(value: Any) -> Settings:
    keys = {"manifest_paths", "approved_models", "data_classifications", "approved_tool_types", "approved_mcp_hosts"}
    if not isinstance(value, dict) or set(value) != keys:
        raise BaselineError("settings must contain exactly: " + ", ".join(sorted(keys)))
    return Settings(
        manifest_paths=tuple(_strings(value["manifest_paths"], "settings.manifest_paths", _PATH)),
        approved_models=tuple(_strings(value["approved_models"], "settings.approved_models", re.compile(r"[a-z0-9][a-z0-9._-]{0,63}"))),
        data_classifications=tuple(_strings(value["data_classifications"], "settings.data_classifications", re.compile(r"[a-z_]{1,40}"))),
        approved_tool_types=tuple(_strings(value["approved_tool_types"], "settings.approved_tool_types", re.compile(r"[a-z_]{1,40}"))),
        approved_mcp_hosts=tuple(_strings(value["approved_mcp_hosts"], "settings.approved_mcp_hosts", _HOST)),
    )


def _rule(value: Any) -> Rule:
    keys = {"id", "title", "category", "severity", "check", "params", "rationale", "remediation"}
    if not isinstance(value, dict) or set(value) - keys or keys - set(value) - {"params"}:
        raise BaselineError("rule fields must be exactly: " + ", ".join(sorted(keys)) + " (params optional)")
    rule_id = value["id"]
    if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
        raise BaselineError("rule id must look like GR-SEC-001")
    if value["category"] not in CATEGORIES:
        raise BaselineError(f"rule {rule_id}: category must be security or governance")
    if value["severity"] not in SEVERITIES:
        raise BaselineError(f"rule {rule_id}: severity must be high, medium or low")
    check = value["check"]
    if check not in CHECK_TYPES:
        raise BaselineError(f"rule {rule_id}: unknown check type")
    params = value.get("params", {})
    if not isinstance(params, dict):
        raise BaselineError(f"rule {rule_id}: params must be an object")
    spec = _PARAM_SPECS[check]
    unknown = set(params) - set(spec)
    if unknown:
        raise BaselineError(f"rule {rule_id}: unknown params {sorted(unknown)}")
    missing = _REQUIRED_PARAMS.get(check, set()) - set(params)
    if missing:
        raise BaselineError(f"rule {rule_id}: missing params {sorted(missing)}")
    for key, item in params.items():
        spec[key](item, f"rule {rule_id} params.{key}")
    return Rule(
        id=rule_id, title=_text(value, "title", 120), category=value["category"], severity=value["severity"],
        check=check, params=json.loads(json.dumps(params)), rationale=_text(value, "rationale", 600),
        remediation=_text(value, "remediation", 600),
    )


def parse_baseline(data: Any) -> Baseline:
    keys = {"schema", "id", "version", "released", "description", "derived_from", "settings", "rules"}
    if not isinstance(data, dict):
        raise BaselineError("baseline must be a JSON object")
    if set(data) != keys:
        raise BaselineError("baseline fields must be exactly: " + ", ".join(sorted(keys)))
    if data["schema"] != SCHEMA:
        raise BaselineError(f"schema must be {SCHEMA}")
    if not isinstance(data["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", data["id"]):
        raise BaselineError("id must be lower-kebab-case")
    version_tuple(data["version"])
    if not isinstance(data["released"], str) or not _DATE.fullmatch(data["released"]):
        raise BaselineError("released must be YYYY-MM-DD")
    rules_raw = data["rules"]
    if not isinstance(rules_raw, list) or not rules_raw or len(rules_raw) > MAX_RULES:
        raise BaselineError(f"rules must contain 1-{MAX_RULES} entries")
    rules = tuple(_rule(item) for item in rules_raw)
    ids = [rule.id for rule in rules]
    if len(set(ids)) != len(ids):
        raise BaselineError("rule ids must be unique")
    return Baseline(
        id=data["id"], version=data["version"], released=data["released"],
        description=_text(data, "description", 600), derived_from=_text(data, "derived_from", 300),
        settings=_settings(data["settings"]), rules=rules,
    )


def load_baseline_bytes(raw: bytes) -> Baseline:
    if not isinstance(raw, (bytes, bytearray)) or not raw.strip():
        raise BaselineError("baseline document is empty")
    if len(raw) > MAX_BASELINE_BYTES:
        raise BaselineError("baseline document is too large")
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise BaselineError("baseline document is not UTF-8") from None

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in pairs]
        if len(set(keys)) != len(keys):
            raise BaselineError("baseline document has duplicate keys")
        return dict(pairs)

    try:
        data = json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError:
        raise BaselineError("baseline document is not valid JSON") from None
    return parse_baseline(data)
