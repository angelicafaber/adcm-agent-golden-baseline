"""Deterministic baseline checks. Each check returns pass, fail or not_evaluated with evidence.

Evidence never contains matched secret values: only paths, line numbers and labels.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Callable

import yaml

from .baseline import Baseline, Rule, version_tuple
from .manifest import Manifest, https_origin
from .snapshot import LOCK_FILES, SECRET_FILE_NAMES, SECRET_FILE_SUFFIXES, RepoSnapshot, is_workflow

PASS, FAIL, NOT_EVALUATED = "pass", "fail", "not_evaluated"
MAX_EVIDENCE = 10

_USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
_SHA = re.compile(r"[0-9a-f]{40}")
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")
_PRE = {"a": 0, "b": 1, "rc": 2}
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("storage account key", re.compile(r"AccountKey=[A-Za-z0-9+/]{40,}={0,2}")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}")),
    ("hard-coded key or password", re.compile(
        r"(?i)\b[\w-]*(api[_-]?key|secret|password|passwd|access[_-]?key)\b\s*[:=]\s*[\"'][A-Za-z0-9_+/=.-]{20,}[\"']")),
)


@dataclass
class Outcome:
    status: str
    message: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class CheckContext:
    snapshot: RepoSnapshot
    baseline: Baseline
    manifest: Manifest | None
    manifest_error: str | None
    deployed: list[dict[str, Any]] | None = None
    _deps: dict[str, list[str]] | None = None

    def workflows(self) -> dict[str, str]:
        return {p: t for p, t in self.snapshot.files.items() if is_workflow(p)}

    def dependencies(self) -> dict[str, list[str]]:
        if self._deps is None:
            self._deps = parse_dependencies(self.snapshot.files)
        return self._deps


def _cap(items: list[str]) -> list[str]:
    out = [item[:200] for item in items[:MAX_EVIDENCE]]
    if len(items) > MAX_EVIDENCE:
        out.append(f"... and {len(items) - MAX_EVIDENCE} more")
    return out


def normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_dependencies(files: dict[str, str]) -> dict[str, list[str]]:
    """Map normalised package name -> list of version specifiers across manifests."""
    deps: dict[str, list[str]] = {}

    def add(name: str, spec: str) -> None:
        deps.setdefault(normalize_package(name), []).append(spec.strip().rstrip("\\").strip())

    for path, text in files.items():
        name = PurePosixPath(path).name
        try:
            if name.startswith("requirements") and name.endswith(".txt"):
                for line in text.splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line or line.startswith(("-", "git+", "http")):
                        continue
                    match = _REQ_LINE.match(line)
                    if match:
                        add(match.group(1), match.group(3).split(";")[0].split("--hash")[0])
            elif name == "pyproject.toml":
                data = tomllib.loads(text)
                project = data.get("project") or {}
                groups = [project.get("dependencies") or []]
                groups.extend((project.get("optional-dependencies") or {}).values())
                for group in groups:
                    for item in group if isinstance(group, list) else []:
                        match = _REQ_LINE.match(item) if isinstance(item, str) else None
                        if match:
                            add(match.group(1), match.group(3).split(";")[0])
                poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
                for dep, spec in poetry.items() if isinstance(poetry, dict) else []:
                    if dep.lower() != "python":
                        add(dep, spec if isinstance(spec, str) else "")
            elif name == "package.json":
                data = json.loads(text)
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    values = data.get(key) or {}
                    for dep, spec in values.items() if isinstance(values, dict) else []:
                        add(dep, spec if isinstance(spec, str) else "")
        except (ValueError, TypeError, AttributeError, tomllib.TOMLDecodeError):
            continue
    return deps


def parse_version(value: str) -> tuple[tuple[int, ...], tuple[int, int]] | None:
    match = re.fullmatch(r"v?(\d{1,6}(?:\.\d{1,6}){0,3})(?:(a|b|rc)(\d{1,9}))?(?:\.post\d+|\.dev\d+)?", value.strip())
    if not match:
        return None
    release = tuple(int(part) for part in match.group(1).split("."))
    release = release + (0,) * (4 - len(release))
    pre = (_PRE[match.group(2)], int(match.group(3))) if match.group(2) else (3, 0)
    return release, pre


def minimum_version(specs: list[str]) -> str | None:
    """Lowest version a set of specifiers guarantees (from >=, ==, ~=, ^ or bare pins)."""
    best: tuple[Any, str] | None = None
    for spec in specs:
        for clause in spec.split(","):
            clause = clause.strip()
            match = re.match(r"^(>=|==|~=|\^|~)?\s*v?([0-9][0-9A-Za-z.]*)$", clause)
            if not match or (match.group(1) is None and clause[:1] not in "0123456789"):
                continue
            parsed = parse_version(match.group(2))
            if parsed and (best is None or parsed > best[0]):
                best = (parsed, match.group(2))
    return best[1] if best else None


def _line_hits(text: str, pattern: re.Pattern[str]) -> list[int]:
    return [number for number, line in enumerate(text.splitlines(), 1) if pattern.search(line)]


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    for item in allowed:
        if item.startswith("*.") and host.endswith(item[1:]) and host != item[2:]:
            return True
        if host == item:
            return True
    return False


# ---------------------------------------------------------------------------
# Repository checks
# ---------------------------------------------------------------------------

def check_file_exists(ctx: CheckContext, rule: Rule) -> Outcome:
    options = rule.params["any_of"]
    found = [path for path in options if path in ctx.snapshot.path_set]
    if found:
        return Outcome(PASS, f"Found {found[0]}", [found[0]])
    return Outcome(FAIL, "Missing: expected one of " + ", ".join(options), [])


def _uses(ctx: CheckContext) -> list[tuple[str, int, str]]:
    rows = []
    for path, text in sorted(ctx.workflows().items()):
        for number, line in enumerate(text.splitlines(), 1):
            match = _USES.match(line)
            if match:
                rows.append((path, number, match.group(1)))
    return rows


def check_workflow_uses_action(ctx: CheckContext, rule: Rule) -> Outcome:
    if not ctx.workflows():
        return Outcome(FAIL, "No GitHub Actions workflows found", [])
    wanted = [item.lower() for item in rule.params["any_of"]]
    for path, number, ref in _uses(ctx):
        action = ref.split("@", 1)[0].lower()
        if any(
            action.endswith(item[1:]) if item.startswith("*/") else (action == item or action.startswith(item + "/"))
            for item in wanted
        ):
            return Outcome(PASS, f"{ref.split('@', 1)[0]} runs in {path}", [f"{path}:{number}"])
    return Outcome(FAIL, "No workflow uses " + " or ".join(rule.params["any_of"]), sorted(ctx.workflows())[:MAX_EVIDENCE])


def check_workflow_actions_pinned(ctx: CheckContext, rule: Rule) -> Outcome:
    uses = _uses(ctx)
    if not uses:
        return Outcome(NOT_EVALUATED, "No workflow actions to check", [])
    unpinned = [
        f"{path}:{number} {ref}" for path, number, ref in uses
        if not ref.startswith(("./", "docker://")) and not _SHA.fullmatch(ref.rsplit("@", 1)[-1] if "@" in ref else "")
    ]
    if unpinned:
        return Outcome(FAIL, f"{len(unpinned)} action reference(s) are not pinned to a full commit SHA", _cap(unpinned))
    return Outcome(PASS, f"All {len(uses)} action references are pinned to commit SHAs", [])


def check_workflow_permissions(ctx: CheckContext, rule: Rule) -> Outcome:
    workflows = ctx.workflows()
    if not workflows:
        return Outcome(NOT_EVALUATED, "No workflows to check", [])
    problems = []
    for path, text in sorted(workflows.items()):
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            problems.append(f"{path}: not valid YAML")
            continue
        if not isinstance(data, dict) or "permissions" not in data:
            problems.append(f"{path}: no top-level permissions block (defaults may grant write)")
            continue
        if data["permissions"] == "write-all":
            problems.append(f"{path}: permissions: write-all")
        jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}
        for job, body in jobs.items():
            if isinstance(body, dict) and body.get("permissions") == "write-all":
                problems.append(f"{path}: job {job} uses permissions: write-all")
    if problems:
        return Outcome(FAIL, "Workflow token permissions are not least-privilege", _cap(problems))
    return Outcome(PASS, f"{len(workflows)} workflow(s) declare explicit token permissions", [])


def check_workflow_no_long_lived_secrets(ctx: CheckContext, rule: Rule) -> Outcome:
    names = rule.params.get("secret_names") or []
    pattern = re.compile(r"secrets\.(" + "|".join(map(re.escape, names)) + r")\b" if names else r"(?!)")
    key_pattern = re.compile(r"^\s*(client-secret|creds)\s*:", re.MULTILINE)
    hits = []
    for path, text in sorted(ctx.workflows().items()):
        hits.extend(f"{path}:{n}" for n in _line_hits(text, pattern))
        hits.extend(f"{path}:{n} (inline credential input)" for n in _line_hits(text, key_pattern))
    if hits:
        return Outcome(FAIL, "Workflows use long-lived cloud credentials instead of OIDC federation", _cap(hits))
    if not ctx.workflows():
        return Outcome(NOT_EVALUATED, "No workflows to check", [])
    return Outcome(PASS, "No long-lived cloud credentials referenced in workflows", [])


def check_lockfile_present(ctx: CheckContext, rule: Rule) -> Outcome:
    names = {PurePosixPath(path).name for path in ctx.snapshot.paths}
    files = ctx.snapshot.files
    missing = []
    has_python = bool(names & {"requirements.txt", "pyproject.toml"})
    has_node = "package.json" in names
    if not has_python and not has_node:
        return Outcome(NOT_EVALUATED, "No Python or Node dependency manifest", [])
    if has_python:
        hashed = any("--hash=" in text for path, text in files.items() if PurePosixPath(path).name.startswith("requirements"))
        if not (names & {"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.lock"}) and not hashed:
            missing.append("Python: add uv.lock/poetry.lock or hash-pinned requirements")
    if has_node and not (names & {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}):
        missing.append("Node: add package-lock.json, pnpm-lock.yaml or yarn.lock")
    if missing:
        return Outcome(FAIL, "Dependencies are not locked", missing)
    return Outcome(PASS, "Dependency lockfile present", sorted(names & LOCK_FILES)[:3])


def check_branch_rules(ctx: CheckContext, rule: Rule) -> Outcome:
    rules = ctx.snapshot.branch_rules
    if rules is None:
        return Outcome(NOT_EVALUATED, "Branch rules are not visible from a local checkout; ADCM evaluates them through the GitHub App", [])
    branch = ctx.snapshot.default_branch or "default branch"
    if rules.source == "none":
        return Outcome(FAIL, f"{branch} has no branch protection or rulesets", [])
    params = rule.params
    violations: list[str] = []
    unknown: list[str] = []

    def expect(flag: str, actual: bool | None, label: str) -> None:
        if params.get(flag):
            if actual is None:
                unknown.append(label)
            elif not actual:
                violations.append(f"{label} is not enforced")

    if "min_approvals" in params:
        if rules.min_approvals is None:
            unknown.append("required approvals")
        elif rules.min_approvals < params["min_approvals"]:
            violations.append(f"requires {rules.min_approvals} approval(s); baseline needs {params['min_approvals']}")
    expect("code_owner_review", rules.code_owner_review, "code owner review")
    expect("block_force_push", rules.block_force_push, "force-push block")
    expect("block_deletion", rules.block_deletion, "deletion block")
    expect("signed_commits", rules.signed_commits, "signed commits")
    for check in params.get("required_checks") or []:
        if check not in rules.required_checks:
            violations.append(f"required status check '{check}' is not configured")
    if violations:
        return Outcome(FAIL, f"{branch} rules drift from the baseline ({rules.source})", _cap(violations + [f"not visible: {u}" for u in unknown]))
    if unknown:
        return Outcome(NOT_EVALUATED, f"Classic protection on {branch}; some settings need Administration read. Prefer rulesets.", _cap(unknown))
    return Outcome(PASS, f"{branch} rules match the baseline ({rules.source})", [])


def check_head_commit_signed(ctx: CheckContext, rule: Rule) -> Outcome:
    if ctx.snapshot.head_signed is None:
        return Outcome(NOT_EVALUATED, "Commit signature verification is evaluated through the GitHub API", [])
    if ctx.snapshot.head_signed:
        return Outcome(PASS, "Head commit signature is verified by GitHub", [])
    return Outcome(FAIL, "Head commit on the default branch is not signed/verified", [ctx.snapshot.commit or ""])


def check_dependency_required(ctx: CheckContext, rule: Rule) -> Outcome:
    deps = ctx.dependencies()
    problems = []
    for item in rule.params["any_of"]:
        name = normalize_package(item["name"])
        if name not in deps:
            continue
        wanted = item.get("min_version")
        if not wanted:
            return Outcome(PASS, f"Uses {item['name']}", [])
        floor = minimum_version(deps[name])
        if floor is None:
            problems.append(f"{item['name']} has no minimum version (needs >= {wanted})")
        elif parse_version(floor) < parse_version(wanted):  # type: ignore[operator]
            problems.append(f"{item['name']} {floor} is below the approved minimum {wanted}")
        else:
            return Outcome(PASS, f"Uses {item['name']} >= {floor}", [])
    if problems:
        return Outcome(FAIL, "Approved SDK is below the minimum version", problems)
    options = ", ".join(f"{i['name']}>={i['min_version']}" if i.get("min_version") else i["name"] for i in rule.params["any_of"])
    return Outcome(FAIL, "No approved agent SDK found. Use one of: " + options, [])


def check_dependency_forbidden(ctx: CheckContext, rule: Rule) -> Outcome:
    deps = ctx.dependencies()
    found = [name for name in rule.params["names"] if normalize_package(name) in deps]
    if found:
        return Outcome(FAIL, "Forbidden dependency present: " + ", ".join(found), [f"{n} {' '.join(deps[normalize_package(n)])}".strip() for n in found])
    return Outcome(PASS, "No forbidden dependencies", [])


def check_dependency_any(ctx: CheckContext, rule: Rule) -> Outcome:
    deps = ctx.dependencies()
    found = [name for name in rule.params["any_of"] if normalize_package(name) in deps]
    if found:
        return Outcome(PASS, "Uses " + ", ".join(found), [])
    return Outcome(FAIL, "None of the required packages are declared: " + ", ".join(rule.params["any_of"]), [])


def check_secrets_absent(ctx: CheckContext, rule: Rule) -> Outcome:
    hits = [
        f"{path} (credential file committed)" for path in ctx.snapshot.paths
        if PurePosixPath(path).name in SECRET_FILE_NAMES or path.endswith(SECRET_FILE_SUFFIXES)
    ]
    for path, text in sorted(ctx.snapshot.files.items()):
        for label, pattern in SECRET_PATTERNS:
            hits.extend(f"{path}:{n} ({label})" for n in _line_hits(text, pattern))
    if hits:
        return Outcome(FAIL, f"{len(hits)} possible committed secret(s); values are not shown", _cap(hits))
    return Outcome(PASS, f"No secrets found in {len(ctx.snapshot.files)} scanned file(s)", [])


def check_pattern_absent(ctx: CheckContext, rule: Rule) -> Outcome:
    patterns = [re.compile(p) for p in rule.params["patterns"]]
    extensions = tuple(rule.params["extensions"])
    hits = []
    scanned = 0
    for path, text in sorted(ctx.snapshot.files.items()):
        if not path.endswith(extensions):
            continue
        scanned += 1
        for pattern in patterns:
            hits.extend(f"{path}:{n}" for n in _line_hits(text, pattern))
    if hits:
        return Outcome(FAIL, "Disallowed pattern found", _cap(sorted(set(hits))))
    if not scanned:
        return Outcome(NOT_EVALUATED, "No matching source files to scan", [])
    return Outcome(PASS, f"Not found in {scanned} source file(s)", [])


def check_evals_in_ci(ctx: CheckContext, rule: Rule) -> Outcome:
    prefix = rule.params["path"]
    files = [path for path in ctx.snapshot.paths if path.startswith(prefix)]
    if not files:
        return Outcome(FAIL, f"No evaluation datasets or configs under {prefix}", [])
    runners = [path for path, text in ctx.workflows().items() if prefix.rstrip("/") in text]
    if not runners:
        return Outcome(FAIL, f"{prefix} exists but no workflow runs the evaluations", files[:3])
    return Outcome(PASS, f"{len(files)} evaluation file(s), run by {runners[0]}", [runners[0]])


# ---------------------------------------------------------------------------
# Manifest checks
# ---------------------------------------------------------------------------

def _manifest_required(ctx: CheckContext) -> Outcome | None:
    if ctx.manifest_error:
        return Outcome(FAIL, f"Agent manifest is unreadable: {ctx.manifest_error}", [])
    if ctx.manifest is None:
        paths = " or ".join(ctx.baseline.settings.manifest_paths)
        return Outcome(FAIL, f"No agent manifest ({paths}); this control cannot be proven", [])
    return None


def check_manifest_valid(ctx: CheckContext, rule: Rule) -> Outcome:
    missing = _manifest_required(ctx)
    if missing:
        return missing
    assert ctx.manifest is not None
    problems = list(ctx.manifest.problems)
    classification = ctx.manifest.data.get("data_classification")
    allowed = ctx.baseline.settings.data_classifications
    if isinstance(classification, str) and classification and classification not in allowed:
        problems.append(f"data_classification '{classification[:40]}' is not one of {', '.join(allowed)}")
    if problems:
        return Outcome(FAIL, "Agent manifest is incomplete or invalid", _cap(problems))
    return Outcome(PASS, f"{ctx.manifest.path} declares owner, sponsor and data classification", [ctx.manifest.path])


def check_manifest_identity(ctx: CheckContext, rule: Rule) -> Outcome:
    missing = _manifest_required(ctx)
    if missing:
        return missing
    assert ctx.manifest is not None
    wanted = rule.params["type"]
    actual = ctx.manifest.get("identity", "type")
    if actual != wanted:
        return Outcome(FAIL, f"Identity type is '{str(actual)[:40]}'; baseline requires {wanted}", [ctx.manifest.path])
    if wanted == "entra_agent_id" and not isinstance(ctx.manifest.get("identity", "blueprint_id"), str):
        return Outcome(FAIL, "Entra Agent ID declared without an agent identity blueprint_id", [ctx.manifest.path])
    return Outcome(PASS, f"Runs as {wanted}", [ctx.manifest.path])


def check_manifest_models(ctx: CheckContext, rule: Rule) -> Outcome:
    missing = _manifest_required(ctx)
    if missing:
        return missing
    assert ctx.manifest is not None
    model = ctx.manifest.get("model", "deployment")
    approved = ctx.baseline.settings.approved_models
    if not isinstance(model, str) or model.lower() not in approved:
        return Outcome(FAIL, f"Model '{str(model)[:60]}' is not on the approved list ({', '.join(approved)})", [ctx.manifest.path])
    return Outcome(PASS, f"Model {model} is approved", [])


def check_manifest_content_safety(ctx: CheckContext, rule: Rule) -> Outcome:
    missing = _manifest_required(ctx)
    if missing:
        return missing
    assert ctx.manifest is not None
    enabled = ctx.manifest.get("model", "content_safety", "enabled")
    policy = ctx.manifest.get("model", "content_safety", "rai_policy")
    if enabled is not True:
        return Outcome(FAIL, "Content safety filtering is not enabled for the model", [ctx.manifest.path])
    if isinstance(policy, str) and policy.strip().lower() in {"", "none", "off", "disabled"}:
        return Outcome(FAIL, "Content safety policy is disabled", [ctx.manifest.path])
    return Outcome(PASS, f"Content safety enabled ({policy or 'default policy'})", [])


def check_manifest_tools(ctx: CheckContext, rule: Rule) -> Outcome:
    missing = _manifest_required(ctx)
    if missing:
        return missing
    assert ctx.manifest is not None
    settings = ctx.baseline.settings
    problems = []
    for tool in ctx.manifest.tools:
        name = str(tool.get("name"))[:60]
        kind = tool.get("type")
        if kind not in settings.approved_tool_types:
            problems.append(f"{name}: tool type '{str(kind)[:30]}' is not approved")
        if kind == "mcp":
            origin = https_origin(tool.get("endpoint"))
            host = origin[len("https://"):] if origin else None
            if not host or not _host_allowed(host, settings.approved_mcp_hosts):
                problems.append(f"{name}: MCP server host '{host or 'missing'}' is not on the allow-list")
        if tool.get("write") is True and tool.get("approval") != "required":
            problems.append(f"{name}: write-capable tool without human approval")
    if problems:
        return Outcome(FAIL, "Tool policy violations", _cap(problems))
    return Outcome(PASS, f"{len(ctx.manifest.tools)} tool(s) comply with the allow-list and approval policy", [])


def check_manifest_baseline_pin(ctx: CheckContext, rule: Rule) -> Outcome:
    missing = _manifest_required(ctx)
    if missing:
        return missing
    assert ctx.manifest is not None
    pinned = ctx.manifest.data.get("baseline_version")
    try:
        pinned_tuple = version_tuple(pinned) if isinstance(pinned, str) else None
    except ValueError:
        pinned_tuple = None
    if pinned_tuple is None:
        return Outcome(FAIL, "Manifest does not pin a baseline version", [ctx.manifest.path])
    current = ctx.baseline.version_tuple
    if pinned_tuple < current:
        return Outcome(FAIL, f"Pinned to baseline {pinned}; current is {ctx.baseline.version}", [ctx.manifest.path])
    if pinned_tuple > current:
        return Outcome(FAIL, f"Pinned to baseline {pinned}, which is newer than the published {ctx.baseline.version}", [ctx.manifest.path])
    return Outcome(PASS, f"Pinned to current baseline {pinned}", [])


def deployed_outcome(deployed: list[dict[str, Any]] | None, has_manifest: bool) -> Outcome:
    """Outcome for declared-vs-deployed drift; shared by the check and ADCM's post-inventory pass."""
    if deployed is None:
        return Outcome(NOT_EVALUATED, "Declared-vs-deployed drift is evaluated by ADCM against the discovered inventory", [])
    if not has_manifest:
        return Outcome(NOT_EVALUATED, "No valid manifest declares deployments", [])
    if not deployed:
        return Outcome(NOT_EVALUATED, "Manifest declares no deployments", [])
    drift = [item for item in deployed if item.get("status") == "drift"]
    matched = [item for item in deployed if item.get("status") == "match"]
    if drift:
        evidence = [f"{item['deployment']}: {d}" for item in drift for d in item.get("differences") or []]
        return Outcome(FAIL, f"{len(drift)} deployment(s) differ from the declared configuration", _cap(evidence))
    if matched:
        return Outcome(PASS, f"{len(matched)} deployment(s) match the declared configuration", [i["deployment"] for i in matched][:MAX_EVIDENCE])
    return Outcome(NOT_EVALUATED, "Declared deployments were not found in the latest inventory", [i["deployment"] for i in deployed][:MAX_EVIDENCE])


def check_deployed_drift(ctx: CheckContext, rule: Rule) -> Outcome:
    return deployed_outcome(ctx.deployed, ctx.manifest is not None and not ctx.manifest_error)


CHECKS: dict[str, Callable[[CheckContext, Rule], Outcome]] = {
    "file_exists": check_file_exists,
    "workflow_uses_action": check_workflow_uses_action,
    "workflow_actions_pinned": check_workflow_actions_pinned,
    "workflow_permissions": check_workflow_permissions,
    "workflow_no_long_lived_secrets": check_workflow_no_long_lived_secrets,
    "lockfile_present": check_lockfile_present,
    "branch_rules": check_branch_rules,
    "head_commit_signed": check_head_commit_signed,
    "dependency_required": check_dependency_required,
    "dependency_forbidden": check_dependency_forbidden,
    "dependency_any": check_dependency_any,
    "secrets_absent": check_secrets_absent,
    "pattern_absent": check_pattern_absent,
    "manifest_valid": check_manifest_valid,
    "manifest_identity": check_manifest_identity,
    "manifest_models": check_manifest_models,
    "manifest_content_safety": check_manifest_content_safety,
    "manifest_tools": check_manifest_tools,
    "manifest_baseline_pin": check_manifest_baseline_pin,
    "evals_in_ci": check_evals_in_ci,
    "deployed_drift": check_deployed_drift,
}
