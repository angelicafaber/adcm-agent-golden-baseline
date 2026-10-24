"""Repository snapshots: what the engine needs to know about one repository at one commit."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

MAX_TREE_PATHS = 10_000
MAX_CONTENT_FILES = 80
MAX_LOCAL_CONTENT_FILES = 2000
MAX_CONTENT_BYTES = 128 * 1024

DEPENDENCY_FILES = frozenset({"requirements.txt", "requirements-dev.txt", "pyproject.toml", "package.json"})
LOCK_FILES = frozenset({
    "uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
})
SOURCE_EXTENSIONS = frozenset({
    ".py", ".ts", ".js", ".mjs", ".cs", ".java", ".go", ".json", ".yaml", ".yml", ".toml",
    ".bicep", ".tf", ".ini", ".cfg", ".env", ".ps1", ".sh",
})
SECRET_FILE_NAMES = frozenset({".env", "id_rsa", "id_ed25519", "credentials.json"})
SECRET_FILE_SUFFIXES = (".pem", ".pfx", ".p12", ".key")
_SKIP_PARTS = frozenset({"node_modules", ".venv", "venv", "vendor", "dist", "build", ".git", "__pycache__", ".worktrees"})


@dataclass
class BranchRules:
    """Effective default-branch rules, normalised across rulesets and classic protection."""

    source: str  # rulesets | classic | none
    min_approvals: int | None = None
    code_owner_review: bool | None = None
    required_checks: tuple[str, ...] = ()
    block_force_push: bool | None = None
    block_deletion: bool | None = None
    signed_commits: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "min_approvals": self.min_approvals, "code_owner_review": self.code_owner_review,
            "required_checks": list(self.required_checks), "block_force_push": self.block_force_push,
            "block_deletion": self.block_deletion, "signed_commits": self.signed_commits,
        }


@dataclass
class RepoSnapshot:
    name: str
    paths: tuple[str, ...]
    files: dict[str, str]
    commit: str | None = None
    url: str | None = None
    default_branch: str | None = None
    branch_rules: BranchRules | None = None  # None = not observable from this source
    head_signed: bool | None = None  # None = not observable from this source
    coverage_notes: list[str] = field(default_factory=list)

    @property
    def path_set(self) -> frozenset[str]:
        return frozenset(self.paths)

    def by_name(self, names: frozenset[str] | set[str]) -> list[str]:
        return [path for path in self.paths if PurePosixPath(path).name in names]


def _skipped(path: str) -> bool:
    return any(part in _SKIP_PARTS for part in PurePosixPath(path).parts)


def is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")) and path.count("/") == 2


def content_paths(paths: list[str] | tuple[str, ...], manifest_paths: tuple[str, ...] | list[str], limit: int = MAX_CONTENT_FILES) -> tuple[list[str], bool]:
    """Choose which file contents to read, most important first. Returns (paths, truncated)."""
    priority: list[str] = []
    rest: list[str] = []
    manifests = set(manifest_paths)
    for path in sorted(set(paths)):
        if _skipped(path) or len(path) > 300:
            continue
        name = PurePosixPath(path).name
        if path in manifests or is_workflow(path) or path in {".github/dependabot.yml", ".github/dependabot.yaml"}:
            priority.append(path)
        elif name in DEPENDENCY_FILES:
            priority.append(path)
        elif PurePosixPath(path).suffix in SOURCE_EXTENSIONS or name in SECRET_FILE_NAMES:
            rest.append(path)
    chosen = priority + rest
    return chosen[:limit], len(chosen) > limit


def _git_tracked(base: Path) -> list[str] | None:
    """Committed paths when the folder is a git checkout, so ignored local files are not reported."""
    if not (base / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(base), "ls-files", "-z", "--cached"],
            capture_output=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return [p for p in result.stdout.decode("utf-8", errors="replace").split("\0") if p]


def snapshot_from_directory(root: str | os.PathLike[str], manifest_paths: tuple[str, ...] | list[str], name: str | None = None) -> RepoSnapshot:
    """Build a snapshot from a local checkout (CLI and CI). Branch rules are not observable locally."""
    base = Path(root).resolve()
    if not base.is_dir():
        raise ValueError("repository path is not a directory")
    notes: list[str] = []
    tracked = _git_tracked(base)
    paths: list[str] = [] if tracked is None else [p for p in tracked if not _skipped(p)][:MAX_TREE_PATHS]
    if tracked is not None and len(tracked) > MAX_TREE_PATHS:
        notes.append("Repository path limit reached; coverage is incomplete")
    for current, dirs, files in os.walk(base) if tracked is None else ():
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_PARTS and not os.path.islink(os.path.join(current, d)))
        for filename in sorted(files):
            full = Path(current, filename)
            if full.is_symlink():
                continue
            paths.append(full.relative_to(base).as_posix())
            if len(paths) >= MAX_TREE_PATHS:
                notes.append("Repository path limit reached; coverage is incomplete")
                break
        if len(paths) >= MAX_TREE_PATHS:
            break
    chosen, truncated = content_paths(paths, manifest_paths, MAX_LOCAL_CONTENT_FILES)
    if truncated:
        notes.append(f"Only the first {MAX_LOCAL_CONTENT_FILES} relevant files were read; coverage is incomplete")
    files: dict[str, str] = {}
    for rel in chosen:
        full = base / rel
        try:
            if full.is_symlink() or not full.is_file():
                continue
            if full.stat().st_size > MAX_CONTENT_BYTES:
                notes.append(f"{rel}: larger than {MAX_CONTENT_BYTES // 1024} KB; not read")
                continue
            files[rel] = full.read_bytes().decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        except OSError:
            notes.append(f"{rel}: could not be read")
    return RepoSnapshot(name=name or base.name, paths=tuple(paths), files=files, coverage_notes=notes)
