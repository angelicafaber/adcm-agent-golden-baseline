"""Agent manifest (``adcm-agent.yaml``) parsing and structural validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import yaml

SCHEMA = "adcm.agent/v1"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_TOOLS = 50
MAX_DEPLOYMENTS = 10

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+")
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_SEMVER = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")
_ARM_ID = re.compile(
    r"/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/"
    r"Microsoft\.(App/containerApps|Web/sites)/[A-Za-z0-9-]{1,64}",
    re.IGNORECASE,
)
_PLATFORMS = ("foundry", "container_app", "function_app")
_TOP_KEYS = {
    "schema", "name", "description", "baseline_version", "owner", "sponsor", "data_classification",
    "identity", "model", "tools", "telemetry", "deployments",
}


class ManifestError(ValueError):
    """The manifest cannot be read as YAML at all."""


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if len(keys) != len(set(map(str, keys))):
            raise ManifestError("manifest has duplicate keys")
        return super().construct_mapping(node, deep=deep)


def https_origin(value: Any) -> str | None:
    """Return ``https://host`` for a plain HTTPS URL, else ``None`` (no credentials or ports)."""
    if not isinstance(value, str) or len(value) > 500:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username or parts.password or port not in (None, 443):
        return None
    return "https://" + host


@dataclass
class Manifest:
    path: str
    data: dict[str, Any]
    problems: list[str] = field(default_factory=list)

    def get(self, *keys: str) -> Any:
        value: Any = self.data
        for key in keys:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
        return value

    @property
    def tools(self) -> list[dict[str, Any]]:
        value = self.data.get("tools")
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    @property
    def deployments(self) -> list[dict[str, Any]]:
        value = self.data.get("deployments")
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def summary(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.data.get("name") if isinstance(self.data.get("name"), str) else None,
            "owner": self.data.get("owner") if isinstance(self.data.get("owner"), str) else None,
            "sponsor": self.data.get("sponsor") if isinstance(self.data.get("sponsor"), str) else None,
            "data_classification": self.data.get("data_classification") if isinstance(self.data.get("data_classification"), str) else None,
            "baseline_version": self.data.get("baseline_version") if isinstance(self.data.get("baseline_version"), str) else None,
            "identity_type": self.get("identity", "type") if isinstance(self.get("identity", "type"), str) else None,
            "model": self.get("model", "deployment") if isinstance(self.get("model", "deployment"), str) else None,
            "tools": sorted(str(t.get("name")) for t in self.tools if isinstance(t.get("name"), str))[:MAX_TOOLS],
            "deployments": [
                {k: str(v) for k, v in d.items() if k in {"platform", "agent_name", "project_endpoint", "resource_id"}}
                for d in self.deployments[:MAX_DEPLOYMENTS]
            ],
            "valid": not self.problems,
        }


def parse_manifest(path: str, raw: str) -> Manifest:
    """Parse and validate. YAML that cannot be read raises; schema problems are listed."""
    if len(raw.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest is too large")
    try:
        for token in yaml.scan(raw, Loader=yaml.SafeLoader):
            if isinstance(token, (yaml.AliasToken, yaml.AnchorToken)):
                raise ManifestError("manifest must not use YAML anchors or aliases")
        data = yaml.load(raw, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError:
        raise ManifestError("manifest is not valid YAML") from None
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a YAML mapping")
    manifest = Manifest(path=path, data=data)
    manifest.problems = validate_manifest(data)
    return manifest


def validate_manifest(data: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    unknown = sorted(str(key) for key in data if key not in _TOP_KEYS)
    if unknown:
        problems.append("unknown fields: " + ", ".join(unknown[:10]))
    if data.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA}")
    if not isinstance(data.get("name"), str) or not _NAME.fullmatch(data["name"]):
        problems.append("name is required (letters, digits, . _ -)")
    if not isinstance(data.get("baseline_version"), str) or not _SEMVER.fullmatch(data["baseline_version"]):
        problems.append("baseline_version is required (MAJOR.MINOR.PATCH)")
    for key in ("owner", "sponsor"):
        if not isinstance(data.get(key), str) or not _EMAIL.fullmatch(data[key]):
            problems.append(f"{key} is required (user principal name)")
    if not isinstance(data.get("data_classification"), str) or not data["data_classification"]:
        problems.append("data_classification is required")
    identity = data.get("identity")
    if not isinstance(identity, dict) or set(identity) - {"type", "blueprint_id", "client_id"} or not isinstance(identity.get("type"), str):
        problems.append("identity must declare type (and blueprint_id for Entra Agent ID)")
    elif "blueprint_id" in identity and (not isinstance(identity["blueprint_id"], str) or not _GUID.fullmatch(identity["blueprint_id"])):
        problems.append("identity.blueprint_id must be a GUID")
    model = data.get("model")
    if not isinstance(model, dict) or set(model) - {"deployment", "content_safety"} or not isinstance(model.get("deployment"), str):
        problems.append("model must declare deployment")
    elif "content_safety" in model:
        safety = model["content_safety"]
        if not isinstance(safety, dict) or set(safety) - {"enabled", "rai_policy"} or type(safety.get("enabled")) is not bool:
            problems.append("model.content_safety must declare enabled: true|false")
    tools = data.get("tools")
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        problems.append(f"tools must be a list (at most {MAX_TOOLS}); use [] for none")
    else:
        names: set[str] = set()
        for tool in tools:
            if not isinstance(tool, dict) or set(tool) - {"name", "type", "endpoint", "write", "approval"}:
                problems.append("each tool needs name, type, write and optional endpoint/approval only")
                continue
            if not isinstance(tool.get("name"), str) or not _NAME.fullmatch(tool["name"]) or tool["name"] in names:
                problems.append("tool names must be unique identifiers")
            else:
                names.add(tool["name"])
            if not isinstance(tool.get("type"), str) or type(tool.get("write")) is not bool:
                problems.append(f"tool {tool.get('name')!s:.40}: type and write (true|false) are required")
            if "endpoint" in tool and https_origin(tool["endpoint"]) is None:
                problems.append(f"tool {tool.get('name')!s:.40}: endpoint must be a plain https URL")
            if "approval" in tool and tool["approval"] not in ("required", "none"):
                problems.append(f"tool {tool.get('name')!s:.40}: approval must be required or none")
    telemetry = data.get("telemetry")
    if not isinstance(telemetry, dict) or set(telemetry) - {"enabled"} or type(telemetry.get("enabled")) is not bool:
        problems.append("telemetry must declare enabled: true|false")
    deployments = data.get("deployments", [])
    if not isinstance(deployments, list) or len(deployments) > MAX_DEPLOYMENTS:
        problems.append(f"deployments must be a list (at most {MAX_DEPLOYMENTS})")
    else:
        for item in deployments:
            problems.extend(_deployment_problems(item))
    return problems


def _deployment_problems(item: Any) -> list[str]:
    if not isinstance(item, dict) or item.get("platform") not in _PLATFORMS:
        return ["each deployment needs platform: foundry, container_app or function_app"]
    if item["platform"] == "foundry":
        if set(item) != {"platform", "project_endpoint", "agent_name"}:
            return ["foundry deployments need exactly platform, project_endpoint and agent_name"]
        endpoint = item["project_endpoint"]
        if not isinstance(endpoint, str) or not re.fullmatch(
            r"https://[a-z0-9][a-z0-9-]{1,62}\.services\.ai\.azure\.com/api/projects/[A-Za-z0-9._-]{1,64}", endpoint,
        ):
            return ["foundry project_endpoint must be https://<account>.services.ai.azure.com/api/projects/<project>"]
        if not isinstance(item["agent_name"], str) or not _NAME.fullmatch(item["agent_name"]):
            return ["foundry agent_name is invalid"]
        return []
    if set(item) != {"platform", "resource_id"} or not isinstance(item["resource_id"], str) or not _ARM_ID.fullmatch(item["resource_id"]):
        return [f"{item['platform']} deployments need exactly platform and an ARM resource_id"]
    expected = "microsoft.app/containerapps" if item["platform"] == "container_app" else "microsoft.web/sites"
    if expected not in item["resource_id"].lower():
        return [f"{item['platform']} resource_id has the wrong resource type"]
    return []
