"""Task/role-based tool access — the SGACL matrix.

Deterministic and deny by default: a tool not in the policy, or a role not listed
for it, is FAIL. No wildcards are accepted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agenttrustsec.models import CheckResult, Status


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    change: bool
    allowed_roles: frozenset[str]
    keywords: frozenset[str] = field(default_factory=frozenset)
    description: str = ""


class TbacPolicy:
    def __init__(self, tools: dict[str, ToolSpec]):
        self.tools = tools

    @classmethod
    def from_yaml(cls, path: str | Path) -> "TbacPolicy":
        raw = yaml.safe_load(Path(path).read_text())
        if not isinstance(raw, dict) or "tools" not in raw:
            raise PolicyError("policy must have a top-level 'tools' mapping")
        tools: dict[str, ToolSpec] = {}
        for name, spec in raw["tools"].items():
            roles = spec.get("allowed_roles", [])
            if not isinstance(roles, list):
                raise PolicyError(f"{name}: allowed_roles must be a list")
            if any(r in ("*", "any", "all") for r in roles):
                raise PolicyError(f"{name}: wildcard roles are forbidden (deny by default)")
            if "change" not in spec:
                raise PolicyError(f"{name}: 'change' flag is required")
            tools[name] = ToolSpec(
                name=name,
                change=bool(spec["change"]),
                allowed_roles=frozenset(roles),
                keywords=frozenset(k.lower() for k in spec.get("keywords", [])),
                description=spec.get("description", ""),
            )
        return cls(tools)

    def spec(self, tool: str) -> ToolSpec | None:
        return self.tools.get(tool)

    def check(self, role: str, tool: str) -> CheckResult:
        spec = self.tools.get(tool)
        if spec is None:
            return CheckResult("tbac", Status.FAIL, f"tool {tool!r} not in policy")
        if role not in spec.allowed_roles:
            return CheckResult(
                "tbac", Status.FAIL,
                f"role {role!r} not permitted for {tool!r} "
                f"(allowed: {sorted(spec.allowed_roles)})",
            )
        return CheckResult("tbac", Status.PASS, f"role {role!r} permitted for {tool!r}")
