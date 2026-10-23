"""Tool inventory: what the MCPServerBadge signs vs what the gateway serves (item C).

TrustSec analogy: the switch's certificate says what it is; a device doing something else than
its certificate vouches for is not trusted. `identity badge issue mcp` signs the server's
`tools/list` into the MCPServerBadge (name, description, parameters = inputSchema without its
top-level `title`). Both ends compare against that SIGNED inventory (deny by default):
  * the gateway refuses to start when what it serves drifts from its badge (serve.py)
  * agents refuse a result for a tool, or an argument, the badge does not vouch for (client.py)

Inventories here are canonical dicts: {tool name: {"description": ..., "parameters": {...}}}.
"""
from __future__ import annotations

import json
from typing import Any

Inventory = dict[str, dict[str, Any]]


class InventoryDrift(Exception):
    """What is served is not what the badge signs -> refuse."""


def from_badge(badge_json: Any) -> Inventory:
    """The `credentialSubject.badge` of a VERIFIED MCPServerBadge -> inventory.
    Anything unreadable raises ValueError (callers turn it into a BadgeError)."""
    data = json.loads(badge_json) if isinstance(badge_json, str) else badge_json
    tools = data.get("tools") if isinstance(data, dict) else None
    if not isinstance(tools, list):
        raise ValueError("MCPServerBadge carries no tool list")
    inv: Inventory = {}
    for t in tools:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str) or t["name"] in inv:
            raise ValueError("MCPServerBadge tool list is malformed")
        inv[t["name"]] = {"description": t.get("description"), "parameters": t.get("parameters") or {}}
    return inv


def to_badge_tools(inv: Inventory) -> list[dict[str, Any]]:
    """Inventory -> the CLI's badge `tools` list (dev badges in tests)."""
    return [{"name": n, **v} for n, v in inv.items()]


async def served(server: Any) -> Inventory:
    """The server's own tools/list, in the shape the CLI signs (in-process, no network)."""
    from mcp import Client
    async with Client(server) as c:
        listed = (await c.list_tools()).tools
    return {t.name: {"description": t.description,
                     "parameters": {k: v for k, v in (t.input_schema or {}).items() if k != "title"}}
            for t in listed}


def drift(signed: Inventory, serving: Inventory) -> list[str]:
    """Human-readable differences; empty = the badge vouches for exactly what is served."""
    out = [f"{n} not in badge" for n in sorted(set(serving) - set(signed))]
    out += [f"{n} signed but not served" for n in sorted(set(signed) - set(serving))]
    for n in sorted(set(signed) & set(serving)):
        changed = [k for k in ("description", "parameters")
                   if json.dumps(signed[n].get(k), sort_keys=True) != json.dumps(serving[n].get(k), sort_keys=True)]
        if changed:
            out.append(f"{n} changed ({', '.join(changed)})")
    return out


def vouches_for(signed: Inventory | None, tool: str, args: dict[str, Any]) -> str | None:
    """None if the signed inventory covers this call, else why not."""
    if signed is None:
        return "server badge carries no tool inventory"
    if tool not in signed:
        return f"tool {tool!r} is not in the server's signed inventory"
    props = signed[tool].get("parameters", {}).get("properties", {})
    extra = sorted(set(args) - set(props if isinstance(props, dict) else {}))
    if extra:
        return f"argument(s) {extra} of {tool!r} are not in the server's signed inventory"
    return None
