"""A non-intake agent trying to dispatch a job to a worker (used by test_gateway_slim_live.py).

argv[1] = caller agent name (e.g. executor-01); argv[2] = worker (reader-01 | executor-01,
default reader-01). Prints one line: RESULT {...}.
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agenttrustsec.agents.runtime import AgentRuntime, load_agent, result_body  # noqa: E402
from agenttrustsec.mcpgate.client import McpBlocked, ServerAuthError  # noqa: E402


JOBS = {
    "reader-01": ("reader", "run_job", {"tool": "show_running_config", "args": {"device": "core-rtr-01"},
                                        "session": "x"}),
    "executor-01": ("executor", "run_change", {"device": "edge-fw-01", "lines": ["permit ip any any"],
                                               "session": "x", "approval": "x"}),
}


async def main(caller: str, target: str) -> dict:
    rt = await AgentRuntime(load_agent(caller)).start()
    role, tool, args = JOBS[target]
    async with rt.peer_client(load_agent(target).metadata_id, role, rt.agent_verifier()) as worker:
        try:
            r = await worker.call(tool, args)
            return {"ok": True, "result": result_body(r)}
        except McpBlocked as e:
            return {"blocked_by": e.blocked_by, "reason": e.reason}
        except ServerAuthError as e:
            return {"server_auth_error": str(e)}


if __name__ == "__main__":
    try:
        target = sys.argv[2] if len(sys.argv) > 2 else "reader-01"
        out = asyncio.run(asyncio.wait_for(main(sys.argv[1], target), 60))
    except Exception as e:  # noqa: BLE001
        out = {"error": f"{type(e).__name__}: {e}"[:300]}
    print("RESULT " + json.dumps(out), flush=True)
