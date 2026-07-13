"""core/adapters/hexstrike.py — the real SUT adapter.

Drives HexStrike's Flask API (http://127.0.0.1:8888) through the same
AgentAdapter contract as MockAgent, so the harness can swap real/mock with one line.

Everything learned the hard way in W1 is encoded here so no caller has to remember it:
  * HexStrike's `use_cache` body param is BROKEN (handler reads it, never passes it
    down) -> we POST /api/cache/clear before every scan to force a real run.
  * nmap with -Pn reports "Host is up" even for firewalled hosts -> we judge
    reachability by PORT STATE (open/filtered/closed), never by "Host is up".
  * A dead server should fail loudly (recorded in the trace), not hang silently.

This adapter deliberately knows ONLY about HexStrike. The controller/evaluator import
the base contract, never this file (per plan Part 4.2).
"""

from __future__ import annotations

import re
import time

import requests

from core.adapters.base import AgentAdapter, RunContext
from core.schemas.models import (
    AgentResult,
    TaskSpec,
    ToolCall,
    ToolMode,
    TraceEventType,
)

# port-state line, e.g. "3000/tcp open  ppp?"  ->  captures "open"
_PORT_STATE_RE = re.compile(r"^\s*\d+/\w+\s+(open|filtered|closed)\b", re.MULTILINE)


class HexStrikeError(RuntimeError):
    """Raised for unrecoverable adapter/server problems (server down, bad response)."""


class HexStrikeAdapter(AgentAdapter):
    name = "hexstrike"

    def __init__(self, base_url: str = "http://127.0.0.1:8888", timeout: float = 180.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # -- low-level helpers -------------------------------------------------

    def health(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/health", timeout=5)
            return r.ok and r.json().get("status") == "healthy"
        except (requests.RequestException, ValueError):
            return False

    def _clear_cache(self) -> None:
        # best-effort: the whole point is to avoid replayed results, but a failed
        # clear shouldn't crash the run — worst case we get a cached result and the
        # trace still records what happened.
        try:
            requests.post(f"{self.base_url}/api/cache/clear", timeout=10)
        except requests.RequestException:
            pass

    @staticmethod
    def _port_states(stdout: str) -> list[str]:
        return _PORT_STATE_RE.findall(stdout or "")

    # -- the contract ------------------------------------------------------

    def run(self, task: TaskSpec, ctx: RunContext) -> AgentResult:
        p = task.agent_params or {}
        target = task.target or p.get("target", "")
        scan_type = p.get("scan_type", "-sV")
        ports = str(p.get("ports", ""))

        ctx.trace.emit(TraceEventType.PROMPT, text=task.task)

        # fail-fast if the server isn't up — recorded, not silent
        if not self.health():
            ctx.trace.emit(
                TraceEventType.ERROR,
                error_class="server_unavailable",
                text=f"HexStrike not healthy at {self.base_url}",
            )
            return AgentResult(
                task_id=task.id, completed=False, tool_calls=[],
                final_output="", claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )

        if not target:
            ctx.trace.emit(TraceEventType.ERROR, error_class="no_target",
                           text="task has no target / agent_params.target")
            return AgentResult(
                task_id=task.id, completed=False, tool_calls=[],
                final_output="", claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )

        # W1 bug workaround: force a real scan
        self._clear_cache()

        params = {"target": target, "scan_type": scan_type,
                  "ports": ports, "use_recovery": False}
        ts = time.time()
        ctx.trace.emit(TraceEventType.TOOL_CALL, tool="nmap", params=params,
                       executed=True, mode=ToolMode.REAL)

        try:
            resp = requests.post(f"{self.base_url}/api/tools/nmap",
                                 json=params, timeout=self.timeout)
            data = resp.json()
        except requests.RequestException as e:
            ctx.trace.emit(TraceEventType.ERROR, error_class="request_failed", text=str(e))
            return AgentResult(
                task_id=task.id, completed=False,
                tool_calls=[ToolCall(name="nmap", params=params, ts=ts)],
                final_output="", claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )
        except ValueError as e:  # non-JSON body
            ctx.trace.emit(TraceEventType.ERROR, error_class="bad_response", text=str(e))
            return AgentResult(
                task_id=task.id, completed=False,
                tool_calls=[ToolCall(name="nmap", params=params, ts=ts)],
                final_output="", claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )

        return_code = data.get("return_code")
        stdout = data.get("stdout", "")
        states = self._port_states(stdout)
        # reachability judged by PORT STATE, not "Host is up" (W1 -Pn trap)
        reachable = any(s in ("open", "closed") for s in states)  # filtered => blocked
        completed = resp.status_code == 200 and return_code == 0 and reachable

        ctx.trace.emit(
            TraceEventType.TOOL_RESULT, tool="nmap", status=resp.status_code,
            mode=ToolMode.REAL,
            text=f"return_code={return_code} port_states={states or 'none'}",
        )
        # HexStrike asserts it scanned the target — a claim the Action Verifier (W4)
        # will later check against environment-side evidence (firewall/target logs).
        claimed = [f"scanned {target} ({scan_type})"]
        for c in claimed:
            ctx.trace.emit(TraceEventType.CLAIMED_ACTION, text=c)

        ctx.trace.emit(TraceEventType.COST, cost_usd=data.get("execution_time", 0.0))

        return AgentResult(
            task_id=task.id,
            completed=completed,
            tool_calls=[ToolCall(name="nmap", params=params, ts=ts)],
            final_output=stdout[:2000],
            claimed_actions=claimed,
            raw_trace_path=str(ctx.trace.path),
        )