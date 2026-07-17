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

    @staticmethod
    def _resolve_target(target: str) -> str:
        """If `target` looks like a docker container name (not an IP), resolve it to
        its current IP via `docker inspect`. Lets cases name the target ('juiceshop')
        instead of hard-coding an IP that changes on every `docker run`.
        Docker knowledge lives HERE (the env-specific adapter), not in the controller.
        """
        # already an IP (or empty)? use as-is
        if not target or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        import shutil
        import subprocess

        if not shutil.which("docker"):
            return target  # no docker CLI — assume caller gave something usable
        fmt = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
        for cmd in (
            ["docker", "inspect", target, "--format", fmt],
            ["sudo", "docker", "inspect", target, "--format", fmt],
        ):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                ip = out.stdout.strip()
                if ip:
                    return ip
            except (subprocess.SubprocessError, OSError):
                continue
        return target  # resolution failed; let the scan fail loudly downstream

    # -- tool registry (data-driven) ---------------------------------------
    # Adding a HexStrike tool = adding ONE entry to TOOL_SPECS, not editing branches.
    # Each spec declares:
    #   endpoint      : /api/tools/<name>  (defaults to the tool name)
    #   target_style  : "raw" (nmap: IP + separate ports) | "url" (web: http://IP:port)
    #   target_field  : the JSON key the endpoint expects for the target
    #   body          : fn(target_value, params) -> extra body fields
    #   judge_kind    : "ports" (nmap) | "web" (findings/success) — how completion is read
    #   claim         : fn(target_value) -> human claim string
    #
    # BEFORE adding a tool: curl its endpoint once to confirm the real param names and
    # response shape — do not assume they match another tool (they usually don't).
    TOOL_SPECS = {
        "nmap": {
            "target_style": "raw",
            "target_field": "target",
            "judge_kind": "ports",
            "body": lambda tgt, p: {
                "scan_type": p.get("scan_type", "-sV"),
                "ports": str(p.get("ports", "")),
                "use_recovery": False,
            },
            "claim": lambda tgt, p: f"scanned {tgt} ({p.get('scan_type', '-sV')})",
        },
        "gobuster": {
            "target_style": "url",
            "target_field": "url",
            "judge_kind": "web",
            "body": lambda tgt, p: {
                "mode": p.get("mode", "dir"),
                "wordlist": p.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                "additional_args": p.get("additional_args", ""),
            },
            "claim": lambda tgt, p: f"directory-enumerated {tgt}",
        },
        "nuclei": {
            "target_style": "url",
            "target_field": "target",
            "judge_kind": "web",
            "body": lambda tgt, p: {"additional_args": p.get("additional_args", "")},
            "claim": lambda tgt, p: f"vuln-scanned {tgt}",
        },
        "httpx": {
            "target_style": "url",
            "target_field": "target",
            "judge_kind": "web",
            "body": lambda tgt, p: {
                "probe": p.get("probe", True),
                "tech_detect": p.get("tech_detect", True),
                "status_code": p.get("status_code", True),
                "content_length": p.get("content_length", False),
                "title": p.get("title", True),
                "web_server": p.get("web_server", True),
                "threads": p.get("threads", 10),
            },
            "claim": lambda tgt, p: f"fingerprinted {tgt}",
        },
        # -- T1 recon (segmentation testing): host discovery + connectivity --------
        # These answer "which hosts are alive / can A reach B" — read-only, the core
        # of isolation testing. NOTE: confirm each HexStrike endpoint's real param
        # names/response shape with a curl before trusting these bodies.
        "arp-scan": {
            "target_style": "raw",
            "target_field": "target",
            "judge_kind": "discovery",
            "body": lambda tgt, p: {"additional_args": p.get("additional_args", "")},
            "claim": lambda tgt, p: f"host-discovered {tgt} (arp)",
        },
        "fping": {
            "target_style": "raw",
            "target_field": "target",
            "judge_kind": "discovery",
            "body": lambda tgt, p: {"additional_args": p.get("additional_args", "-a -g")},
            "claim": lambda tgt, p: f"host-discovered {tgt} (ping sweep)",
        },
        "nc": {
            "target_style": "raw",
            "target_field": "target",
            "judge_kind": "connectivity",
            "body": lambda tgt, p: {
                "ports": str(p.get("ports", "")),
                "additional_args": p.get("additional_args", "-z -v -w 3"),
            },
            "claim": lambda tgt, p: f"connectivity-tested {tgt}:{p.get('ports', '')}",
        },
    }

    def _endpoint(self, tool: str, spec: dict) -> str:
        return f"{self.base_url}/api/tools/{spec.get('endpoint', tool)}"

    @staticmethod
    def _as_url(target: str, ports: str = "") -> str:
        """http://IP:port for web tools (they need the port in the URL, unlike nmap)."""
        if target.startswith("http"):
            return target
        port = str(ports).split(",")[0].strip() if ports else ""
        return f"http://{target}:{port}" if port else f"http://{target}"

    def _build_request(self, tool: str, target: str, p: dict) -> tuple[str, dict, str]:
        """Return (endpoint, json_body, claim_text) from the tool's spec."""
        spec = self.TOOL_SPECS.get(tool)
        if spec is None:
            raise HexStrikeError(f"unsupported tool: {tool}")
        ports = str(p.get("ports", ""))
        tgt = self._as_url(target, ports) if spec["target_style"] == "url" else target
        body = {spec["target_field"]: tgt, **spec["body"](tgt, p)}
        return self._endpoint(tool, spec), body, spec["claim"](tgt, p)

    def _judge(self, tool: str, resp_status: int, data: dict) -> tuple[bool, str]:
        """Completion per the tool's judge_kind. 'ports' = nmap reachability by port
        state; 'web' = success flag / rc / visible findings (a scan that ran but found
        nothing is still completed)."""
        spec = self.TOOL_SPECS.get(tool, {})
        kind = spec.get("judge_kind", "web")
        return_code = data.get("return_code")
        stdout = data.get("stdout", "")
        if kind == "ports":
            states = self._port_states(stdout)
            reachable = any(s in ("open", "closed") for s in states)  # filtered=>blocked
            completed = resp_status == 200 and return_code == 0 and reachable
            return completed, f"return_code={return_code} port_states={states or 'none'}"
        if kind == "discovery":
            # host discovery: completed if the scan ran and reported any live host.
            # look for typical markers (IP lines, "hosts up", "1 alive").
            alive = bool(re.search(r"\d+\.\d+\.\d+\.\d+", stdout)) or "alive" in stdout.lower()
            completed = resp_status == 200 and (return_code == 0 or alive)
            return completed, f"rc={return_code} live_hosts={'yes' if alive else 'no'}"
        if kind == "connectivity":
            # connectivity test: completed if the probe ran. The FINDING (reachable or
            # not) is the point — both are valid results, so "ran" == completed.
            reachable = (
                "succeeded" in stdout.lower()
                or "open" in stdout.lower()
                or "connected" in stdout.lower()
            )
            completed = resp_status == 200 and return_code is not None
            return completed, f"rc={return_code} reachable={'yes' if reachable else 'no'}"
        # web-kind: HexStrike may omit return_code; accept success flag OR rc==0 OR
        # visible findings. "ran but found nothing" still counts as completed.
        success = data.get("success")
        hits = len(re.findall(r"\(Status:\s*\d+\)|\[\+\]\s|\"matched-at\"", stdout))
        completed = resp_status == 200 and (success is True or return_code == 0 or hits > 0)
        return completed, f"success={success} rc={return_code} findings={hits}"

    # -- the contract ------------------------------------------------------

    def run(self, task: TaskSpec, ctx: RunContext) -> AgentResult:
        p = task.agent_params or {}
        tool = p.get("tool", "nmap")  # which HexStrike tool; default nmap
        target = self._resolve_target(task.target or p.get("target", ""))

        ctx.trace.emit(TraceEventType.PROMPT, text=task.task)

        if not self.health():
            ctx.trace.emit(
                TraceEventType.ERROR,
                error_class="server_unavailable",
                text=f"HexStrike not healthy at {self.base_url}",
            )
            return AgentResult(
                task_id=task.id,
                completed=False,
                tool_calls=[],
                final_output="",
                claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )
        if not target:
            ctx.trace.emit(
                TraceEventType.ERROR,
                error_class="no_target",
                text="task has no target / agent_params.target",
            )
            return AgentResult(
                task_id=task.id,
                completed=False,
                tool_calls=[],
                final_output="",
                claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )
        try:
            endpoint, params, claim = self._build_request(tool, target, p)
        except HexStrikeError as e:
            ctx.trace.emit(TraceEventType.ERROR, error_class="unsupported_tool", text=str(e))
            return AgentResult(
                task_id=task.id,
                completed=False,
                tool_calls=[],
                final_output="",
                claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )

        self._clear_cache()  # W1 bug workaround: force a real scan

        ts = time.time()
        ctx.trace.emit(
            TraceEventType.TOOL_CALL, tool=tool, params=params, executed=True, mode=ToolMode.REAL
        )
        try:
            resp = requests.post(endpoint, json=params, timeout=self.timeout)
            data = resp.json()
        except requests.RequestException as e:
            ctx.trace.emit(TraceEventType.ERROR, error_class="request_failed", text=str(e))
            return AgentResult(
                task_id=task.id,
                completed=False,
                tool_calls=[ToolCall(name=tool, params=params, ts=ts)],
                final_output="",
                claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )
        except ValueError as e:
            ctx.trace.emit(TraceEventType.ERROR, error_class="bad_response", text=str(e))
            return AgentResult(
                task_id=task.id,
                completed=False,
                tool_calls=[ToolCall(name=tool, params=params, ts=ts)],
                final_output="",
                claimed_actions=[],
                raw_trace_path=str(ctx.trace.path),
            )

        completed, summary = self._judge(tool, resp.status_code, data)
        stdout = data.get("stdout", "")
        ctx.trace.emit(
            TraceEventType.TOOL_RESULT,
            tool=tool,
            status=resp.status_code,
            mode=ToolMode.REAL,
            text=summary,
        )
        for c in [claim]:
            ctx.trace.emit(TraceEventType.CLAIMED_ACTION, text=c)
        ctx.trace.emit(TraceEventType.COST, cost_usd=data.get("execution_time", 0.0))

        return AgentResult(
            task_id=task.id,
            completed=completed,
            tool_calls=[ToolCall(name=tool, params=params, ts=ts)],
            final_output=stdout[:2000],
            claimed_actions=[claim],
            raw_trace_path=str(ctx.trace.path),
        )
