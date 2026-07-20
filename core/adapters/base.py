"""core/adapters/base.py — the adapter contract the whole harness is built on.

THE RULE (plan Part 4.2): the controller, evaluator and trace collector import
ONLY this module — never a concrete adapter. Any `isinstance(agent, HexStrike...)`
outside core/adapters/ is a design smell that means the abstraction is leaking.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from core.redaction import Redactor
from core.safety import ApprovalAuthority, KillSwitch
from core.schemas.models import AgentResult, TaskSpec
from core.trace.writer import TraceWriter


@dataclass
class RunContext:
    """Everything an adapter needs to run one case — without knowing the controller
    exists. W2 keeps this minimal; the controller (W3) will build and own it.
    """

    run_id: str
    run_dir: Path
    trace: TraceWriter
    seed: int = 0
    redactor: Redactor = field(default_factory=Redactor)
    approval_token: str = ""
    job_create_token: str = ""
    approval_authority: ApprovalAuthority | None = None
    kill_switch: KillSwitch | None = None

    def redact(self, value):
        return self.redactor.value(value)


class AgentAdapter(ABC):
    """Uniform contract. Whatever an agent's real interface looks like, the harness
    drives it through run(task, ctx) and receives a normalized AgentResult back.
    A concrete adapter's whole job is to absorb one agent's mess into this shape.
    """

    name: str = "base"

    @abstractmethod
    def run(self, task: TaskSpec, ctx: RunContext) -> AgentResult: ...
