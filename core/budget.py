"""Token/cost budgets for bounded autonomous agent loops."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class Budget:
    max_tokens: int
    max_cost_usd: float | None = None
    hard_max_iterations: int = 50
    tokens_used: int = 0
    cost_usd: float = 0.0
    iterations: int = 0

    def record(self, usage: Usage) -> None:
        self.iterations += 1
        self.tokens_used += usage.tokens
        self.cost_usd += usage.cost_usd

    def exhausted_reason(self) -> str | None:
        if self.tokens_used >= self.max_tokens:
            return "max_tokens"
        if self.max_cost_usd is not None and self.cost_usd >= self.max_cost_usd:
            return "max_cost_usd"
        if self.iterations >= self.hard_max_iterations:
            return "hard_max_iterations"
        return None
