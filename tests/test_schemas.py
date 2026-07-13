"""
tests/test_schemas.py — the harness's first tests.

We test the SCHEMA, not an agent. A valid case YAML must load into a TaskSpec;
a malformed one must raise pydantic.ValidationError. This is the "we test the
test tool" point from the plan: it separates 'the case file is wrong' from
'the agent is wrong' long before any agent ever runs.

Fixtures live in tests/fixtures/cases/ and are auto-discovered by prefix:
  valid_*.yaml   -> must load
  invalid_*.yaml -> must be rejected
Drop a new fixture file and it's tested automatically — no edits here.
"""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from core.schemas.models import TaskSpec

CASES_DIR = Path(__file__).parent / "fixtures" / "cases"


def load_case(path: Path) -> TaskSpec:
    """Minimal case loader.

    TODO: when you build core/schemas/loader.py, move this there and point the
    test at the real loader so the test exercises production code, not a copy.
    """
    data = yaml.safe_load(path.read_text())
    return TaskSpec(**data)


VALID_CASES = sorted(CASES_DIR.glob("valid_*.yaml"))
INVALID_CASES = sorted(CASES_DIR.glob("invalid_*.yaml"))


def test_fixtures_exist():
    # Guard against a silent false-green: parametrizing over an empty glob
    # produces zero tests and still "passes". Fail loudly if fixtures vanish.
    assert VALID_CASES, "no valid_*.yaml fixtures found"
    assert INVALID_CASES, "no invalid_*.yaml fixtures found"


@pytest.mark.parametrize("path", VALID_CASES, ids=lambda p: p.name)
def test_valid_case_loads(path: Path):
    case = load_case(path)
    assert isinstance(case, TaskSpec)
    assert case.id                          # non-empty id
    assert case.scoring.success_predicate   # scoring actually parsed


@pytest.mark.parametrize("path", INVALID_CASES, ids=lambda p: p.name)
def test_invalid_case_rejected(path: Path):
    with pytest.raises(ValidationError):
        load_case(path)
