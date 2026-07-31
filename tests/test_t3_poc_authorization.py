import pytest

from core.t3.poc_authorization import issue_poc_authorization_id


@pytest.mark.parametrize(
    ("stage", "tag"),
    [("T3-A", "a1"), ("T3-B", "b1"), ("T3-C", "c1")],
)
def test_authorization_id_is_opaque_timestamped_and_stage_bound(stage, tag):
    selected = issue_poc_authorization_id(stage, now=1_800_000_000)
    assert len(selected) == 40
    assert selected[:8] == f"{1_800_000_000:08x}"
    assert selected[8:10] == tag
    int(selected, 16)


def test_unknown_stage_is_rejected():
    with pytest.raises(ValueError, match="unknown"):
        issue_poc_authorization_id("unknown")
