import pytest

from app.services.safety import UnsafeTarget, validate_target, within_scope


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1", "169.254.1.3", "224.0.0.1", "0.0.0.0", "10.0.0.0/8", "127.0.0.1;id"])
def test_public_oversized_and_malformed_targets_are_rejected(target: str):
    with pytest.raises(UnsafeTarget):
        validate_target(target)


@pytest.mark.parametrize("target,count", [("127.0.0.1",1),("10.20.0.12",1),("192.168.56.0/30",2)])
def test_small_private_targets_are_accepted(target: str, count: int):
    validated = validate_target(target)
    assert len(validated.addresses) == count


def test_project_scope_is_separate_from_private_range_check():
    target = validate_target("10.21.0.4")
    assert not within_scope(target.addresses, "10.20.0.0/24")

