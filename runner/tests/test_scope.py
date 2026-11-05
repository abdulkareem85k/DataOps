from __future__ import annotations

import pytest

from app.scope import ScopeViolation, validate_lab_target


def test_accepts_literal_ipv4_inside_lab_cidr() -> None:
    assert str(validate_lab_target("172.30.0.10", "172.30.0.0/24")) == "172.30.0.10"


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("8.8.8.8", "outside_lab_cidr"),
        ("127.0.0.1", "special_address_blocked"),
        ("169.254.1.1", "special_address_blocked"),
        ("224.0.0.1", "special_address_blocked"),
        ("juice-shop", "invalid_ip_or_cidr"),
        ("172.30.0.0/24", "invalid_ip_or_cidr"),
    ],
)
def test_rejects_non_lab_or_non_literal_destinations(target: str, reason: str) -> None:
    with pytest.raises(ScopeViolation) as exc_info:
        validate_lab_target(target, "172.30.0.0/24")
    assert exc_info.value.reason_code == reason
