"""Runner-side defense-in-depth validation for every scanner destination."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network


class ScopeViolation(ValueError):
    """Raised when a target cannot be proven to belong to the lab network."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def validate_lab_target(target: str, lab_cidr: str) -> IPv4Address:
    """Accept only ordinary IPv4 literals inside the private configured lab CIDR."""
    try:
        address = ip_address(target)
        network = ip_network(lab_cidr, strict=True)
    except ValueError as exc:
        raise ScopeViolation("invalid_ip_or_cidr") from exc

    if not isinstance(address, IPv4Address) or not isinstance(network, IPv4Network):
        raise ScopeViolation("ipv4_only")
    if address.is_loopback or address.is_link_local or address.is_multicast:
        raise ScopeViolation("special_address_blocked")
    if address.is_unspecified or address.is_reserved:
        raise ScopeViolation("special_address_blocked")
    if address not in network:
        raise ScopeViolation("outside_lab_cidr")
    if not address.is_private:
        raise ScopeViolation("special_address_blocked")
    return address
