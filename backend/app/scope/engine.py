"""Deterministic scope engine. Approval never overrides these checks."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.orm import AuditEvent
from app.models.schemas import ScopeRuleCreate, ScopeRuleRead
from app.repo.audit import append_audit_event
from app.repo.common import RecordNotFound, as_utc
from app.repo.scope import get_scope_rules, upsert_scope_rules
from app.scope.models import ActionClass, Decision, ScopeRules
from app.scope.sanitize import ArgsSanitizerError, sanitize_args
from app.settings import Settings, get_settings

Resolver = Callable[[str], list[str]]
RedirectResolver = Callable[[str], list[str]]

MAX_URL_LENGTH = 2048
MAX_PREFIX_LEN_V4 = 16
CLOUD_METADATA_V4 = ip_network("169.254.169.254/32")
CLOUD_METADATA_V6 = ip_network("fd00:ec2::254/128")
IPV4_LINK_LOCAL = ip_network("169.254.0.0/16")


class ScopeRegistrationError(ValueError):
    """Raised when a scope document is invalid or too broad."""


class ScopeDenied(RuntimeError):
    """Raised when check_action denies a requested action."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def _now() -> datetime:
    return datetime.now(UTC)


def _rules_from_row(row: ScopeRuleRead) -> ScopeRules:
    return ScopeRules(
        allowed_targets=list(row.allowed_targets),
        exclusions=list(row.exclusions),
        allowed_tools=list(row.allowed_tools),
        allowed_action_classes=list(row.allowed_action_classes),  # type: ignore[arg-type]
        rate_limit_max=row.rate_limit_max,
        rate_limit_window_seconds=row.rate_limit_window_seconds,
        window_start=row.window_start,
        window_end=row.window_end,
        notes=row.notes,
    )


def default_resolve(hostname: str) -> list[str]:
    """Resolve a hostname using the stdlib; tests should inject a mock instead."""
    import socket

    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise ScopeRegistrationError(f"hostname {hostname} could not be resolved") from exc
    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            addresses.append(str(sockaddr[0]))
    if not addresses:
        raise ScopeRegistrationError(f"hostname {hostname} resolved to no addresses")
    return list(dict.fromkeys(addresses))


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _parse_network(value: str) -> IPv4Network | IPv6Network | None:
    try:
        return ip_network(value, strict=False)
    except ValueError:
        return None


def _host_from_target(target: str) -> tuple[str, str | None]:
    """Return (host, original_scheme_or_none) for an IP, hostname, or URL."""
    if "://" in target:
        parts = urlsplit(target)
        return parts.hostname or "", parts.scheme
    return target, None


def _address_blocked_special(address: IPv4Address | IPv6Address) -> str | None:
    if (
        address in CLOUD_METADATA_V4
        or address in CLOUD_METADATA_V6
        or str(address) == "169.254.169.254"
    ):
        return "cloud-metadata addresses are blocked"
    if address.is_loopback:
        return "loopback addresses are blocked"
    if address.is_link_local or address in IPV4_LINK_LOCAL:
        return "link-local addresses are blocked"
    if address.is_multicast:
        return "multicast addresses are blocked"
    if address.is_reserved or address.is_unspecified:
        return "reserved addresses are blocked"
    return None


def _is_public_ip(address: IPv4Address | IPv6Address) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _target_in_spec(candidate: str, spec: str, resolve: Resolver) -> bool:
    network = _parse_network(spec)
    if network is not None and "/" in spec:
        if _is_ip(candidate):
            return ip_address(candidate) in network
        for resolved in resolve(candidate):
            if ip_address(resolved) in network:
                return True
        return False
    if _is_ip(spec) and _is_ip(candidate):
        return ip_address(spec) == ip_address(candidate)
    if spec == candidate:
        return True
    if spec.lower() == candidate.lower():
        return True
    if "://" in spec:
        spec_host, _ = _host_from_target(spec)
        cand_host, _ = _host_from_target(candidate)
        return bool(spec_host) and spec_host.lower() == (cand_host or "").lower()
    return False


def _iter_ips_for_target(target: str, resolve: Resolver) -> list[str]:
    host, _scheme = _host_from_target(target)
    if not host:
        host = target
    if _is_ip(host):
        return [str(ip_address(host))]
    return [str(ip_address(item)) for item in resolve(host)]


def validate_scope_document(
    rules: ScopeRules,
    settings: Settings,
) -> None:
    """Reject public, unspecified, or overly broad registration input."""
    if not rules.allowed_targets:
        raise ScopeRegistrationError("at least one allowed target is required")
    lab = ip_network(settings.lab_cidr, strict=True)
    for spec in [*rules.allowed_targets, *rules.exclusions]:
        _validate_registration_spec(spec, lab, settings)
    if not rules.allowed_tools:
        raise ScopeRegistrationError("at least one allowed tool is required")
    if not rules.allowed_action_classes:
        raise ScopeRegistrationError("at least one allowed action class is required")


def _validate_registration_spec(
    spec: str, lab: IPv4Network | IPv6Network, settings: Settings
) -> None:
    if not spec or spec.strip() != spec:
        raise ScopeRegistrationError("scope entries must be non-empty and trimmed")
    network = _parse_network(spec) if "/" in spec else None
    if network is not None:
        if str(network.network_address) in {"0.0.0.0", "::"} and network.prefixlen == 0:
            raise ScopeRegistrationError("0.0.0.0/0 and equivalent ranges are not allowed")
        if isinstance(network, IPv4Network) and network.prefixlen < MAX_PREFIX_LEN_V4:
            raise ScopeRegistrationError("IPv4 ranges larger than /16 are not allowed")
        if isinstance(network, IPv6Network) and network.prefixlen < 32:
            raise ScopeRegistrationError("IPv6 ranges larger than /32 are not allowed")
        if any(_address_blocked_special(ip_address(str(network.network_address))) for _ in [0]):
            reason = _address_blocked_special(ip_address(str(network.network_address)))
            if reason:
                raise ScopeRegistrationError(reason)
        public_net = not network.is_private and not settings.allow_public_targets
        if public_net and (
            network != lab and not network.subnet_of(lab) and not lab.subnet_of(network)
        ):
            # Allow only if entirely inside LAB_CIDR.
            if not all(
                address in lab for address in (network.network_address, network.broadcast_address)
            ):
                raise ScopeRegistrationError("public IPs/CIDRs are not inside LAB_CIDR")
        if not settings.allow_public_targets and isinstance(network, IPv4Network):
            if not network.subnet_of(lab) and network != lab:
                # Private but outside lab CIDR is still a registration of non-lab space.
                if network.is_private:
                    raise ScopeRegistrationError("CIDR is not inside LAB_CIDR")
                raise ScopeRegistrationError("public IPs/CIDRs are not inside LAB_CIDR")
        return

    if _is_ip(spec):
        address = ip_address(spec)
        reason = _address_blocked_special(address)
        if reason:
            raise ScopeRegistrationError(reason)
        if address in lab:
            return
        if _is_public_ip(address) and not settings.allow_public_targets:
            raise ScopeRegistrationError("public IPs/CIDRs are not inside LAB_CIDR")
        if not settings.allow_public_targets:
            raise ScopeRegistrationError("target is not inside LAB_CIDR")
        return

    if "://" in spec:
        host, scheme = _host_from_target(spec)
        if scheme not in {"http", "https"}:
            raise ScopeRegistrationError("URLs may only use http or https")
        if len(spec) > MAX_URL_LENGTH:
            raise ScopeRegistrationError("URL exceeds the maximum length")
        if not host:
            raise ScopeRegistrationError("URL is missing a host")
        _validate_registration_spec(host, lab, settings)
        return

    # Hostnames are stored as-is; public resolution is enforced at check_action time.
    if "/" in spec or " " in spec:
        raise ScopeRegistrationError("invalid scope target")


def register_scope(
    session: Session,
    assessment_id: str,
    rules: ScopeRules | ScopeRuleCreate,
    settings: Settings | None = None,
) -> ScopeRuleRead:
    """Validate and persist scope rules for an assessment."""
    effective = settings or get_settings()
    document = ScopeRules.model_validate(rules.model_dump())
    validate_scope_document(document, effective)
    payload = ScopeRuleCreate.model_validate(document.model_dump())
    stored = upsert_scope_rules(session, assessment_id, payload)
    append_audit_event(
        session,
        assessment_id=assessment_id,
        actor="scope-engine",
        event_type="scope.registered",
        detail={"scope_id": stored.id, "allowed_targets": stored.allowed_targets},
        outcome="recorded",
    )
    return stored


def check_action(
    session: Session,
    assessment_id: str,
    tool: str,
    target: str,
    action_class: ActionClass | str,
    args: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    resolve: Resolver | None = None,
    redirects: Sequence[str] | None = None,
    now: datetime | None = None,
) -> Decision:
    """Allow or deny a requested tool action against stored scope rules."""
    effective = settings or get_settings()
    resolver = resolve or default_resolve
    argv = list(args or [])
    try:
        stored = get_scope_rules(session, assessment_id)
    except RecordNotFound:
        decision = Decision.deny("scope is not registered", rule_id=None)
        _audit_check(session, assessment_id, tool, target, action_class, argv, decision)
        return decision

    rules = _rules_from_row(stored)
    decision = _evaluate(
        rules,
        stored.id,
        tool,
        target,
        action_class,
        argv,
        effective,
        resolver,
        redirects or [],
        now or _now(),
        session,
        assessment_id,
    )
    _audit_check(session, assessment_id, tool, target, action_class, argv, decision)
    return decision


def revalidate_at_execution(
    session: Session,
    assessment_id: str,
    tool: str,
    target: str,
    action_class: ActionClass | str,
    args: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    resolve: Resolver | None = None,
    redirects: Sequence[str] | None = None,
) -> Decision:
    """Re-resolve DNS and re-check every hop immediately before execution."""
    return check_action(
        session,
        assessment_id,
        tool,
        target,
        action_class,
        args,
        settings=settings,
        resolve=resolve,
        redirects=redirects,
    )


def _evaluate(
    rules: ScopeRules,
    rule_id: str,
    tool: str,
    target: str,
    action_class: ActionClass | str,
    args: list[str],
    settings: Settings,
    resolve: Resolver,
    redirects: Sequence[str],
    now: datetime,
    session: Session,
    assessment_id: str,
) -> Decision:
    if action_class not in rules.allowed_action_classes:
        return Decision.deny("action class is not allowlisted", rule_id=rule_id)
    if tool not in rules.allowed_tools:
        return Decision.deny("tool is not allowlisted", rule_id=rule_id)

    if rules.window_start and now < as_utc(rules.window_start):
        return Decision.deny("action is outside the allowed time window", rule_id=rule_id)
    if rules.window_end and now > as_utc(rules.window_end):
        return Decision.deny("action is outside the allowed time window", rule_id=rule_id)

    if rules.rate_limit_max and rules.rate_limit_window_seconds:
        cutoff = now.timestamp() - rules.rate_limit_window_seconds
        events = (
            session.execute(
                select(AuditEvent).where(
                    AuditEvent.assessment_id == assessment_id,
                    AuditEvent.event_type == "scope.check_action",
                    AuditEvent.outcome == "allowed",
                )
            )
            .scalars()
            .all()
        )
        recent = [event for event in events if as_utc(event.timestamp).timestamp() >= cutoff]
        if len(recent) >= rules.rate_limit_max:
            return Decision.deny("rate limit exceeded", rule_id=rule_id)

    if args:
        try:
            sanitize_args(tool, args)
        except ArgsSanitizerError as exc:
            return Decision.deny(str(exc), rule_id="args-allowlist")

    hops = [target, *redirects]
    for hop in hops:
        hop_decision = _check_single_target(rules, rule_id, hop, settings, resolve)
        if not hop_decision.allowed:
            if hop != target:
                return Decision.deny(
                    f"redirect leaving scope: {hop_decision.reason}",
                    rule_id=rule_id,
                )
            return hop_decision
    return Decision.allow("target is inside registered scope", rule_id=rule_id)


def _check_single_target(
    rules: ScopeRules,
    rule_id: str,
    target: str,
    settings: Settings,
    resolve: Resolver,
) -> Decision:
    if "://" in target:
        if len(target) > MAX_URL_LENGTH:
            return Decision.deny("URL exceeds the maximum length", rule_id=rule_id)
        host, scheme = _host_from_target(target)
        if scheme not in {"http", "https"}:
            return Decision.deny("URLs may only use http or https", rule_id=rule_id)
        if not host:
            return Decision.deny("URL is missing a host", rule_id=rule_id)
        target_host = host
    else:
        target_host = target

    try:
        ips = _iter_ips_for_target(target, resolve)
    except (ScopeRegistrationError, ValueError, OSError):
        return Decision.deny(
            "hostname could not be resolved to an in-scope address", rule_id=rule_id
        )

    lab = ip_network(settings.lab_cidr, strict=True)
    for ip_text in ips:
        address = ip_address(ip_text)
        blocked = _address_blocked_special(address)
        if blocked:
            return Decision.deny(blocked, rule_id=rule_id)
        if address not in lab and _is_public_ip(address) and not settings.allow_public_targets:
            return Decision.deny(
                "resolved address is a public IP outside LAB_CIDR", rule_id=rule_id
            )

    for spec in rules.exclusions:
        if _target_in_spec(target_host, spec, resolve) or any(
            _target_in_spec(ip_text, spec, resolve) for ip_text in ips
        ):
            return Decision.deny("target is excluded", rule_id=rule_id)

    matched = False
    for spec in rules.allowed_targets:
        if _target_in_spec(target_host, spec, resolve) or any(
            _target_in_spec(ip_text, spec, resolve) for ip_text in ips
        ):
            matched = True
            break
    if not matched:
        return Decision.deny("target is not in the allowed set", rule_id=rule_id)

    for ip_text in ips:
        address = ip_address(ip_text)
        if address not in lab and not settings.allow_public_targets:
            # Allowed list can include a hostname that resolves outside unless it also matches
            # an allowed CIDR. If it matched an allowed hostname spec, still require lab/private.
            hostname_only = any(
                not _is_ip(spec) and "/" not in spec and "://" not in spec
                for spec in rules.allowed_targets
            )
            in_allowed_cidr = any(
                _parse_network(spec) is not None and "/" in spec and address in _parse_network(spec)
                for spec in rules.allowed_targets
            )
            if not in_allowed_cidr:
                return Decision.deny("resolved address is outside scope", rule_id=rule_id)
            if hostname_only and _is_public_ip(address):
                return Decision.deny("resolved address is outside scope", rule_id=rule_id)

    return Decision.allow("target is inside registered scope", rule_id=rule_id)


def _audit_check(
    session: Session,
    assessment_id: str,
    tool: str,
    target: str,
    action_class: str,
    args: list[str],
    decision: Decision,
) -> None:
    append_audit_event(
        session,
        assessment_id=assessment_id,
        actor="scope-engine",
        event_type="scope.check_action",
        detail={
            "tool": tool,
            "target": target,
            "action_class": action_class,
            "args": args,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
        },
        outcome=decision.outcome,
    )
