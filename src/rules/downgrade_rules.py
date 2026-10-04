"""Downgrade / policy-violation rules: R01, R02, R04."""
from __future__ import annotations

from src.rules.policy_loader import ServicePolicy
from src.utils.schemas import RuleViolation, TLSSessionRecord

_TLS_VERSION_ORDER = {"TLSv1.0": 0, "TLSv1.1": 1, "TLSv1.2": 2, "TLSv1.3": 3}


def _version_rank(version: str) -> int:
    return _TLS_VERSION_ORDER.get(version, -1)


def check_r01_min_tls_version(session: TLSSessionRecord, policy: ServicePolicy) -> RuleViolation | None:
    """R01: negotiated TLS version lower than the configured minimum."""
    if _version_rank(session.tls_version) < _version_rank(policy.minimum_tls_version):
        return RuleViolation(
            rule_id="R01",
            description=(
                f"Negotiated TLS version {session.tls_version!r} is below the configured "
                f"minimum {policy.minimum_tls_version!r} for {policy.hostname!r}."
            ),
            severity="high",
            evidence={
                "negotiated_tls_version": session.tls_version,
                "minimum_required": policy.minimum_tls_version,
            },
        )
    return None


def check_r02_pqc_required_classical_group(
    session: TLSSessionRecord, policy: ServicePolicy
) -> RuleViolation | None:
    """R02: PQC-required service negotiated a classical-only group."""
    if not policy.pqc_required or session.selected_group is None:
        return None
    if session.selected_group not in policy.allowed_key_exchange_groups:
        return RuleViolation(
            rule_id="R02",
            description=(
                f"Service {policy.hostname!r} requires PQC but negotiated classical-only "
                f"group {session.selected_group!r}."
            ),
            severity="critical",
            evidence={
                "selected_group": session.selected_group,
                "pqc_required": True,
                "allowed_groups": policy.allowed_key_exchange_groups,
            },
        )
    return None


def check_r04_group_not_allowlisted(
    session: TLSSessionRecord, policy: ServicePolicy
) -> RuleViolation | None:
    """R04: server-selected group is not in the service allowlist."""
    if session.selected_group is None or not policy.allowed_key_exchange_groups:
        return None
    if session.selected_group not in policy.allowed_key_exchange_groups:
        return RuleViolation(
            rule_id="R04",
            description=(
                f"Server-selected group {session.selected_group!r} is not in the "
                f"allowlist for {policy.hostname!r}."
            ),
            severity="high",
            evidence={
                "selected_group": session.selected_group,
                "allowed_groups": policy.allowed_key_exchange_groups,
            },
        )
    return None