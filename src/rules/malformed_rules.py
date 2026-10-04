"""Malformed / protocol-violation rules: R03, R05."""
from __future__ import annotations

from src.rules.policy_loader import ServicePolicy
from src.utils.constants import DEFAULT_KEY_SHARE_BOUNDS
from src.utils.schemas import RuleViolation, TLSSessionRecord


def check_r03_group_not_offered(session: TLSSessionRecord, policy: ServicePolicy) -> RuleViolation | None:
    """R03: server-selected group was not offered by the client."""
    if session.selected_group is None or not session.offered_groups:
        return None
    if session.selected_group not in session.offered_groups:
        return RuleViolation(
            rule_id="R03",
            description=(
                f"Server selected group {session.selected_group!r} which the client "
                f"never offered {session.offered_groups!r}."
            ),
            severity="critical",
            evidence={
                "selected_group": session.selected_group,
                "offered_groups": session.offered_groups,
            },
        )
    return None


def check_r05_malformed_key_share(session: TLSSessionRecord, policy: ServicePolicy) -> RuleViolation | None:
    """R05: key-share length malformed or outside expected bounds."""
    if session.selected_group is None or session.key_share_length is None:
        return None

    bounds = policy.key_share_bounds.get(session.selected_group)
    if bounds is not None:
        min_bytes, max_bytes = bounds.min_bytes, bounds.max_bytes
    else:
        default = DEFAULT_KEY_SHARE_BOUNDS.get(session.selected_group.lower())
        if default is None:
            return None  # no known bounds for this group; can't evaluate
        min_bytes, max_bytes = default

    if not (min_bytes <= session.key_share_length <= max_bytes):
        return RuleViolation(
            rule_id="R05",
            description=(
                f"Key-share length {session.key_share_length} bytes for group "
                f"{session.selected_group!r} is outside expected bounds "
                f"[{min_bytes}, {max_bytes}]."
            ),
            severity="high",
            evidence={
                "selected_group": session.selected_group,
                "key_share_length": session.key_share_length,
                "expected_min_bytes": min_bytes,
                "expected_max_bytes": max_bytes,
            },
        )
    return None