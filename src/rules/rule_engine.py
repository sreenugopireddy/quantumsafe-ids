"""Rule engine orchestrator: runs R01-R05 against a TLS session record.

R06-R08 (rate-based rules) need multi-session state per source IP and are
deferred to a later task - a single TLSSessionRecord isn't enough to
evaluate them.
"""
from __future__ import annotations


from src.parsers.session_aggregator import SourceWindowStats
from src.rules import downgrade_rules, exhaustion_rules, malformed_rules
from src.rules.policy_loader import PQCPolicyConfig, ServicePolicy
from src.utils.schemas import RuleViolation, TLSSessionRecord

class UnknownServiceError(Exception):
    """Raised when a session's destination_service has no matching policy."""


_RULE_CHECKS = (
    downgrade_rules.check_r01_min_tls_version,
    downgrade_rules.check_r02_pqc_required_classical_group,
    malformed_rules.check_r03_group_not_offered,
    downgrade_rules.check_r04_group_not_allowlisted,
    malformed_rules.check_r05_malformed_key_share,
)

_WINDOW_RULE_CHECKS = (
    exhaustion_rules.check_r06_handshake_rate_exceeded,
    exhaustion_rules.check_r07_failed_handshake_ratio_exceeded,
    exhaustion_rules.check_r08_rate_correlates_with_latency,
)

def evaluate_session(session: TLSSessionRecord, policy_config: PQCPolicyConfig) -> list[RuleViolation]:
    """Run all implemented rules (R01-R05) against one TLS session.

    Raises:
        UnknownServiceError: if no ServicePolicy matches session.destination_service.
    """
    policy: ServicePolicy | None = policy_config.get_service(session.destination_service)
    if policy is None:
        raise UnknownServiceError(f"No PQC policy defined for service {session.destination_service!r}")

    violations: list[RuleViolation] = []
    for check in _RULE_CHECKS:
        result = check(session, policy)
        if result is not None:
            violations.append(result)
    return violations
def evaluate_window(stats: SourceWindowStats, policy: ServicePolicy) -> list[RuleViolation]:
    """Run R06-R08 against one SourceWindowStats aggregate.

    Unlike evaluate_session(), this takes an already-resolved
    ServicePolicy directly rather than looking one up via
    PQCPolicyConfig.get_service() - a window is grouped by source_ip only
    and has no destination_service to resolve against. The caller
    (real-time/batch detector) is responsible for supplying the correct
    policy for the service this source is targeting.
    """
    violations: list[RuleViolation] = []
    for check in _WINDOW_RULE_CHECKS:
        result = check(stats, policy)
        if result is not None:
            violations.append(result)
    return violations