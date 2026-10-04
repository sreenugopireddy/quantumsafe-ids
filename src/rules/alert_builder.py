"""Builds the project's alert JSON (see ALERT FORMAT spec) from a TLS
session record and the violations evaluate_session() found for it.

Classification mapping (rule-only, Phase 2):
  R03, R05      -> malformed_handshake (label 4) [takes precedence]
  R01, R02, R04 -> downgrade_violation (label 2)
  no violations -> benign_hybrid_pqc if an allowlisted PQC group was
                   selected, else benign_classical

Rule-only confidence is deterministic (1.0 triggered / 0.0 clean); the
fusion layer will later combine this with tabular/sequence model scores.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from src.parsers.session_aggregator import SourceWindowStats
from src.rules.policy_loader import ServicePolicy
from src.utils.constants import Label
from src.utils.schemas import Alert, RuleViolation, TLSSessionRecord
_EXHAUSTION_RULES = {"R06", "R07", "R08"}
_DOWNGRADE_RULES = {"R01", "R02", "R04"}
_MALFORMED_RULES = {"R03", "R05"}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _classify(violations: list[RuleViolation], session: TLSSessionRecord, policy: ServicePolicy) -> Label:
    triggered = {v.rule_id for v in violations}
    if triggered & _MALFORMED_RULES:
        return Label.MALFORMED_HANDSHAKE
    if triggered & _DOWNGRADE_RULES:
        return Label.DOWNGRADE_VIOLATION
    if session.selected_group and session.selected_group in policy.allowed_key_exchange_groups:
        return Label.BENIGN_HYBRID_PQC
    return Label.BENIGN_CLASSICAL


def _overall_severity(violations: list[RuleViolation]) -> str:
    if not violations:
        return "low"
    return max((v.severity for v in violations), key=lambda s: _SEVERITY_RANK.get(s, 0))


def _recommendation(classification: Label) -> str:
    if classification == Label.MALFORMED_HANDSHAKE:
        return "Quarantine source and inspect handshake capture; possible tampering or buggy client."
    if classification == Label.DOWNGRADE_VIOLATION:
        return "Block or renegotiate session; verify client and server PQC configuration against policy."
    return "No action required; session complies with configured PQC policy."


def build_alert(session: TLSSessionRecord, violations: list[RuleViolation], policy: ServicePolicy) -> Alert:
    classification = _classify(violations, session, policy)
    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        source_ip=session.source_ip,
        destination_ip=session.destination_ip,
        destination_service=session.destination_service,
        classification=classification.name.lower(),
        severity=_overall_severity(violations),
        confidence=1.0 if violations else 0.0,
        rules_triggered=[v.rule_id for v in violations],
        model_scores={},
        evidence={v.rule_id: v.evidence for v in violations},
        recommendation=_recommendation(classification),
    )
def build_window_alert(
    stats: SourceWindowStats, violations: list[RuleViolation], policy: ServicePolicy
) -> Alert:
    """Build an Alert for a source-IP time window evaluated against
    R06-R08. Unlike build_alert() (single-session), there is no single
    destination_ip or single session's timestamp to report - policy.hostname
    is used as destination_service, destination_ip is left as the
    window's target service hostname since a window may span multiple
    connections to the same logical service, and the alert timestamp is
    the window's end time.
    """
    triggered = {v.rule_id for v in violations}
    classification = Label.HANDSHAKE_EXHAUSTION if (triggered & _EXHAUSTION_RULES) else None

    severity = _overall_severity(violations)
    classification_name = (
        classification.name.lower() if classification is not None else Label.BENIGN_CLASSICAL.name.lower()
    )
    recommendation = (
        "Rate-limit or temporarily block source IP; investigate for handshake-exhaustion attack."
        if classification is not None
        else "No action required; source is within configured rate limits for this window."
    )

    return Alert(
        alert_id=str(uuid.uuid4()),
        timestamp=stats.window_end,
        source_ip=stats.source_ip,
        destination_ip=policy.hostname,
        destination_service=policy.hostname,
        classification=classification_name,
        severity=severity,
        confidence=1.0 if violations else 0.0,
        rules_triggered=[v.rule_id for v in violations],
        model_scores={},
        evidence={v.rule_id: v.evidence for v in violations},
        recommendation=recommendation,
    )