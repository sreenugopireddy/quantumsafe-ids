"""Unit tests for the Phase 2 policy loader and rule engine (R01-R05).
Uses synthetic TLSSessionRecord instances - no lab containers required.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.rules.alert_builder import build_alert
from src.rules.policy_loader import PQCPolicyConfig, ServicePolicy, load_policy
from src.rules.rule_engine import UnknownServiceError, evaluate_session
from src.utils.constants import Label
from src.utils.schemas import TLSSessionRecord


@pytest.fixture
def pqc_policy() -> ServicePolicy:
    return ServicePolicy(
        hostname="pqc-api.lab.local",
        minimum_tls_version="TLSv1.3",
        pqc_required=True,
        allowed_key_exchange_groups=["X25519MLKEM768"],
        allow_classical_fallback=False,
        key_share_bounds={"X25519MLKEM768": {"min_bytes": 1216, "max_bytes": 1216}},
    )


@pytest.fixture
def classical_policy() -> ServicePolicy:
    return ServicePolicy(
        hostname="classical-api.lab.local",
        minimum_tls_version="TLSv1.2",
        pqc_required=False,
        allowed_key_exchange_groups=["x25519", "secp256r1"],
        allow_classical_fallback=True,
    )


@pytest.fixture
def policy_config(pqc_policy, classical_policy) -> PQCPolicyConfig:
    return PQCPolicyConfig(services={"pqc_api": pqc_policy, "classical_api": classical_policy})


def _session(**overrides) -> TLSSessionRecord:
    base = dict(
        session_id="sess-1",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.100",
        destination_service="pqc-api.lab.local",
        tls_version="TLSv1.3",
        offered_groups=["X25519MLKEM768", "x25519"],
        selected_group="X25519MLKEM768",
        key_share_length=1216,
    )
    base.update(overrides)
    return TLSSessionRecord(**base)


# --- policy_loader ---

def test_load_policy_from_yaml(tmp_path: Path):
    yaml_text = textwrap.dedent("""
        services:
          pqc_api:
            hostname: "pqc-api.lab.local"
            minimum_tls_version: "TLSv1.3"
            pqc_required: true
            allowed_key_exchange_groups:
              - "X25519MLKEM768"
            allow_classical_fallback: false
    """)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml_text)

    config = load_policy(path)
    service = config.get_service("pqc-api.lab.local")
    assert service is not None
    assert service.pqc_required is True
    assert service.allowed_key_exchange_groups == ["X25519MLKEM768"]


def test_load_policy_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "does_not_exist.yaml")


def test_key_share_bounds_rejects_max_below_min():
    with pytest.raises(ValidationError):
        ServicePolicy(
            hostname="bad.lab.local",
            key_share_bounds={"x25519": {"min_bytes": 100, "max_bytes": 10}},
        )


# --- R01 ---

def test_r01_flags_tls_version_below_minimum(policy_config):
    violations = evaluate_session(_session(tls_version="TLSv1.2"), policy_config)
    assert "R01" in {v.rule_id for v in violations}


def test_r01_passes_at_minimum_version(policy_config):
    violations = evaluate_session(_session(tls_version="TLSv1.3"), policy_config)
    assert "R01" not in {v.rule_id for v in violations}


# --- R02 ---

def test_r02_flags_pqc_required_service_negotiating_classical_group(policy_config):
    session = _session(selected_group="x25519", offered_groups=["X25519MLKEM768", "x25519"])
    violations = evaluate_session(session, policy_config)
    assert "R02" in {v.rule_id for v in violations}


def test_r02_passes_when_pqc_group_negotiated(policy_config):
    violations = evaluate_session(_session(), policy_config)
    assert "R02" not in {v.rule_id for v in violations}


def test_r02_not_evaluated_for_non_pqc_required_service(policy_config):
    session = _session(
        destination_service="classical-api.lab.local",
        selected_group="x25519",
        offered_groups=["x25519"],
        key_share_length=32,
    )
    violations = evaluate_session(session, policy_config)
    assert "R02" not in {v.rule_id for v in violations}


# --- R03 ---

def test_r03_flags_group_server_selected_but_client_never_offered(policy_config):
    session = _session(offered_groups=["x25519"], selected_group="X25519MLKEM768")
    violations = evaluate_session(session, policy_config)
    assert "R03" in {v.rule_id for v in violations}


def test_r03_passes_when_selected_group_was_offered(policy_config):
    violations = evaluate_session(_session(), policy_config)
    assert "R03" not in {v.rule_id for v in violations}


# --- R04 ---

def test_r04_flags_group_outside_allowlist(policy_config):
    session = _session(
        selected_group="prime256v1",
        offered_groups=["X25519MLKEM768", "prime256v1"],
        key_share_length=65,
    )
    violations = evaluate_session(session, policy_config)
    assert "R04" in {v.rule_id for v in violations}


def test_r04_passes_for_allowlisted_group(policy_config):
    violations = evaluate_session(_session(), policy_config)
    assert "R04" not in {v.rule_id for v in violations}


# --- R05 ---

def test_r05_flags_malformed_key_share_length(policy_config):
    violations = evaluate_session(_session(key_share_length=64), policy_config)
    assert "R05" in {v.rule_id for v in violations}


def test_r05_passes_for_correct_key_share_length(policy_config):
    violations = evaluate_session(_session(), policy_config)
    assert "R05" not in {v.rule_id for v in violations}


def test_r05_skipped_when_no_known_bounds(policy_config):
    session = _session(
        destination_service="classical-api.lab.local",
        selected_group="unknown-group",
        offered_groups=["unknown-group"],
        key_share_length=999999,
    )
    violations = evaluate_session(session, policy_config)
    assert "R05" not in {v.rule_id for v in violations}


# --- unknown service ---

def test_evaluate_session_raises_for_unknown_service(policy_config):
    with pytest.raises(UnknownServiceError):
        evaluate_session(_session(destination_service="unlisted.lab.local"), policy_config)


# --- alert_builder ---

def test_alert_builder_classifies_clean_pqc_session_as_benign_hybrid_pqc(policy_config, pqc_policy):
    session = _session()
    violations = evaluate_session(session, policy_config)
    alert = build_alert(session, violations, pqc_policy)
    assert alert.classification == Label.BENIGN_HYBRID_PQC.name.lower()
    assert alert.severity == "low"
    assert alert.rules_triggered == []


def test_alert_builder_classifies_downgrade_violation(policy_config, pqc_policy):
    session = _session(selected_group="x25519", offered_groups=["X25519MLKEM768", "x25519"], key_share_length=32)
    violations = evaluate_session(session, policy_config)
    alert = build_alert(session, violations, pqc_policy)
    assert alert.classification == Label.DOWNGRADE_VIOLATION.name.lower()
    assert "R02" in alert.rules_triggered
    assert alert.confidence == 1.0


def test_alert_builder_classifies_malformed_handshake_over_downgrade(policy_config, pqc_policy):
    session = _session(offered_groups=["x25519"], selected_group="X25519MLKEM768")
    violations = evaluate_session(session, policy_config)
    alert = build_alert(session, violations, pqc_policy)
    assert alert.classification == Label.MALFORMED_HANDSHAKE.name.lower()
    assert "R03" in alert.rules_triggered


def test_alert_json_schema_fields(policy_config, pqc_policy):
    session = _session(selected_group="x25519", offered_groups=["X25519MLKEM768", "x25519"], key_share_length=32)
    violations = evaluate_session(session, policy_config)
    alert = build_alert(session, violations, pqc_policy)
    payload = alert.model_dump(mode="json")
    for field in (
        "alert_id", "timestamp", "source_ip", "destination_ip", "destination_service",
        "classification", "severity", "confidence", "rules_triggered", "model_scores",
        "evidence", "recommendation",
    ):
        assert field in payload