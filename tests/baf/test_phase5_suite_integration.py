#!/usr/bin/env python3

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = (ROOT / "tests" / "baf" / "Makefile.am").read_text(
    encoding="utf-8")
PHASE5 = (ROOT / "tests" / "baf" / "test_phase5_dual_mode_contract.py").read_text(
    encoding="utf-8")
REFERENCE = (
    ROOT / "broker-auth" / "reference-broker" / "tests" / "test_dual_mode_reference_broker.py"
).read_text(encoding="utf-8")
GATEWAY = (
    ROOT / "broker-auth" / "gateway" / "tests" / "test_gateway_contract.py"
).read_text(encoding="utf-8")
KEYCLOAK = (
    ROOT / "broker-auth" / "reference-broker" / "tests" / "test_keycloak_auth.py"
).read_text(encoding="utf-8")

# The normal Automake BAF suite must run the Phase 5 suite entry point.
assert "test_phase5_dual_mode_contract.py" in MAKEFILE

# The Phase 5 suite entry point must execute the external broker/gateway tests,
# so normal `make -C tests/baf check` covers all Phase 5 Python tests.
assert "broker-auth/reference-broker/tests/test_dual_mode_reference_broker.py" in PHASE5
assert "broker-auth/reference-broker/tests/test_keycloak_auth.py" in PHASE5
assert "broker-auth/gateway/tests/test_gateway_contract.py" in PHASE5

# Required Phase 5 coverage must be present in the referenced tests.
for required in (
    "test_issue_assertion_cli_outputs_valid_rs256_baf_token",
    "test_wrong_audience_and_target_rejected",
    "test_expired_assertion_rejected",
    "test_replayed_assertion_rejected",
    "test_missing_preferred_username_rejected_before_signing",
    "test_uid0_is_not_encoded_as_authority",
    "test_uds_skeleton_mapping_has_no_unix_authority",
):
    assert required in REFERENCE
for required in (
    "test_gateway_docs_require_rdsaad_and_forbid_overloading",
    "test_gateway_config_disables_unsafe_fallbacks",
    "test_gateway_is_outside_xrdp_core",
):
    assert required in GATEWAY
for required in (
    "test_valid_token_is_strictly_mapped",
    "test_missing_or_wrong_audience_is_rejected",
    "test_multiple_audiences_require_matching_authorized_party",
    "test_access_token_profile_is_required",
    "test_token_lifetime_is_bounded",
    "test_subject_binding_includes_issuer",
    "test_broker_adapter_enforces_role_user_mapping_and_target_policy",
):
    assert required in KEYCLOAK
