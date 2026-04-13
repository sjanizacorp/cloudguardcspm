"""
CloudGuard Pro CSPM v3 — AWS Checks: Identity & Access
Aniza Corp | Shahryar Jahangir

Source: CIS AWS Foundations 1.5.0 + AWS FSBP
Family file — replace this file to update this specific check family.
Custom checks go in: backend/custom_checks/store/
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from backend.check_engine.engine import CheckMeta, CheckResult, register_check

_SRC_CIS = "CIS Amazon Web Services Foundations Benchmark v1.5.0"
_SRC_CIS_URL = "https://www.cisecurity.org/benchmark/amazon_web_services"
_SRC_FSBP = "AWS Foundational Security Best Practices"
_SRC_FSBP_URL = "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html"
_RETRIEVED = "2024-01-15"

def _check_iam_root_mfa(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.5 — Ensure MFA is enabled for the root account."""
    has_mfa = resource.get("account_mfa_enabled", False)
    return has_mfa, {"account_mfa_enabled": has_mfa}

register_check(CheckMeta(
    check_id="aws-iam-001",
    name="Root Account MFA Enabled",
    family="Identity & Access",
    provider="aws",
    service="iam",
    resource_type="account_summary",
    severity="critical",
    description="The root account has unrestricted access to all AWS resources. MFA must be enabled to protect against unauthorized access.",
    remediation="Enable MFA on the root account via the IAM console > Security credentials > Assign MFA device. Use a hardware MFA device for root.",
    rationale="Root account compromise gives complete control of the AWS environment.",
    impact="Root account takeover leads to full environment compromise.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    license_notes="CIS Benchmark — mapping reference only.",
    normalization_confidence="high",
    logic_explanation="Checks AccountSummary.AccountMFAEnabled == 1 from IAM GetAccountSummary API call.",
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "1.5"},
        {"framework": "NIST CSF", "control_id": "PR.AC-7"},
        {"framework": "SOC 2", "control_id": "CC6.1"},
    ],
    test_cases=[
        {"input": {"account_mfa_enabled": True}, "expected_pass": True},
        {"input": {"account_mfa_enabled": False}, "expected_pass": False},
    ],
    sample_payload={"account_mfa_enabled": False, "account_id": "123456789012"},
    func=_check_iam_root_mfa,
))

def _check_iam_password_policy(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.8–1.14 — IAM password policy checks."""
    policy = resource.get("password_policy", {})
    issues = []
    if not policy.get("RequireUppercaseCharacters", False):
        issues.append("no_uppercase_required")
    if not policy.get("RequireLowercaseCharacters", False):
        issues.append("no_lowercase_required")
    if not policy.get("RequireNumbers", False):
        issues.append("no_numbers_required")
    if not policy.get("RequireSymbols", False):
        issues.append("no_symbols_required")
    if policy.get("MinimumPasswordLength", 0) < 14:
        issues.append("min_length_too_short")
    if policy.get("PasswordReusePrevention", 0) < 24:
        issues.append("password_reuse_too_low")
    if policy.get("MaxPasswordAge", 999) > 90:
        issues.append("max_age_too_high")
    passed = len(issues) == 0
    return passed, {"issues": issues, "policy": policy}

register_check(CheckMeta(
    check_id="aws-iam-002",
    name="IAM Password Policy Meets Minimum Requirements",
    family="Identity & Access",
    provider="aws",
    service="iam",
    resource_type="password_policy",
    severity="high",
    description="The IAM account password policy must enforce strong password requirements: uppercase, lowercase, numbers, symbols, minimum 14 chars, max age 90 days, reuse prevention 24.",
    remediation="Update the IAM account password policy via IAM console > Account settings. Set minimum length 14, require complexity, max age 90, reuse prevention 24.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "1.8"},
        {"framework": "NIST CSF", "control_id": "PR.AC-1"},
    ],
    test_cases=[
        {"input": {"password_policy": {"RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True, "RequireNumbers": True, "RequireSymbols": True, "MinimumPasswordLength": 14, "PasswordReusePrevention": 24, "MaxPasswordAge": 90}}, "expected_pass": True},
        {"input": {"password_policy": {}}, "expected_pass": False},
    ],
    func=_check_iam_password_policy,
))

def _check_iam_no_root_access_keys(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.4 — Root account must not have active access keys."""
    has_keys = resource.get("root_access_key_active", False)
    return not has_keys, {"root_access_key_active": has_keys}

register_check(CheckMeta(
    check_id="aws-iam-003",
    name="Root Account Has No Active Access Keys",
    family="Identity & Access",
    provider="aws",
    service="iam",
    resource_type="account_summary",
    severity="critical",
    description="The root account must not have active access keys. Access keys for root give programmatic full access to the account.",
    remediation="Delete root access keys via IAM console > Security credentials. Use IAM users with least-privilege policies instead.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "1.4"}],
    test_cases=[
        {"input": {"root_access_key_active": False}, "expected_pass": True},
        {"input": {"root_access_key_active": True}, "expected_pass": False},
    ],
    func=_check_iam_no_root_access_keys,
))
