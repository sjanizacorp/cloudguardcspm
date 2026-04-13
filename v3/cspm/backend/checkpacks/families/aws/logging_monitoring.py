"""
CloudGuard Pro CSPM v3 — AWS Checks: Logging & Monitoring
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

def _check_cloudtrail_enabled(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.1 — CloudTrail must be enabled in all regions."""
    is_multi = resource.get("IsMultiRegionTrail", False)
    is_logging = resource.get("IsLogging", False)
    include_global = resource.get("IncludeGlobalServiceEvents", False)
    passed = is_multi and is_logging and include_global
    return passed, {
        "is_multi_region": is_multi,
        "is_logging": is_logging,
        "include_global_service_events": include_global,
    }

register_check(CheckMeta(
    check_id="aws-cloudtrail-001",
    name="CloudTrail Enabled in All Regions",
    family="Logging & Monitoring",
    provider="aws",
    service="cloudtrail",
    resource_type="trail",
    severity="high",
    description="CloudTrail must be enabled as a multi-region trail that includes global service events and is actively logging.",
    remediation="Enable CloudTrail with multi-region logging: CloudTrail console > Create trail > Apply to all regions. Enable S3 server-side encryption and log file validation.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[
        {"framework": "CIS AWS 1.5", "control_id": "3.1"},
        {"framework": "NIST CSF", "control_id": "DE.CM-1"},
    ],
    func=_check_cloudtrail_enabled,
))

def _check_cloudtrail_log_validation(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.2 — CloudTrail log file validation must be enabled."""
    enabled = resource.get("LogFileValidationEnabled", False)
    return enabled, {"log_file_validation_enabled": enabled}

register_check(CheckMeta(
    check_id="aws-cloudtrail-002",
    name="CloudTrail Log File Validation Enabled",
    family="Logging & Monitoring",
    provider="aws",
    service="cloudtrail",
    resource_type="trail",
    severity="medium",
    description="CloudTrail log file validation ensures that log files have not been tampered with after delivery to S3.",
    remediation="Enable log file validation: CloudTrail console > Trail > Edit > Enable log file validation.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "3.2"}],
    func=_check_cloudtrail_log_validation,
))

def _check_cloudwatch_root_usage_alarm(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 1.7 — Alarm must exist for root account usage."""
    has_alarm = resource.get("has_root_usage_alarm", False)
    return has_alarm, {"has_root_usage_alarm": has_alarm}

register_check(CheckMeta(
    check_id="aws-cloudwatch-001",
    name="CloudWatch Alarm for Root Account Usage",
    family="Logging & Monitoring",
    provider="aws",
    service="cloudwatch",
    resource_type="alarm_config",
    severity="medium",
    description="A CloudWatch alarm should exist that triggers on root account API usage to detect unauthorized root account activity.",
    remediation="Create a CloudWatch metric filter on CloudTrail logs for root user activity and set an alarm with SNS notification.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "1.7"}],
    func=_check_cloudwatch_root_usage_alarm,
))
