"""
CloudGuard Pro CSPM v3 — AWS Checks: Serverless
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

def _check_lambda_no_admin_policy(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP Lambda.1 — Lambda functions must not have admin-equivalent permissions."""
    policies = resource.get("attached_policies", [])
    admin_policies = []
    for p in policies:
        arn = p.get("PolicyArn", "")
        if arn in ("arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/PowerUserAccess"):
            admin_policies.append(arn)
        # Check inline policy documents for *:* actions
        doc = p.get("PolicyDocument", {})
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "*" in actions or "lambda:*" in actions:
                    admin_policies.append(f"inline:{stmt}")
    return len(admin_policies) == 0, {"admin_policies": admin_policies}

register_check(CheckMeta(
    check_id="aws-lambda-001",
    name="Lambda Functions Do Not Have Admin Permissions",
    family="Serverless",
    provider="aws",
    service="lambda",
    resource_type="function",
    severity="high",
    description="Lambda function execution roles must follow least privilege. Admin or wildcard policies grant excessive access.",
    remediation="Review Lambda execution role policies. Remove AdministratorAccess or wildcard Action policies. Apply minimum permissions needed for the function's purpose.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "1.22"}],
    func=_check_lambda_no_admin_policy,
))
