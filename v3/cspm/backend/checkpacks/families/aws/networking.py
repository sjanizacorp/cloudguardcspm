"""
CloudGuard Pro CSPM v3 — AWS Checks: Networking
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

def _check_sg_no_unrestricted_ssh(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 5.2 — No security group should allow unrestricted SSH (port 22) from 0.0.0.0/0."""
    violations = []
    for rule in resource.get("ip_permissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        if not (from_port <= 22 <= to_port):
            continue
        for cidr in rule.get("IpRanges", []):
            if cidr.get("CidrIp") in ("0.0.0.0/0",):
                violations.append({"cidr": cidr.get("CidrIp"), "port": 22})
        for cidr6 in rule.get("Ipv6Ranges", []):
            if cidr6.get("CidrIpv6") in ("::/0",):
                violations.append({"cidr": cidr6.get("CidrIpv6"), "port": 22})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="aws-ec2-001",
    name="Security Groups: No Unrestricted SSH Access",
    family="Networking",
    provider="aws",
    service="ec2",
    resource_type="security_group",
    severity="critical",
    description="Security groups must not allow unrestricted inbound access on port 22 (SSH) from 0.0.0.0/0 or ::/0.",
    remediation="Edit the security group inbound rules to restrict SSH access to specific trusted IP ranges only. Remove any rules allowing 0.0.0.0/0 or ::/0 on port 22.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "5.2"}],
    func=_check_sg_no_unrestricted_ssh,
))

def _check_sg_no_unrestricted_rdp(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 5.3 — No security group should allow unrestricted RDP (port 3389)."""
    violations = []
    for rule in resource.get("ip_permissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        if not (from_port <= 3389 <= to_port):
            continue
        for cidr in rule.get("IpRanges", []):
            if cidr.get("CidrIp") in ("0.0.0.0/0",):
                violations.append({"cidr": cidr.get("CidrIp"), "port": 3389})
    return len(violations) == 0, {"violations": violations}

register_check(CheckMeta(
    check_id="aws-ec2-002",
    name="Security Groups: No Unrestricted RDP Access",
    family="Networking",
    provider="aws",
    service="ec2",
    resource_type="security_group",
    severity="critical",
    description="Security groups must not allow unrestricted inbound access on port 3389 (RDP) from 0.0.0.0/0.",
    remediation="Edit security group rules to restrict RDP access to specific management IP ranges. Remove 0.0.0.0/0 entries on port 3389.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "5.3"}],
    func=_check_sg_no_unrestricted_rdp,
))

def _check_vpc_flow_logs(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """CIS 3.9 — VPC flow logging must be enabled for all VPCs."""
    flow_logs = resource.get("flow_logs", [])
    active = [fl for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"]
    return len(active) > 0, {"active_flow_logs": len(active), "total_flow_logs": len(flow_logs)}

register_check(CheckMeta(
    check_id="aws-vpc-001",
    name="VPC Flow Logs Enabled",
    family="Networking",
    provider="aws",
    service="vpc",
    resource_type="vpc",
    severity="medium",
    description="VPC flow logs capture IP traffic information for network interface monitoring, security analysis, and troubleshooting.",
    remediation="Enable VPC flow logs: VPC console > Your VPCs > Select VPC > Flow logs > Create flow log. Send to CloudWatch Logs or S3.",
    source_type="benchmark",
    source_vendor="CIS",
    source_product=_SRC_CIS,
    source_url=_SRC_CIS_URL,
    source_version="1.5.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS AWS 1.5", "control_id": "3.9"}],
    func=_check_vpc_flow_logs,
))
