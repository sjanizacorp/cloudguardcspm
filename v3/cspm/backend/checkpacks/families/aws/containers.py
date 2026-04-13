"""
CloudGuard Pro CSPM v3 — AWS Checks: Containers & Kubernetes
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

def _check_eks_private_endpoint(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """EKS cluster API endpoint should not be publicly accessible."""
    access = resource.get("resourcesVpcConfig", {})
    endpoint_public = access.get("endpointPublicAccess", True)
    endpoint_private = access.get("endpointPrivateAccess", False)
    # Best practice: private enabled, public disabled or restricted
    public_cidrs = access.get("publicAccessCidrs", ["0.0.0.0/0"])
    unrestricted_public = endpoint_public and "0.0.0.0/0" in public_cidrs
    passed = not unrestricted_public
    return passed, {
        "endpoint_public_access": endpoint_public,
        "endpoint_private_access": endpoint_private,
        "public_access_cidrs": public_cidrs,
    }

register_check(CheckMeta(
    check_id="aws-eks-001",
    name="EKS Cluster API Endpoint Not Unrestricted Public",
    family="Containers & Kubernetes",
    provider="aws",
    service="eks",
    resource_type="cluster",
    severity="high",
    description="EKS cluster Kubernetes API server endpoint should not be accessible from 0.0.0.0/0. Restrict to known CIDRs or disable public access entirely.",
    remediation="EKS console > Cluster > Networking > Manage networking: Disable public endpoint or restrict publicAccessCidrs to known IP ranges. Enable private endpoint.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    compliance_mappings=[{"framework": "CIS EKS Benchmark", "control_id": "3.1.1"}],
    func=_check_eks_private_endpoint,
))

def _check_ecr_image_scan_on_push(resource: Dict[str, Any]) -> Tuple[bool, Dict]:
    """FSBP ECR.1 — ECR repository must have scan-on-push enabled."""
    scan = resource.get("imageScanningConfiguration", {})
    scan_on_push = scan.get("scanOnPush", False)
    return scan_on_push, {"scan_on_push": scan_on_push}

register_check(CheckMeta(
    check_id="aws-ecr-001",
    name="ECR Repository Scan on Push Enabled",
    family="Containers & Kubernetes",
    provider="aws",
    service="ecr",
    resource_type="repository",
    severity="medium",
    description="ECR repositories should have image scanning on push enabled to detect known vulnerabilities in container images at upload time.",
    remediation="Enable scan on push: ECR console > Repository > Edit > Scan settings > Enable scan on push.",
    source_type="vendor",
    source_vendor="AWS",
    source_product=_SRC_FSBP,
    source_url=_SRC_FSBP_URL,
    source_version="1.0",
    source_retrieved=_RETRIEVED,
    func=_check_ecr_image_scan_on_push,
))
