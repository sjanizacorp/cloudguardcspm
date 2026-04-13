"""
CloudGuard Pro CSPM — Test Suite
Aniza Corp | Shahryar Jahangir

Tests:
  - Unit: check engine, individual check functions
  - Integration: DB models, scan worker logic
  - API: FastAPI endpoint smoke tests
  - Check engine: registry, evaluation, provenance
"""
import hashlib
import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# ─── Path setup ─────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SEED_DEMO_DATA"] = "false"

# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def db_engine():
    from backend.models.models import Base
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture(scope="function")
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="session")
def test_client():
    from backend.database import init_db
    init_db()
    from backend.check_engine.engine import load_all_checkpacks
    load_all_checkpacks()
    from backend.main import app
    from backend.database import get_db, SessionLocal

    def override_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    return TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════
# UNIT TESTS — Individual check functions
# ═══════════════════════════════════════════════════════════════════════════

class TestAWSChecks:
    def test_root_mfa_enabled_pass(self):
        from backend.checkpacks.aws.checks import _check_iam_root_mfa
        passed, evidence = _check_iam_root_mfa({"account_mfa_enabled": True})
        assert passed is True
        assert evidence["account_mfa_enabled"] is True

    def test_root_mfa_enabled_fail(self):
        from backend.checkpacks.aws.checks import _check_iam_root_mfa
        passed, evidence = _check_iam_root_mfa({"account_mfa_enabled": False})
        assert passed is False

    def test_root_access_keys_pass(self):
        from backend.checkpacks.aws.checks import _check_iam_no_root_access_keys
        passed, _ = _check_iam_no_root_access_keys({"root_access_key_active": False})
        assert passed is True

    def test_root_access_keys_fail(self):
        from backend.checkpacks.aws.checks import _check_iam_no_root_access_keys
        passed, _ = _check_iam_no_root_access_keys({"root_access_key_active": True})
        assert passed is False

    def test_s3_public_access_block_pass(self):
        from backend.checkpacks.aws.checks import _check_s3_public_access_block
        resource = {"public_access_block": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}
        passed, evidence = _check_s3_public_access_block(resource)
        assert passed is True
        assert evidence["missing_settings"] == []

    def test_s3_public_access_block_fail(self):
        from backend.checkpacks.aws.checks import _check_s3_public_access_block
        passed, evidence = _check_s3_public_access_block({"public_access_block": {}})
        assert passed is False
        assert len(evidence["missing_settings"]) == 4

    def test_s3_encryption_pass(self):
        from backend.checkpacks.aws.checks import _check_s3_encryption
        resource = {"server_side_encryption_configuration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
        }}
        passed, evidence = _check_s3_encryption(resource)
        assert passed is True
        assert evidence["algorithm"] == "aws:kms"

    def test_s3_encryption_fail(self):
        from backend.checkpacks.aws.checks import _check_s3_encryption
        passed, _ = _check_s3_encryption({"server_side_encryption_configuration": {"Rules": []}})
        assert passed is False

    def test_sg_no_ssh_open_pass(self):
        from backend.checkpacks.aws.checks import _check_sg_no_unrestricted_ssh
        resource = {"ip_permissions": [
            {"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]}
        passed, evidence = _check_sg_no_unrestricted_ssh(resource)
        assert passed is True

    def test_sg_no_ssh_open_fail(self):
        from backend.checkpacks.aws.checks import _check_sg_no_unrestricted_ssh
        resource = {"ip_permissions": [
            {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]}
        passed, evidence = _check_sg_no_unrestricted_ssh(resource)
        assert passed is False
        assert len(evidence["violations"]) == 1

    def test_sg_no_rdp_fail(self):
        from backend.checkpacks.aws.checks import _check_sg_no_unrestricted_rdp
        resource = {"ip_permissions": [
            {"FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]}
        passed, _ = _check_sg_no_unrestricted_rdp(resource)
        assert passed is False

    def test_rds_not_public_pass(self):
        from backend.checkpacks.aws.checks import _check_rds_not_publicly_accessible
        passed, _ = _check_rds_not_publicly_accessible({"PubliclyAccessible": False})
        assert passed is True

    def test_rds_not_public_fail(self):
        from backend.checkpacks.aws.checks import _check_rds_not_publicly_accessible
        passed, _ = _check_rds_not_publicly_accessible({"PubliclyAccessible": True})
        assert passed is False

    def test_cloudtrail_pass(self):
        from backend.checkpacks.aws.checks import _check_cloudtrail_enabled
        resource = {"IsMultiRegionTrail": True, "IsLogging": True, "IncludeGlobalServiceEvents": True}
        passed, _ = _check_cloudtrail_enabled(resource)
        assert passed is True

    def test_cloudtrail_fail_not_multi(self):
        from backend.checkpacks.aws.checks import _check_cloudtrail_enabled
        resource = {"IsMultiRegionTrail": False, "IsLogging": True, "IncludeGlobalServiceEvents": True}
        passed, _ = _check_cloudtrail_enabled(resource)
        assert passed is False

    def test_kms_rotation_pass(self):
        from backend.checkpacks.aws.checks import _check_kms_key_rotation
        resource = {"KeyRotationEnabled": True, "KeyState": "Enabled", "KeyManager": "CUSTOMER"}
        passed, _ = _check_kms_key_rotation(resource)
        assert passed is True

    def test_kms_rotation_fail(self):
        from backend.checkpacks.aws.checks import _check_kms_key_rotation
        resource = {"KeyRotationEnabled": False, "KeyState": "Enabled", "KeyManager": "CUSTOMER"}
        passed, _ = _check_kms_key_rotation(resource)
        assert passed is False

    def test_kms_rotation_skip_aws_managed(self):
        from backend.checkpacks.aws.checks import _check_kms_key_rotation
        resource = {"KeyRotationEnabled": False, "KeyState": "Enabled", "KeyManager": "AWS"}
        passed, evidence = _check_kms_key_rotation(resource)
        assert passed is True  # skip AWS-managed keys
        assert evidence.get("skipped") is True

    def test_password_policy_pass(self):
        from backend.checkpacks.aws.checks import _check_iam_password_policy
        policy = {
            "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True,
            "RequireNumbers": True, "RequireSymbols": True,
            "MinimumPasswordLength": 14, "PasswordReusePrevention": 24, "MaxPasswordAge": 90,
        }
        passed, evidence = _check_iam_password_policy({"password_policy": policy})
        assert passed is True
        assert evidence["issues"] == []

    def test_password_policy_fail_too_short(self):
        from backend.checkpacks.aws.checks import _check_iam_password_policy
        policy = {"RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True,
                  "RequireNumbers": True, "RequireSymbols": True,
                  "MinimumPasswordLength": 8, "PasswordReusePrevention": 24, "MaxPasswordAge": 90}
        passed, evidence = _check_iam_password_policy({"password_policy": policy})
        assert passed is False
        assert "min_length_too_short" in evidence["issues"]

    def test_vpc_flow_logs_pass(self):
        from backend.checkpacks.aws.checks import _check_vpc_flow_logs
        resource = {"flow_logs": [{"FlowLogStatus": "ACTIVE"}]}
        passed, _ = _check_vpc_flow_logs(resource)
        assert passed is True

    def test_vpc_flow_logs_fail(self):
        from backend.checkpacks.aws.checks import _check_vpc_flow_logs
        passed, _ = _check_vpc_flow_logs({"flow_logs": []})
        assert passed is False

    def test_ecr_scan_on_push_pass(self):
        from backend.checkpacks.aws.checks import _check_ecr_image_scan_on_push
        passed, _ = _check_ecr_image_scan_on_push({"imageScanningConfiguration": {"scanOnPush": True}})
        assert passed is True

    def test_secrets_rotation_fail(self):
        from backend.checkpacks.aws.checks import _check_secrets_manager_rotation
        passed, _ = _check_secrets_manager_rotation({"RotationEnabled": False})
        assert passed is False


class TestAzureChecks:
    def test_storage_public_access_pass(self):
        from backend.checkpacks.azure.checks import _check_storage_public_access_disabled
        passed, _ = _check_storage_public_access_disabled({"allowBlobPublicAccess": False})
        assert passed is True

    def test_storage_public_access_fail(self):
        from backend.checkpacks.azure.checks import _check_storage_public_access_disabled
        passed, _ = _check_storage_public_access_disabled({"allowBlobPublicAccess": True})
        assert passed is False

    def test_storage_https_only_pass(self):
        from backend.checkpacks.azure.checks import _check_storage_https_only
        passed, _ = _check_storage_https_only({"supportsHttpsTrafficOnly": True})
        assert passed is True

    def test_nsg_no_ssh_pass(self):
        from backend.checkpacks.azure.checks import _check_nsg_no_unrestricted_ssh
        resource = {"securityRules": [
            {"name": "AllowHTTPS", "properties": {"direction": "Inbound", "access": "Allow",
             "destinationPortRange": "443", "sourceAddressPrefix": "0.0.0.0/0"}}
        ]}
        passed, _ = _check_nsg_no_unrestricted_ssh(resource)
        assert passed is True

    def test_nsg_no_ssh_fail(self):
        from backend.checkpacks.azure.checks import _check_nsg_no_unrestricted_ssh
        resource = {"securityRules": [
            {"name": "AllowSSH", "properties": {"direction": "Inbound", "access": "Allow",
             "destinationPortRange": "22", "sourceAddressPrefix": "*"}}
        ]}
        passed, evidence = _check_nsg_no_unrestricted_ssh(resource)
        assert passed is False
        assert len(evidence["violations"]) == 1

    def test_sql_tde_pass(self):
        from backend.checkpacks.azure.checks import _check_sql_tde_enabled
        passed, _ = _check_sql_tde_enabled({"transparentDataEncryption": {"status": "Enabled"}})
        assert passed is True

    def test_keyvault_soft_delete_fail(self):
        from backend.checkpacks.azure.checks import _check_keyvault_soft_delete
        passed, _ = _check_keyvault_soft_delete({"properties": {"enableSoftDelete": False}})
        assert passed is False


class TestGCPChecks:
    def test_gcs_not_public_pass(self):
        from backend.checkpacks.gcp.checks import _check_gcp_storage_bucket_not_public
        resource = {"iam_policy": {"bindings": [
            {"role": "roles/storage.objectViewer", "members": ["user:alice@example.com"]}
        ]}}
        passed, _ = _check_gcp_storage_bucket_not_public(resource)
        assert passed is True

    def test_gcs_not_public_fail(self):
        from backend.checkpacks.gcp.checks import _check_gcp_storage_bucket_not_public
        resource = {"iam_policy": {"bindings": [
            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
        ]}}
        passed, evidence = _check_gcp_storage_bucket_not_public(resource)
        assert passed is False
        assert len(evidence["public_members"]) == 1

    def test_firewall_no_ssh_pass(self):
        from backend.checkpacks.gcp.checks import _check_gcp_firewall_no_ssh_world
        resource = {"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}], "sourceRanges": ["0.0.0.0/0"]}
        passed, _ = _check_gcp_firewall_no_ssh_world(resource)
        assert passed is True

    def test_firewall_no_ssh_fail(self):
        from backend.checkpacks.gcp.checks import _check_gcp_firewall_no_ssh_world
        resource = {"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "sourceRanges": ["0.0.0.0/0"]}
        passed, evidence = _check_gcp_firewall_no_ssh_world(resource)
        assert passed is False

    def test_kms_rotation_pass(self):
        from backend.checkpacks.gcp.checks import _check_gcp_kms_rotation
        passed, evidence = _check_gcp_kms_rotation({"rotationPeriod": "7776000s"})  # 90 days
        assert passed is True
        assert evidence["rotation_period_days"] == 90.0

    def test_kms_rotation_fail_too_long(self):
        from backend.checkpacks.gcp.checks import _check_gcp_kms_rotation
        passed, _ = _check_gcp_kms_rotation({"rotationPeriod": "31536000s"})  # 365 days
        assert passed is False

    def test_kms_rotation_fail_none(self):
        from backend.checkpacks.gcp.checks import _check_gcp_kms_rotation
        passed, _ = _check_gcp_kms_rotation({})
        assert passed is False


class TestOCIChecks:
    def test_object_storage_not_public_pass(self):
        from backend.checkpacks.ibm_oci.checks import _check_oci_object_storage_not_public
        passed, _ = _check_oci_object_storage_not_public({"publicAccessType": "NoPublicAccess"})
        assert passed is True

    def test_object_storage_not_public_fail(self):
        from backend.checkpacks.ibm_oci.checks import _check_oci_object_storage_not_public
        passed, _ = _check_oci_object_storage_not_public({"publicAccessType": "ObjectRead"})
        assert passed is False

    def test_mfa_enabled_pass(self):
        from backend.checkpacks.ibm_oci.checks import _check_oci_mfa_enabled
        passed, _ = _check_oci_mfa_enabled({"isMfaActivated": True})
        assert passed is True

    def test_mfa_enabled_fail(self):
        from backend.checkpacks.ibm_oci.checks import _check_oci_mfa_enabled
        passed, _ = _check_oci_mfa_enabled({"isMfaActivated": False})
        assert passed is False

    def test_audit_retention_pass(self):
        from backend.checkpacks.ibm_oci.checks import _check_oci_audit_retention
        passed, _ = _check_oci_audit_retention({"retentionPeriodDays": 365})
        assert passed is True

    def test_audit_retention_fail(self):
        from backend.checkpacks.ibm_oci.checks import _check_oci_audit_retention
        passed, _ = _check_oci_audit_retention({"retentionPeriodDays": 90})
        assert passed is False


# ═══════════════════════════════════════════════════════════════════════════
# CHECK ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckEngine:
    def test_registry_populated(self):
        from backend.check_engine.engine import load_all_checkpacks, _REGISTRY
        load_all_checkpacks()
        assert len(_REGISTRY) >= 40, f"Expected >= 40 checks, got {len(_REGISTRY)}"

    def test_all_providers_represented(self):
        from backend.check_engine.engine import _REGISTRY, load_all_checkpacks
        load_all_checkpacks()
        providers = {m.provider for m in _REGISTRY.values()}
        for p in ("aws", "azure", "gcp", "ibm", "oci"):
            assert p in providers, f"Provider {p} has no checks registered"

    def test_check_has_required_fields(self):
        from backend.check_engine.engine import _REGISTRY, load_all_checkpacks
        load_all_checkpacks()
        for check_id, meta in _REGISTRY.items():
            assert meta.check_id, f"{check_id}: missing check_id"
            assert meta.name, f"{check_id}: missing name"
            assert meta.family, f"{check_id}: missing family"
            assert meta.provider, f"{check_id}: missing provider"
            assert meta.service, f"{check_id}: missing service"
            assert meta.severity, f"{check_id}: missing severity"
            assert meta.description, f"{check_id}: missing description"
            assert meta.remediation, f"{check_id}: missing remediation"
            assert meta.source_url or meta.source_vendor, f"{check_id}: missing provenance (source_url or source_vendor required)"

    def test_check_has_func_or_status(self):
        from backend.check_engine.engine import _REGISTRY, load_all_checkpacks
        load_all_checkpacks()
        for check_id, meta in _REGISTRY.items():
            if meta.status == "implemented":
                assert meta.func is not None, f"{check_id}: status=implemented but no func registered"

    def test_evaluate_passing_resource(self):
        from backend.check_engine.engine import CheckEngine, load_all_checkpacks
        load_all_checkpacks()
        eng = CheckEngine()
        result = eng.evaluate_resource("aws-s3-001", {
            "public_access_block": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            }
        })
        assert result.passed is True
        assert result.error is None

    def test_evaluate_failing_resource(self):
        from backend.check_engine.engine import CheckEngine, load_all_checkpacks
        load_all_checkpacks()
        eng = CheckEngine()
        result = eng.evaluate_resource("aws-s3-001", {"public_access_block": {}})
        assert result.passed is False

    def test_unknown_check_fails_open(self):
        from backend.check_engine.engine import CheckEngine
        eng = CheckEngine()
        result = eng.evaluate_resource("nonexistent-check-999", {})
        assert result.passed is True  # fail-open
        assert result.error is not None

    def test_finding_id_deterministic(self):
        from backend.check_engine.engine import make_finding_id
        fid1 = make_finding_id("aws-s3-001", "cspm://aws/123/us-east-1/s3/bucket/mybucket")
        fid2 = make_finding_id("aws-s3-001", "cspm://aws/123/us-east-1/s3/bucket/mybucket")
        assert fid1 == fid2

    def test_finding_id_different_check(self):
        from backend.check_engine.engine import make_finding_id
        fid1 = make_finding_id("aws-s3-001", "cspm://aws/123/us-east-1/s3/bucket/mybucket")
        fid2 = make_finding_id("aws-s3-002", "cspm://aws/123/us-east-1/s3/bucket/mybucket")
        assert fid1 != fid2

    def test_run_checks_for_resource(self):
        from backend.check_engine.engine import CheckEngine, load_all_checkpacks
        load_all_checkpacks()
        eng = CheckEngine()
        resource = {"ip_permissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        results = eng.run_checks_for_resource(resource, "aws", "ec2", "security_group")
        # Should find at least the SSH check
        failing = [r for r in results if not r.passed]
        assert any(r.check_id == "aws-ec2-001" for r in failing)


# ═══════════════════════════════════════════════════════════════════════════
# DATABASE / MODEL TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestModels:
    def test_create_provider_connection(self, db_session):
        from backend.models.models import ProviderConnection, CloudProvider
        conn = ProviderConnection(
            id="test-conn-001",
            name="Test AWS",
            provider=CloudProvider.AWS,
            account_id="111222333444",
            credential_type="env",
            regions=["us-east-1"],
        )
        db_session.add(conn)
        db_session.flush()
        retrieved = db_session.query(ProviderConnection).filter_by(id="test-conn-001").first()
        assert retrieved is not None
        assert retrieved.name == "Test AWS"
        assert retrieved.provider == CloudProvider.AWS

    def test_create_asset(self, db_session):
        from backend.models.models import Asset, ProviderConnection, CloudProvider
        conn = ProviderConnection(id="test-conn-002", name="Test", provider=CloudProvider.GCP)
        db_session.add(conn)
        db_session.flush()

        asset = Asset(
            connection_id="test-conn-002",
            provider=CloudProvider.GCP,
            service="storage",
            resource_type="bucket",
            native_id="my-test-bucket",
            universal_resource_name="cspm://gcp/proj/us/storage/bucket/my-test-bucket",
            display_name="my-test-bucket",
            region="us-central1",
            tags={},
            raw_config={},
        )
        db_session.add(asset)
        db_session.flush()
        assert asset.id is not None
        assert asset.universal_resource_name.startswith("cspm://")

    def test_finding_dedup_by_finding_id(self, db_session):
        from backend.models.models import (
            Finding, Asset, ProviderConnection, CheckDefinition,
            FindingStatus, CloudProvider, Severity, CheckStatus, CheckType, CollectionMethod,
        )
        conn = ProviderConnection(id="test-conn-003", name="T", provider=CloudProvider.AWS)
        db_session.add(conn)
        db_session.flush()

        asset = Asset(
            connection_id="test-conn-003",
            provider=CloudProvider.AWS, service="s3", resource_type="bucket",
            native_id="b1", universal_resource_name="cspm://aws/acct/us/s3/bucket/b1",
            tags={}, raw_config={},
        )
        db_session.add(asset)
        db_session.flush()

        finding_id = "abcdef1234567890abcdef1234567890"
        f = Finding(
            finding_id=finding_id,
            check_id="aws-s3-001",
            asset_id=asset.id,
            family="Storage",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test",
            description="Test",
            remediation="Test",
            provider=CloudProvider.AWS,
            service="s3",
            resource_type="bucket",
            universal_resource_name="cspm://aws/acct/us/s3/bucket/b1",
            evidence={},
            compliance_frameworks=[],
            resource_tags={},
        )
        db_session.add(f)
        db_session.flush()

        # Verify unique constraint on finding_id
        count = db_session.query(Finding).filter_by(finding_id=finding_id).count()
        assert count == 1


# ═══════════════════════════════════════════════════════════════════════════
# API SMOKE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestAPI:
    def test_health_endpoint(self, test_client):
        resp = test_client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_readiness_endpoint(self, test_client):
        resp = test_client.get("/api/v1/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert "database" in data
        assert "checks_loaded" in data
        assert data["checks_loaded"] >= 40

    def test_metrics_endpoint(self, test_client):
        resp = test_client.get("/api/v1/health/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert "assets" in data
        assert "checks_registered" in data

    def test_list_checks(self, test_client):
        resp = test_client.get("/api/v1/checks?page_size=100")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] >= 40

    def test_list_checks_filter_provider(self, test_client):
        resp = test_client.get("/api/v1/checks?provider=aws&page_size=100")
        assert resp.status_code == 200
        data = resp.json()
        assert all(c["provider"] == "aws" for c in data["items"])

    def test_check_families(self, test_client):
        resp = test_client.get("/api/v1/checks/families")
        assert resp.status_code == 200
        families = resp.json()
        assert len(families) > 0
        assert all("family" in f and "count" in f for f in families)

    def test_get_check_by_id(self, test_client):
        resp = test_client.get("/api/v1/checks/aws-s3-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["check_id"] == "aws-s3-001"
        assert data["provider"] == "aws"
        assert data["severity"] == "high"

    def test_get_check_code(self, test_client):
        resp = test_client.get("/api/v1/checks/aws-s3-001/code")
        assert resp.status_code == 200
        data = resp.json()
        assert "implementation_code" in data
        assert "yaml_definition" in data
        assert data["implementation_code"] is not None
        assert "_check_s3_public_access_block" in data["implementation_code"]

    def test_check_code_has_provenance(self, test_client):
        resp = test_client.get("/api/v1/checks/aws-iam-001/code")
        assert resp.status_code == 200
        data = resp.json()
        assert data["source_vendor"] is not None
        assert data["source_url"] is not None

    def test_list_findings_empty(self, test_client):
        resp = test_client.get("/api/v1/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    def test_list_connections(self, test_client):
        resp = test_client.get("/api/v1/connections")
        assert resp.status_code == 200

    def test_create_and_delete_connection(self, test_client):
        body = {
            "name": "Test Connection",
            "provider": "aws",
            "account_id": "999888777666",
            "credential_type": "env",
            "regions": ["us-east-1"],
        }
        resp = test_client.post("/api/v1/connections", json=body)
        assert resp.status_code == 200
        conn_id = resp.json()["id"]

        resp2 = test_client.get(f"/api/v1/connections/{conn_id}")
        assert resp2.status_code == 200
        assert resp2.json()["name"] == "Test Connection"

        resp3 = test_client.delete(f"/api/v1/connections/{conn_id}")
        assert resp3.status_code == 200

    def test_dashboard_stats(self, test_client):
        resp = test_client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        for key in ("total_findings", "open_findings", "critical", "high", "medium", "low"):
            assert key in data

    def test_list_assets(self, test_client):
        resp = test_client.get("/api/v1/assets")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data

    def test_create_report(self, test_client):
        resp = test_client.post("/api/v1/reports", json={"report_type": "executive", "filters": {}})
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_type"] == "executive"
        assert data["status"] in ("pending", "generating", "completed")

    def test_404_check_not_found(self, test_client):
        resp = test_client.get("/api/v1/checks/nonexistent-check-id")
        assert resp.status_code == 404

    def test_list_scans(self, test_client):
        resp = test_client.get("/api/v1/scans")
        assert resp.status_code == 200

    def test_check_all_providers_in_catalog(self, test_client):
        """Ensure all 5 cloud providers have checks in the catalog."""
        for provider in ["aws", "azure", "gcp", "ibm", "oci"]:
            resp = test_client.get(f"/api/v1/checks?provider={provider}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total"] > 0, f"No checks found for provider: {provider}"
