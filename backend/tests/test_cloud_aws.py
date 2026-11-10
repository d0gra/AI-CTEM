"""AWS posture connector exercised against moto (an in-process AWS API emulation)."""

import json

import boto3
import pytest
from moto import mock_aws

CREDS = {"access_key_id": "AKIAEXAMPLEEXAMPLE00", "secret_access_key": "test-secret-key-value"}


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        yield


def _seed():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r-long-passw0rd!")
    iam.attach_user_policy(UserName="alice", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_access_key(UserName="alice")
    trust_any = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}
    trust_ec2 = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="open-role", AssumeRolePolicyDocument=json.dumps(trust_any))
    iam.create_role(RoleName="web-app", AssumeRolePolicyDocument=json.dumps(trust_ec2))
    iam.attach_role_policy(RoleName="web-app", PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    iam.create_instance_profile(InstanceProfileName="web-app")
    iam.add_role_to_instance_profile(InstanceProfileName="web-app", RoleName="web-app")
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="acme-public-assets")
    s3.put_bucket_acl(Bucket="acme-public-assets", ACL="public-read")
    s3.create_bucket(Bucket="acme-customer-exports")
    s3.put_public_access_block(Bucket="acme-customer-exports", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="web", Description="web")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SecurityGroupIds=[sg], IamInstanceProfile={"Name": "web-app"},
                      TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-1"}]}])
    boto3.client("rds", region_name="us-east-1").create_db_instance(
        DBInstanceIdentifier="orders", DBInstanceClass="db.t3.micro", Engine="postgres", MasterUsername="x",
        MasterUserPassword="long-password-123", AllocatedStorage=20, PubliclyAccessible=True)


def test_aws_posture_end_to_end(org, drain, aws):
    _seed()
    bad = org.post("/integrations", json={"connector": "aws", "name": "bad", "config": {"regions": []}, "credentials": CREDS})
    assert bad.status_code == 422
    integration = org.ok("POST", "/integrations", json={"connector": "aws", "name": "AWS prod", "config": {"regions": ["us-east-1"]}, "credentials": CREDS})
    assert "credentials" not in integration and integration["has_credentials"] is True
    assert "test-secret-key-value" not in json.dumps(org.ok("GET", "/integrations"))
    tested = org.ok("POST", f"/integrations/{integration['id']}/test")
    assert tested["ok"] is True and tested["integration"]["health"] == "healthy"

    a = org.ok("POST", "/assessments", json={"name": "AWS posture", "kind": "aws_posture", "integration_id": integration["id"]})
    run = org.ok("POST", f"/assessments/{a['id']}/run", json={})
    drain()
    run = org.ok("GET", f"/assessment-runs/{run['id']}")
    assert run["status"] == "succeeded", run
    rules = {f["rule_id"]: f for f in org.ok("GET", "/findings?page_size=200")["items"]}
    for expected in ("aws.s3.bucket_public", "aws.iam.user_no_mfa", "aws.iam.user_admin_policy", "aws.iam.role_trusts_anyone",
                     "aws.ec2.sg_open_to_world", "aws.rds.publicly_accessible", "aws.cloudtrail.not_enabled",
                     "aws.iam.password_policy_missing"):
        assert expected in rules, f"missing {expected}: {sorted(rules)}"
    assert rules["aws.s3.bucket_public"]["severity"] == "critical" and rules["aws.iam.user_no_mfa"]["domain"] == "identity"
    buckets = {b["name"]: b for b in org.ok("GET", "/assets?type=storage")["items"]}
    assert buckets["S3 bucket acme-public-assets"]["exposure"] == "internet"
    assert buckets["S3 bucket acme-customer-exports"]["exposure"] == "private"

    # Identity graph: instance -> role -> bucket, discovered from API data, yields an attack path
    # once the instance is reachable and the export bucket is classified as sensitive.
    instance = org.ok("GET", "/assets?type=host")["items"][0]
    rels = org.ok("GET", f"/assets/{instance['id']}/relationships")
    assert any(r["type"] == "AUTHENTICATES_TO" and r["target"]["name"] == "IAM role web-app" for r in rels)
    org.ok("PATCH", f"/assets/{instance['id']}", json={"exposure": "internet"})
    org.ok("PATCH", f"/assets/{buckets['S3 bucket acme-customer-exports']['id']}", json={"data_sensitivity": "restricted"})
    org.ok("POST", "/attack-paths/compute")
    drain()
    paths = org.ok("GET", "/attack-paths")["items"]
    path = next(org.ok("GET", f"/attack-paths/{p['id']}") for p in paths if p["target_asset_id"] == buckets["S3 bucket acme-customer-exports"]["id"])
    assert [n["type"] for n in path["nodes"]] == ["host", "identity", "storage"]
    assert [e["relationship_type"] for e in path["edges"]] == ["AUTHENTICATES_TO", "HAS_PERMISSION"]
    assert path["edges"][1]["technique"] == "T1530" and path["classification"] in ("probable", "verified")
    assert any(o["type"] == "reduce_privilege" for o in path["remediation_opportunities"])

    # The default policy on cloud audit logging is evaluated against real attributes.
    policies = {p["key"]: p for p in org.ok("GET", "/policies")["items"]}
    result = org.ok("POST", f"/policies/{policies['cloud-accounts-audit-logging']['id']}/evaluate")
    assert result["status"] == "non_compliant" and result["violations"][0]["observed"]["attributes.audit_logging_enabled"] is False
    overview = org.ok("GET", "/dashboard/overview")
    assert overview["cloud"]["accounts"] == 1 and sum(overview["cloud"]["open_findings_by_severity"].values()) >= 8


def test_aws_bad_credentials_are_classified(org, monkeypatch):
    from botocore.exceptions import ClientError

    def deny(*a, **k):
        raise ClientError({"Error": {"Code": "InvalidClientTokenId", "Message": "The security token is invalid"}}, "GetCallerIdentity")

    monkeypatch.setattr("botocore.client.BaseClient._make_api_call", deny)
    integration = org.ok("POST", "/integrations", json={"connector": "aws", "name": "AWS bad", "config": {"regions": ["us-east-1"]}, "credentials": CREDS})
    tested = org.ok("POST", f"/integrations/{integration['id']}/test")
    assert tested["ok"] is False and tested["error_class"] == "auth" and tested["integration"]["health"] == "error"
    assert org.ok("GET", "/notifications")["items"][0]["event_type"] == "integration.failed"
