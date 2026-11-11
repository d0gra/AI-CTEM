"""AWS security posture assessment using read-only API calls.

Covers IAM, S3, EC2 security groups and instances, RDS, CloudTrail, KMS and EKS. Each service
is assessed independently: an access-denied error on one service is reported in the run
summary and does not hide results from the others.

Required permissions: the AWS managed policies `SecurityAudit` and `ViewOnlyAccess` are
sufficient. No write API is called.
"""

import json
from datetime import UTC, datetime

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, Field

from app.core.security import decrypt_secret
from app.domains.assessments.service import EngineContext, EngineSpec, register
from app.domains.assets.service import AssetSpec
from app.domains.findings.service import EvidenceInput, FindingInput
from app.integrations.base import ConnectionResult, ConnectorSpec, register_connector
from app.models import Asset
from app.workers.queue import PermanentJobError

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB",
                   6379: "Redis", 9200: "Elasticsearch", 23: "Telnet", 445: "SMB", 2375: "Docker API", 11434: "Ollama"}
ADMIN_POLICIES = {"arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/AmazonS3FullAccess",
                  "arn:aws:iam::aws:policy/PowerUserAccess", "arn:aws:iam::aws:policy/IAMFullAccess"}
MAX_KEY_AGE_DAYS = 90


class AwsConfig(BaseModel):
    regions: list[str] = Field(default=["us-east-1"], min_length=1, max_length=30)
    role_arn: str | None = Field(default=None, pattern=r"^arn:aws[a-z-]*:iam::\d{12}:role/.+$")
    external_id: str | None = None
    use_default_credentials: bool = Field(default=False, description="Use the worker's ambient AWS identity instead of stored keys")


class AwsCredentials(BaseModel):
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""


def make_session(config: AwsConfig, creds: AwsCredentials) -> boto3.Session:
    if config.use_default_credentials:
        session = boto3.Session()
    elif creds.access_key_id and creds.secret_access_key:
        session = boto3.Session(aws_access_key_id=creds.access_key_id, aws_secret_access_key=creds.secret_access_key,
                                aws_session_token=creds.session_token or None)
    else:
        raise ValueError("Provide access keys or enable use_default_credentials")
    if config.role_arn:
        params = {"RoleArn": config.role_arn, "RoleSessionName": "ctem-posture"}
        if config.external_id:
            params["ExternalId"] = config.external_id
        assumed = session.client("sts").assume_role(**params)["Credentials"]
        session = boto3.Session(aws_access_key_id=assumed["AccessKeyId"], aws_secret_access_key=assumed["SecretAccessKey"],
                                aws_session_token=assumed["SessionToken"])
    return session


def test_connection(config: AwsConfig, creds: AwsCredentials) -> ConnectionResult:
    try:
        identity = make_session(config, creds).client("sts", config=_BOTO).get_caller_identity()
        return ConnectionResult(True, f"Authenticated as {identity['Arn']}", metadata={"account": identity["Account"]})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        klass = "auth" if code in ("InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken") else (
            "permission" if "AccessDenied" in code else "unknown")
        return ConnectionResult(False, f"{code}: {exc.response.get('Error', {}).get('Message', '')}"[:400], klass)
    except (BotoCoreError, ValueError) as exc:
        return ConnectionResult(False, str(exc)[:400], "config" if isinstance(exc, ValueError) else "network")


_BOTO = BotoConfig(retries={"max_attempts": 5, "mode": "adaptive"}, connect_timeout=10, read_timeout=30)


class _Aws:
    def __init__(self, ctx: EngineContext, session: boto3.Session, account_id: str):
        self.ctx, self.session, self.account_id = ctx, session, account_id
        self.buckets: dict[str, Asset] = {}
        self.roles: dict[str, Asset] = {}
        self.privileged_roles: set[str] = set()

    def client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region, config=_BOTO)

    def finding(self, asset: Asset, rule: str, title: str, severity: str, description: str, remediation: str,
                evidence: dict, *, domain: str = "cloud", discriminator: str = "", impact: str = "") -> None:
        self.ctx.finding(FindingInput(
            asset=asset, source=self.ctx.source, rule_id=f"aws.{rule}", domain=domain, title=title, severity=severity,
            confidence="confirmed", description=description, remediation=remediation, technical_impact=impact,
            discriminator=discriminator, evidence=[EvidenceInput("config", f"AWS API response for {asset.name}", evidence)]))

    def guarded(self, label: str, fn) -> None:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            self.ctx.skip(label, f"{code}: {exc.response.get('Error', {}).get('Message', '')}"[:300])
        except BotoCoreError as exc:
            self.ctx.skip(label, str(exc)[:300])

    # --- IAM ---
    def iam(self, account: Asset) -> None:
        iam = self.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled") == 0:
            self.finding(account, "iam.root_mfa_disabled", "Root account does not have MFA enabled", "critical",
                         "The AWS account root user can sign in with a password alone.", "Enable a hardware or virtual MFA device for the root user.",
                         {"AccountMFAEnabled": 0}, domain="identity", impact="Root credentials grant unrestricted control of the account.")
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            self.finding(account, "iam.root_access_keys", "Root account has access keys", "critical",
                         "Long-lived access keys exist for the root user.", "Delete root access keys and use IAM roles.",
                         {"AccountAccessKeysPresent": summary["AccountAccessKeysPresent"]}, domain="identity")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            if policy.get("MinimumPasswordLength", 0) < 14:
                self.finding(account, "iam.password_policy_weak", "IAM password policy allows passwords shorter than 14 characters", "low",
                             "The account password policy does not meet the CIS benchmark minimum length.",
                             "Require a minimum length of 14 characters.", {"PasswordPolicy": policy}, domain="identity")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            self.finding(account, "iam.password_policy_missing", "No IAM password policy is configured", "medium",
                         "IAM users are subject only to the default password requirements.",
                         "Configure an account password policy (length >= 14, reuse prevention).", {"PasswordPolicy": None}, domain="identity")
        now = datetime.now(UTC)
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                self.ctx.checkpoint()
                name = user["UserName"]
                attached = {p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]}
                privileged = bool(attached & ADMIN_POLICIES)
                asset = self.ctx.asset(AssetSpec(type="identity", identifier=user["Arn"], name=f"IAM user {name}",
                                                 attributes={"provider": "aws", "kind": "human_or_service_user", "privileged": privileged,
                                                             "attached_policies": sorted(attached)}))
                self.ctx.link(account, asset, "CONTAINS")
                has_console = True
                try:
                    iam.get_login_profile(UserName=name)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
                    has_console = False
                if has_console and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                    self.finding(asset, "iam.user_no_mfa", f"IAM user {name} has console access without MFA",
                                 "high" if privileged else "medium", "The user can sign in to the console with a password alone.",
                                 "Enforce MFA for all console users, or migrate to federated access.",
                                 {"UserName": name, "MFADevices": [], "privileged": privileged}, domain="identity")
                if "arn:aws:iam::aws:policy/AdministratorAccess" in attached:
                    self.finding(asset, "iam.user_admin_policy", f"IAM user {name} has AdministratorAccess attached directly", "high",
                                 "Administrative permissions are attached directly to a long-lived user identity.",
                                 "Grant administrative access through roles with MFA and session limits.",
                                 {"UserName": name, "AttachedPolicies": sorted(attached)}, domain="identity")
                for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                    age = (now - key["CreateDate"]).days
                    if key["Status"] == "Active" and age > MAX_KEY_AGE_DAYS:
                        self.finding(asset, "iam.access_key_old", f"Access key for {name} is {age} days old", "medium",
                                     f"Active access key {key['AccessKeyId'][:8]}… has not been rotated in more than {MAX_KEY_AGE_DAYS} days.",
                                     "Rotate or remove long-lived access keys; prefer short-lived role credentials.",
                                     {"AccessKeyIdPrefix": key["AccessKeyId"][:8], "age_days": age}, domain="identity",
                                     discriminator=key["AccessKeyId"][:8])
                self.ctx.mark_complete(asset)
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                if role["Path"].startswith("/aws-service-role/"):
                    continue
                name = role["RoleName"]
                attached = {p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]}
                trust = role.get("AssumeRolePolicyDocument") or {}
                trust = json.loads(trust) if isinstance(trust, str) else trust
                privileged = bool(attached & ADMIN_POLICIES)
                asset = self.ctx.asset(AssetSpec(type="identity", identifier=role["Arn"], name=f"IAM role {name}",
                                                 attributes={"provider": "aws", "kind": "role", "privileged": privileged,
                                                             "attached_policies": sorted(attached)}))
                self.ctx.link(account, asset, "CONTAINS")
                self.roles[role["Arn"]] = asset
                if privileged:
                    self.privileged_roles.add(role["Arn"])
                for stmt in trust.get("Statement", []) if isinstance(trust.get("Statement"), list) else [trust.get("Statement") or {}]:
                    principal = stmt.get("Principal")
                    aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else principal
                    aws_principals = [aws_principals] if isinstance(aws_principals, str) else (aws_principals or [])
                    if stmt.get("Effect") == "Allow" and "*" in aws_principals and not stmt.get("Condition"):
                        self.finding(asset, "iam.role_trusts_anyone", f"IAM role {name} can be assumed by any AWS principal",
                                     "critical" if privileged else "high", "The role's trust policy allows Principal '*' without a condition.",
                                     "Restrict the trust policy to specific principals and require an ExternalId for third parties.",
                                     {"AssumeRolePolicyDocument": trust}, domain="identity",
                                     impact="Any AWS account can obtain this role's permissions.")
                    external = [p for p in aws_principals if isinstance(p, str) and ":iam::" in p and f":{self.account_id}:" not in p]
                    if stmt.get("Effect") == "Allow" and external and "sts:ExternalId" not in json.dumps(stmt.get("Condition", {})):
                        self.finding(asset, "iam.role_cross_account_no_external_id", f"IAM role {name} trusts another account without an ExternalId",
                                     "medium", "Cross-account trust without an ExternalId condition is exposed to the confused-deputy problem.",
                                     "Add an sts:ExternalId condition for third-party access.", {"principals": external}, domain="identity")
                self.ctx.mark_complete(asset)

    # --- S3 ---
    def s3(self, account: Asset) -> None:
        s3 = self.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            self.ctx.checkpoint()
            name = bucket["Name"]
            try:
                block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                    raise
                block = {}
            blocked = all(block.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
            public_policy = False
            try:
                public_policy = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("NoSuchBucketPolicy", "NoSuchBucket"):
                    raise
            grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
            public_acl = [g["Permission"] for g in grants if "AllUsers" in g.get("Grantee", {}).get("URI", "")
                          or "AuthenticatedUsers" in g.get("Grantee", {}).get("URI", "")]
            is_public = not blocked and (public_policy or bool(public_acl))
            asset = self.ctx.asset(AssetSpec(type="storage", identifier=f"arn:aws:s3:::{name}", name=f"S3 bucket {name}",
                                             exposure="internet" if is_public else "private",
                                             attributes={"provider": "aws", "public_access_block": block, "public": is_public}))
            self.ctx.link(account, asset, "CONTAINS")
            self.buckets[name] = asset
            evidence = {"Bucket": name, "PublicAccessBlockConfiguration": block, "PolicyIsPublic": public_policy, "PublicAclGrants": public_acl}
            if is_public:
                self.finding(asset, "s3.bucket_public", f"S3 bucket {name} is publicly accessible", "critical",
                             "The bucket is reachable by anonymous users through its " + ("policy" if public_policy else "ACL")
                             + " and Block Public Access does not prevent it.",
                             "Enable all four Block Public Access settings and remove public grants; serve public content through CloudFront.",
                             evidence, impact="Objects can be listed or downloaded (and possibly written) by anyone on the internet.")
            elif not blocked:
                self.finding(asset, "s3.block_public_access_incomplete", f"S3 bucket {name} does not have Block Public Access fully enabled", "medium",
                             "A future policy or ACL change could expose the bucket.", "Enable all four Block Public Access settings.", evidence)
            self.ctx.mark_complete(asset)

    # --- EC2 ---
    def ec2(self, account: Asset, region: str) -> None:
        ec2 = self.client("ec2", region)
        open_groups: dict[str, list[str]] = {}
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for group in page["SecurityGroups"]:
                exposed = []
                for perm in group.get("IpPermissions", []):
                    world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or any(
                        r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                    if not world:
                        continue
                    if perm.get("IpProtocol") == "-1":
                        exposed.append("all ports")
                        continue
                    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                    exposed += [f"{port}/{label}" for port, label in SENSITIVE_PORTS.items() if lo <= port <= hi]
                if exposed:
                    open_groups[group["GroupId"]] = exposed
                    arn = f"arn:aws:ec2:{region}:{self.account_id}:security-group/{group['GroupId']}"
                    asset = self.ctx.asset(AssetSpec(type="cloud_resource", identifier=arn, name=f"Security group {group.get('GroupName')} ({group['GroupId']})",
                                                     attributes={"provider": "aws", "region": region, "resource_type": "security_group"}))
                    self.ctx.link(account, asset, "CONTAINS")
                    self.finding(asset, "ec2.sg_open_to_world", f"Security group {group['GroupId']} allows {', '.join(exposed[:5])} from the internet",
                                 "high", "Inbound rules permit 0.0.0.0/0 or ::/0 on administrative or data-store ports.",
                                 "Restrict sources to known address ranges or use Session Manager / a VPN.",
                                 {"GroupId": group["GroupId"], "exposed": exposed, "IpPermissions": group.get("IpPermissions", [])[:10]})
                    self.ctx.mark_complete(asset)
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue
                    arn = f"arn:aws:ec2:{region}:{self.account_id}:instance/{inst['InstanceId']}"
                    name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst["InstanceId"])
                    groups = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
                    reachable = bool(inst.get("PublicIpAddress")) and any(g in open_groups for g in groups)
                    asset = self.ctx.asset(AssetSpec(
                        type="host", identifier=arn, name=f"EC2 {name}", exposure="internet" if reachable else ("internal" if not inst.get("PublicIpAddress") else "unknown"),
                        attributes={"provider": "aws", "region": region, "public_ip": inst.get("PublicIpAddress"), "security_groups": groups,
                                    "imds_v2_required": inst.get("MetadataOptions", {}).get("HttpTokens") == "required"}))
                    self.ctx.link(account, asset, "CONTAINS")
                    profile = (inst.get("IamInstanceProfile") or {}).get("Arn")
                    if profile:
                        # Instance profile and role share a name in the common case; link when the role is known.
                        role_arn = profile.replace(":instance-profile/", ":role/")
                        if role_arn in self.roles:
                            self.ctx.link(asset, self.roles[role_arn], "AUTHENTICATES_TO", evidence={"instance_profile": profile}, confidence=0.9)
                    if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                        self.finding(asset, "ec2.imdsv1_allowed", f"EC2 instance {name} allows IMDSv1", "medium",
                                     "IMDSv1 lets a server-side request forgery flaw retrieve the instance role credentials.",
                                     "Set HttpTokens=required to enforce IMDSv2.", {"MetadataOptions": inst.get("MetadataOptions", {})})
                    self.ctx.mark_complete(asset)

    # --- RDS / CloudTrail / KMS / EKS ---
    def rds(self, account: Asset, region: str) -> None:
        for page in self.client("rds", region).get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                public = bool(db.get("PubliclyAccessible"))
                asset = self.ctx.asset(AssetSpec(type="database", identifier=db["DBInstanceArn"], name=f"RDS {db['DBInstanceIdentifier']}",
                                                 exposure="internet" if public else "private",
                                                 attributes={"provider": "aws", "region": region, "engine": db.get("Engine"),
                                                             "encrypted": db.get("StorageEncrypted")}))
                self.ctx.link(account, asset, "CONTAINS")
                ev = {k: db.get(k) for k in ("DBInstanceIdentifier", "PubliclyAccessible", "StorageEncrypted", "Engine")}
                if public:
                    self.finding(asset, "rds.publicly_accessible", f"RDS instance {db['DBInstanceIdentifier']} is publicly accessible", "high",
                                 "The instance has a public endpoint.", "Disable public accessibility and reach the database through private subnets.", ev)
                if not db.get("StorageEncrypted"):
                    self.finding(asset, "rds.unencrypted", f"RDS instance {db['DBInstanceIdentifier']} storage is not encrypted", "medium",
                                 "Data at rest, snapshots and backups are unencrypted.", "Enable storage encryption (requires snapshot restore).", ev)
                self.ctx.mark_complete(asset)

    def cloudtrail(self, account: Asset, region: str) -> None:
        ct = self.client("cloudtrail", region)
        trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
        logging = [t for t in trails if t.get("IsMultiRegionTrail") and ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging")]
        account.attributes = {**account.attributes, "audit_logging_enabled": bool(logging), "cloudtrail_trails": len(trails)}
        if not logging:
            self.finding(account, "cloudtrail.not_enabled", "No multi-region CloudTrail trail is logging", "high",
                         "API activity in the account is not being recorded across all regions.",
                         "Create a multi-region trail delivering to a dedicated, access-controlled bucket.",
                         {"trails": [{"Name": t.get("Name"), "IsMultiRegionTrail": t.get("IsMultiRegionTrail")} for t in trails]},
                         impact="Compromise and misuse cannot be investigated.")
        for t in logging:
            if not t.get("LogFileValidationEnabled"):
                self.finding(account, "cloudtrail.no_log_validation", f"CloudTrail trail {t.get('Name')} has log file validation disabled", "low",
                             "Log tampering would not be detectable.", "Enable log file validation.", {"Name": t.get("Name")}, discriminator=t.get("Name", ""))

    def kms(self, account: Asset, region: str) -> None:
        kms = self.client("kms", region)
        for page in kms.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled" or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue
                if not kms.get_key_rotation_status(KeyId=key["KeyId"]).get("KeyRotationEnabled"):
                    asset = self.ctx.asset(AssetSpec(type="cloud_resource", identifier=meta["Arn"], name=f"KMS key {key['KeyId'][:8]}",
                                                     attributes={"provider": "aws", "region": region, "resource_type": "kms_key"}))
                    self.finding(asset, "kms.rotation_disabled", f"KMS key {key['KeyId'][:8]}… does not rotate automatically", "low",
                                 "Automatic annual rotation is disabled for a customer-managed key.", "Enable automatic key rotation.",
                                 {"KeyId": key["KeyId"], "KeyRotationEnabled": False})

    def eks(self, account: Asset, region: str) -> None:
        eks = self.client("eks", region)
        for name in eks.list_clusters().get("clusters", []):
            cluster = eks.describe_cluster(name=name)["cluster"]
            vpc = cluster.get("resourcesVpcConfig", {})
            public = vpc.get("endpointPublicAccess") and "0.0.0.0/0" in (vpc.get("publicAccessCidrs") or ["0.0.0.0/0"])
            asset = self.ctx.asset(AssetSpec(type="k8s_resource", identifier=cluster["arn"], name=f"EKS cluster {name}",
                                             exposure="internet" if public else "private",
                                             attributes={"provider": "aws", "region": region, "version": cluster.get("version")}))
            self.ctx.link(account, asset, "CONTAINS")
            if public:
                self.finding(asset, "eks.public_endpoint", f"EKS cluster {name} API endpoint is open to the internet", "high",
                             "The Kubernetes API server accepts connections from 0.0.0.0/0.",
                             "Disable public access or restrict publicAccessCidrs to known ranges.",
                             {"resourcesVpcConfig": {k: vpc.get(k) for k in ("endpointPublicAccess", "publicAccessCidrs", "endpointPrivateAccess")}},
                             domain="container")
            self.ctx.mark_complete(asset)

    def permission_edges(self) -> None:
        """Roles holding broad managed policies can reach every bucket in the account."""
        for arn in self.privileged_roles:
            for bucket in self.buckets.values():
                self.ctx.link(self.roles[arn], bucket, "HAS_PERMISSION", confidence=0.9,
                              evidence={"basis": "AWS managed policy granting s3:* attached to the role",
                                        "policies": self.roles[arn].attributes.get("attached_policies")})


def run(ctx: EngineContext) -> None:
    assert ctx.integration is not None
    config = AwsConfig.model_validate(ctx.integration.config)
    if ctx.dry_run:
        ctx.planned(f"Read-only AWS API calls (IAM, S3 global; EC2, RDS, CloudTrail, KMS, EKS in {', '.join(config.regions)})")
        return
    creds = AwsCredentials.model_validate(json.loads(decrypt_secret(ctx.integration.credentials_encrypted))
                                          if ctx.integration.credentials_encrypted else {})
    try:
        session = make_session(config, creds)
        identity = session.client("sts", config=_BOTO).get_caller_identity()
    except (ClientError, BotoCoreError, ValueError) as exc:
        raise PermanentJobError(f"AWS authentication failed: {exc}"[:500]) from exc
    account_id = identity["Account"]
    account = ctx.asset(AssetSpec(type="cloud_account", identifier=f"arn:aws:iam::{account_id}:root", name=f"AWS account {account_id}",
                                  attributes={"provider": "aws", "account_id": account_id, "assessed_as": identity["Arn"]}))
    aws = _Aws(ctx, session, account_id)
    ctx.job.progress(5, "Assessing IAM")
    aws.guarded("iam", lambda: aws.iam(account))
    ctx.job.progress(30, "Assessing S3")
    aws.guarded("s3", lambda: aws.s3(account))
    for index, region in enumerate(config.regions):
        ctx.job.progress(40 + int(55 * index / len(config.regions)), f"Assessing {region}")
        for service in ("ec2", "rds", "kms", "eks"):
            aws.guarded(f"{service}:{region}", lambda s=service, r=region: getattr(aws, s)(account, r))
    aws.guarded("cloudtrail", lambda: aws.cloudtrail(account, config.regions[0]))
    aws.permission_edges()
    ctx.mark_complete(account)
    ctx.stats["account_id"], ctx.stats["regions"] = account_id, config.regions


register_connector(ConnectorSpec(
    key="aws", name="Amazon Web Services", category="cloud", config_model=AwsConfig, credentials_model=AwsCredentials,
    test=test_connection, description="Read-only posture assessment of IAM, S3, EC2, RDS, CloudTrail, KMS and EKS.",
    required_permissions="AWS managed policies SecurityAudit and ViewOnlyAccess (read-only). Optional sts:AssumeRole into a target role.",
))
register(EngineSpec(
    kind="aws_posture", name="AWS security posture", module="cloud", run=run, requires_connector="aws",
    description="Read-only assessment of IAM, S3, EC2, RDS, CloudTrail, KMS and EKS; builds identity and permission relationships.",
))
