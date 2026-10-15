"""Read-only AWS collectors.

Each collector is a function `(ctx) -> list[resource]` registered with the
service it reports on and the IAM permissions it needs. Only list/describe/get
APIs are used. Add a service by writing one function and decorating it.
"""
from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from botocore.exceptions import BotoCoreError, ClientError

from app.inventory.schema import CollectionContext, make_resource


@dataclass(frozen=True)
class Collector:
    label: str
    service: str  # must match the `service` of the resources it returns
    permissions: tuple[str, ...]
    fn: Callable[[CollectionContext], list[dict]]


COLLECTORS: list[Collector] = []


def collector(label: str, service: str, permissions: tuple[str, ...]):
    def register(fn: Callable[[CollectionContext], list[dict]]):
        COLLECTORS.append(Collector(label, service, permissions, fn))
        return fn

    return register


def _tags(item: dict) -> dict:
    return {t.get("Key"): t.get("Value") for t in item.get("Tags", [])}


@collector("EC2 instances", "EC2", ("ec2:DescribeInstances",))
def ec2_instances(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("ec2").get_paginator("describe_instances").paginate():
        for reservation in page.get("Reservations", []):
            for item in reservation.get("Instances", []):
                rid = item.get("InstanceId")
                result.append(make_resource(
                    "EC2", "Instance", rid, _tags(item).get("Name", rid),
                    item.get("State", {}).get("Name"),
                    item.get("Placement", {}).get("AvailabilityZone"),
                    updated_at=item.get("LaunchTime"),
                    details={
                        "instance_type": item.get("InstanceType"),
                        "vpc_id": item.get("VpcId"),
                        "subnet_id": item.get("SubnetId"),
                        "private_ip": item.get("PrivateIpAddress"),
                    },
                ))
    return result


@collector("EBS volumes", "EC2", ("ec2:DescribeVolumes",))
def ebs_volumes(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("ec2").get_paginator("describe_volumes").paginate():
        for item in page.get("Volumes", []):
            rid = item.get("VolumeId")
            result.append(make_resource(
                "EC2", "EBS Volume", rid, rid, item.get("State"),
                item.get("AvailabilityZone"), updated_at=item.get("CreateTime"),
                details={
                    "size_gib": item.get("Size"),
                    "volume_type": item.get("VolumeType"),
                    "encrypted": item.get("Encrypted"),
                    "attached_instance_ids": [
                        a.get("InstanceId") for a in item.get("Attachments", [])
                    ],
                },
            ))
    return result


@collector("VPCs", "VPC", ("ec2:DescribeVpcs",))
def vpcs(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("ec2").get_paginator("describe_vpcs").paginate():
        for item in page.get("Vpcs", []):
            rid = item.get("VpcId")
            result.append(make_resource(
                "VPC", "VPC", rid, _tags(item).get("Name", rid),
                item.get("State"), ctx.region,
                details={
                    "cidr_block": item.get("CidrBlock"),
                    "is_default": item.get("IsDefault"),
                },
            ))
    return result


@collector("Security groups", "EC2", ("ec2:DescribeSecurityGroups",))
def security_groups(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("ec2").get_paginator("describe_security_groups").paginate():
        for item in page.get("SecurityGroups", []):
            rid = item.get("GroupId")
            result.append(make_resource(
                "EC2", "Security Group", rid, item.get("GroupName", rid),
                "configured", ctx.region,
                details={
                    "vpc_id": item.get("VpcId"),
                    "description": item.get("Description"),
                    "ingress_rule_count": len(item.get("IpPermissions", [])),
                    "egress_rule_count": len(item.get("IpPermissionsEgress", [])),
                },
            ))
    return result


# --- S3 -------------------------------------------------------------------

_S3_NOT_CONFIGURED = {
    "encryption": "ServerSideEncryptionConfigurationNotFoundError",
    "public_access_block": "NoSuchPublicAccessBlockConfiguration",
}


def _s3_check(call, check: str, unavailable: dict[str, set[str]], bucket: str):
    """Run one per-bucket check. Returns (value, state).

    state is "configured", "not_configured" (AWS says the setting is absent)
    or "unknown" (the check failed, e.g. AccessDenied). Unknown is never
    reported as 'not configured'.
    """
    try:
        return call(), "configured"
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == _S3_NOT_CONFIGURED.get(check):
            return None, "not_configured"
        unavailable.setdefault(f"{check} ({code})", set()).add(bucket)
        return None, "unknown"
    except BotoCoreError as exc:
        unavailable.setdefault(f"{check} ({type(exc).__name__})", set()).add(bucket)
        return None, "unknown"


def _bucket_resource(client, item: dict) -> tuple[dict, dict[str, int]]:
    """Describe one bucket. Returns (resource, {failed_check: 1}); safe to run in a thread."""
    name = item.get("Name")
    unavailable: dict[str, set[str]] = {}

    try:
        bucket_region = (
            client.get_bucket_location(Bucket=name).get("LocationConstraint")
            or "us-east-1"
        )
    except (BotoCoreError, ClientError):
        bucket_region = None

    encryption, enc_state = _s3_check(
        lambda: client.get_bucket_encryption(Bucket=name)
        ["ServerSideEncryptionConfiguration"]["Rules"],
        "encryption", unavailable, name,
    )
    public_block, pab_state = _s3_check(
        lambda: client.get_public_access_block(Bucket=name)
        ["PublicAccessBlockConfiguration"],
        "public_access_block", unavailable, name,
    )
    versioning, ver_state = _s3_check(
        lambda: client.get_bucket_versioning(Bucket=name).get("Status", "Disabled"),
        "versioning", unavailable, name,
    )

    details = {
        "encryption": (
            sorted({
                r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                for r in encryption
            } - {None})
            if enc_state == "configured" else enc_state
        ),
        "public_access_block": (
            {**public_block, "all_blocked": all(public_block.values())}
            if pab_state == "configured" else pab_state
        ),
        "versioning": versioning if ver_state == "configured" else ver_state,
    }

    resource = make_resource(
        "S3", "Bucket", name, name, "present", bucket_region,
        arn=f"arn:aws:s3:::{name}", updated_at=item.get("CreationDate"),
        details=details,
    )
    return resource, {check: 1 for check in unavailable}


@collector(
    "S3 buckets",
    "S3",
    (
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
    ),
)
def s3_buckets(ctx: CollectionContext) -> list[dict]:
    client = ctx.client("s3")
    buckets = client.list_buckets().get("Buckets", [])
    if not buckets:
        return []

    # Four read calls per bucket: do buckets in parallel to keep this fast.
    with ThreadPoolExecutor(max_workers=min(8, len(buckets))) as pool:
        outcomes = list(pool.map(lambda b: _bucket_resource(client, b), buckets))

    failed_checks: dict[str, int] = {}
    for _, failures in outcomes:
        for check in failures:
            failed_checks[check] = failed_checks.get(check, 0) + 1
    for check, count in sorted(failed_checks.items()):
        ctx.notes.append(f"S3 {check} unavailable for {count} bucket(s)")

    return [resource for resource, _ in outcomes]


# --- Other services ---------------------------------------------------------


@collector("RDS instances", "RDS", ("rds:DescribeDBInstances",))
def rds_instances(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("rds").get_paginator("describe_db_instances").paginate():
        for item in page.get("DBInstances", []):
            rid = item.get("DBInstanceIdentifier")
            result.append(make_resource(
                "RDS", "DB Instance", rid, rid, item.get("DBInstanceStatus"),
                item.get("AvailabilityZone", ctx.region), item.get("DBInstanceArn"),
                details={
                    "engine": item.get("Engine"),
                    "class": item.get("DBInstanceClass"),
                    "storage_gib": item.get("AllocatedStorage"),
                    "publicly_accessible": item.get("PubliclyAccessible"),
                },
            ))
    return result


@collector("Lambda functions", "Lambda", ("lambda:ListFunctions",))
def lambda_functions(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("lambda").get_paginator("list_functions").paginate():
        for item in page.get("Functions", []):
            result.append(make_resource(
                "Lambda", "Function", item.get("FunctionArn"), item.get("FunctionName"),
                item.get("State", "Active"), ctx.region, item.get("FunctionArn"),
                item.get("LastModified"),
                {
                    "runtime": item.get("Runtime"),
                    "memory_mb": item.get("MemorySize"),
                    "timeout_seconds": item.get("Timeout"),
                },
            ))
    return result


@collector("EKS clusters", "EKS", ("eks:ListClusters", "eks:DescribeCluster"))
def eks_clusters(ctx: CollectionContext) -> list[dict]:
    client = ctx.client("eks")
    result = []
    for page in client.get_paginator("list_clusters").paginate():
        for name in page.get("clusters", []):
            item = client.describe_cluster(name=name).get("cluster", {})
            vpc = item.get("resourcesVpcConfig", {})
            result.append(make_resource(
                "EKS", "Kubernetes Cluster", item.get("arn") or name, name,
                item.get("status"), ctx.region, item.get("arn"), item.get("createdAt"),
                {
                    "version": item.get("version"),
                    "endpoint_private_access": vpc.get("endpointPrivateAccess"),
                    "endpoint_public_access": vpc.get("endpointPublicAccess"),
                },
            ))
    return result


@collector("ECS clusters", "ECS", ("ecs:ListClusters", "ecs:DescribeClusters"))
def ecs_clusters(ctx: CollectionContext) -> list[dict]:
    client = ctx.client("ecs")
    arns: list[str] = []
    for page in client.get_paginator("list_clusters").paginate():
        arns.extend(page.get("clusterArns", []))

    result = []
    for start in range(0, len(arns), 100):
        response = client.describe_clusters(
            clusters=arns[start:start + 100], include=["SETTINGS", "STATISTICS"]
        )
        for item in response.get("clusters", []):
            result.append(make_resource(
                "ECS", "Cluster", item.get("clusterArn"), item.get("clusterName"),
                item.get("status"), ctx.region, item.get("clusterArn"),
                details={
                    "running_tasks": item.get("runningTasksCount"),
                    "pending_tasks": item.get("pendingTasksCount"),
                    "services": item.get("activeServicesCount"),
                },
            ))
    return result


@collector("DynamoDB tables", "DynamoDB", ("dynamodb:ListTables", "dynamodb:DescribeTable"))
def dynamodb_tables(ctx: CollectionContext) -> list[dict]:
    client = ctx.client("dynamodb")
    result = []
    for page in client.get_paginator("list_tables").paginate():
        for name in page.get("TableNames", []):
            item = client.describe_table(TableName=name).get("Table", {})
            result.append(make_resource(
                "DynamoDB", "Table", item.get("TableArn") or name, name,
                item.get("TableStatus"), ctx.region, item.get("TableArn"),
                details={
                    "billing_mode": item.get("BillingModeSummary", {}).get("BillingMode"),
                    "item_count": item.get("ItemCount"),
                    "size_bytes": item.get("TableSizeBytes"),
                },
            ))
    return result


@collector("SQS queues", "SQS", ("sqs:ListQueues",))
def sqs_queues(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("sqs").get_paginator("list_queues").paginate():
        for url in page.get("QueueUrls", []):
            result.append(make_resource(
                "SQS", "Queue", url, url.rsplit("/", 1)[-1], "present", ctx.region, url,
            ))
    return result


@collector("SNS topics", "SNS", ("sns:ListTopics",))
def sns_topics(ctx: CollectionContext) -> list[dict]:
    result = []
    for page in ctx.client("sns").get_paginator("list_topics").paginate():
        for item in page.get("Topics", []):
            arn = item.get("TopicArn")
            result.append(make_resource(
                "SNS", "Topic", arn, arn.rsplit(":", 1)[-1] if arn else None,
                "present", ctx.region, arn,
            ))
    return result


@collector(
    "Load balancers",
    "Elastic Load Balancing",
    ("elasticloadbalancing:DescribeLoadBalancers",),
)
def load_balancers(ctx: CollectionContext) -> list[dict]:
    result = []
    paginator = ctx.client("elbv2").get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for item in page.get("LoadBalancers", []):
            zone = (item.get("AvailabilityZones") or [{}])[0].get("ZoneName", ctx.region)
            result.append(make_resource(
                "Elastic Load Balancing", item.get("Type", "Load Balancer"),
                item.get("LoadBalancerArn"), item.get("LoadBalancerName"),
                item.get("State", {}).get("Code"), zone, item.get("LoadBalancerArn"),
                details={
                    "scheme": item.get("Scheme"),
                    "vpc_id": item.get("VpcId"),
                    "dns_name": item.get("DNSName"),
                },
            ))
    return result