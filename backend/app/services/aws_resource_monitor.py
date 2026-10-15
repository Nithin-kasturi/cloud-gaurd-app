"""Read-only, multi-service AWS inventory and CloudTrail change monitor.

This extends the existing CloudGuard architecture: STS identity -> CloudTrail
activity -> read-only service inventory. It never creates, updates, or deletes
AWS resources. Inventory coverage is intentionally explicit and partial: AWS has
hundreds of services, and each additional service needs a read-only adapter.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

DEFAULT_PROFILE = "cloudguard-dev"
DEFAULT_REGION = "us-east-1"


def _session(profile_name: str = DEFAULT_PROFILE, region_name: str = DEFAULT_REGION):
    return boto3.Session(profile_name=profile_name, region_name=region_name)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _resource(service: str, resource_type: str, resource_id: str | None,
              name: str | None = None, status: str | None = None,
              region: str | None = None, arn: str | None = None,
              updated_at: Any = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "resource_id": resource_id or name or "unknown",
        "name": name or resource_id or "Unnamed resource",
        "service": service,
        "resource_type": resource_type,
        "status": status or "Unknown",
        "region": region,
        "arn": arn,
        "updated_at": _iso(updated_at),
        "details": details or {},
    }


def _call(warnings: list[str], service_label: str, fn):
    """Run one optional service collector without losing other service results."""
    try:
        return fn()
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as exc:
        code = exc.response.get("Error", {}).get("Code", type(exc).__name__) if isinstance(exc, ClientError) else type(exc).__name__
        # Do not leak credentials or full SDK request data into the API response.
        warnings.append(f"{service_label}: unavailable ({code}). Check read-only IAM permissions and region support.")
        return []


def get_resource_inventory(profile_name: str = DEFAULT_PROFILE,
                           region_name: str = DEFAULT_REGION) -> dict[str, Any]:
    """Collect a best-effort inventory across commonly used AWS services.

    Each service is isolated so AccessDenied for one service does not prevent
    the rest of the dashboard from loading. Uses read/list/describe APIs only.
    """
    session = _session(profile_name, region_name)
    resources: list[dict[str, Any]] = []
    warnings: list[str] = []

    def ec2_instances():
        client = session.client("ec2")
        result = []
        paginator = client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for item in reservation.get("Instances", []):
                    tags = {t.get("Key"): t.get("Value") for t in item.get("Tags", [])}
                    rid = item.get("InstanceId")
                    result.append(_resource("EC2", "Instance", rid, tags.get("Name", rid),
                        item.get("State", {}).get("Name"), item.get("Placement", {}).get("AvailabilityZone"),
                        updated_at=item.get("LaunchTime"), details={"instance_type": item.get("InstanceType"),
                        "vpc_id": item.get("VpcId"), "subnet_id": item.get("SubnetId"), "private_ip": item.get("PrivateIpAddress")}))
        return result
    resources += _call(warnings, "EC2 instances", ec2_instances)

    def ec2_volumes():
        client = session.client("ec2")
        result = []
        for page in client.get_paginator("describe_volumes").paginate():
            for item in page.get("Volumes", []):
                rid = item.get("VolumeId")
                result.append(_resource("EC2", "EBS Volume", rid, rid, item.get("State"), item.get("AvailabilityZone"),
                    updated_at=item.get("CreateTime"), details={"size_gib": item.get("Size"), "volume_type": item.get("VolumeType"),
                    "encrypted": item.get("Encrypted"), "attached_instance_ids": [a.get("InstanceId") for a in item.get("Attachments", [])]}))
        return result
    resources += _call(warnings, "EBS volumes", ec2_volumes)

    def vpcs():
        client = session.client("ec2")
        result = []
        for page in client.get_paginator("describe_vpcs").paginate():
            for item in page.get("Vpcs", []):
                tags = {t.get("Key"): t.get("Value") for t in item.get("Tags", [])}
                rid = item.get("VpcId")
                result.append(_resource("VPC", "VPC", rid, tags.get("Name", rid), item.get("State"), region_name,
                    details={"cidr_block": item.get("CidrBlock"), "is_default": item.get("IsDefault")}))
        return result
    resources += _call(warnings, "VPCs", vpcs)

    def security_groups():
        client = session.client("ec2")
        result = []
        for page in client.get_paginator("describe_security_groups").paginate():
            for item in page.get("SecurityGroups", []):
                rid = item.get("GroupId")
                result.append(_resource("EC2", "Security Group", rid, item.get("GroupName", rid), "configured", region_name,
                    details={"vpc_id": item.get("VpcId"), "description": item.get("Description"),
                    "ingress_rule_count": len(item.get("IpPermissions", [])), "egress_rule_count": len(item.get("IpPermissionsEgress", []))}))
        return result
    resources += _call(warnings, "Security groups", security_groups)

    def s3_buckets():
        # S3 bucket listing is account-global; region is fetched per bucket where available.
        client = session.client("s3")
        result = []
        for item in client.list_buckets().get("Buckets", []):
            name = item.get("Name")
            bucket_region = None
            try:
                bucket_region = client.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            except (BotoCoreError, ClientError):
                bucket_region = None
            result.append(_resource("S3", "Bucket", name, name, "present", bucket_region,
                arn=f"arn:aws:s3:::{name}", updated_at=item.get("CreationDate")))
        return result
    resources += _call(warnings, "S3 buckets", s3_buckets)

    def rds_instances():
        client = session.client("rds")
        result = []
        for page in client.get_paginator("describe_db_instances").paginate():
            for item in page.get("DBInstances", []):
                rid = item.get("DBInstanceIdentifier")
                result.append(_resource("RDS", "DB Instance", rid, rid, item.get("DBInstanceStatus"),
                    item.get("AvailabilityZone", region_name), item.get("DBInstanceArn"),
                    details={"engine": item.get("Engine"), "class": item.get("DBInstanceClass"),
                    "storage_gib": item.get("AllocatedStorage"), "publicly_accessible": item.get("PubliclyAccessible")}))
        return result
    resources += _call(warnings, "RDS instances", rds_instances)

    def lambda_functions():
        client = session.client("lambda")
        result = []
        for page in client.get_paginator("list_functions").paginate():
            for item in page.get("Functions", []):
                result.append(_resource("Lambda", "Function", item.get("FunctionArn"), item.get("FunctionName"),
                    item.get("State", "Active"), region_name, item.get("FunctionArn"), item.get("LastModified"),
                    {"runtime": item.get("Runtime"), "memory_mb": item.get("MemorySize"), "timeout_seconds": item.get("Timeout")}))
        return result
    resources += _call(warnings, "Lambda functions", lambda_functions)

    def eks_clusters():
        client = session.client("eks")
        result = []
        names = client.list_clusters().get("clusters", [])
        for name in names:
            item = client.describe_cluster(name=name).get("cluster", {})
            result.append(_resource("EKS", "Kubernetes Cluster", item.get("arn") or name, name,
                item.get("status"), item.get("region", region_name), item.get("arn"), item.get("createdAt"),
                {"version": item.get("version"), "endpoint_private_access": item.get("resourcesVpcConfig", {}).get("endpointPrivateAccess"),
                 "endpoint_public_access": item.get("resourcesVpcConfig", {}).get("endpointPublicAccess")}))
        return result
    resources += _call(warnings, "EKS clusters", eks_clusters)

    def ecs_clusters():
        client = session.client("ecs")
        result = []
        arns = client.list_clusters().get("clusterArns", [])
        for start in range(0, len(arns), 100):
            for item in client.describe_clusters(clusters=arns[start:start + 100], include=["SETTINGS", "STATISTICS"]).get("clusters", []):
                result.append(_resource("ECS", "Cluster", item.get("clusterArn"), item.get("clusterName"), item.get("status"), region_name,
                    item.get("clusterArn"), details={"running_tasks": item.get("runningTasksCount"), "pending_tasks": item.get("pendingTasksCount"), "services": item.get("activeServicesCount")}))
        return result
    resources += _call(warnings, "ECS clusters", ecs_clusters)

    def dynamodb_tables():
        client = session.client("dynamodb")
        result = []
        for page in client.get_paginator("list_tables").paginate():
            for name in page.get("TableNames", []):
                item = client.describe_table(TableName=name).get("Table", {})
                result.append(_resource("DynamoDB", "Table", item.get("TableArn") or name, name, item.get("TableStatus"), region_name,
                    item.get("TableArn"), details={"billing_mode": item.get("BillingModeSummary", {}).get("BillingMode"),
                    "item_count": item.get("ItemCount"), "size_bytes": item.get("TableSizeBytes")}))
        return result
    resources += _call(warnings, "DynamoDB tables", dynamodb_tables)

    def sqs_queues():
        client = session.client("sqs")
        result = []
        for url in client.list_queues().get("QueueUrls", []):
            result.append(_resource("SQS", "Queue", url, url.rsplit("/", 1)[-1], "present", region_name, url))
        return result
    resources += _call(warnings, "SQS queues", sqs_queues)

    def sns_topics():
        client = session.client("sns")
        result = []
        for page in client.get_paginator("list_topics").paginate():
            for item in page.get("Topics", []):
                arn = item.get("TopicArn")
                result.append(_resource("SNS", "Topic", arn, arn.rsplit(":", 1)[-1] if arn else None, "present", region_name, arn))
        return result
    resources += _call(warnings, "SNS topics", sns_topics)

    def load_balancers():
        client = session.client("elbv2")
        result = []
        for page in client.get_paginator("describe_load_balancers").paginate():
            for item in page.get("LoadBalancers", []):
                result.append(_resource("Elastic Load Balancing", item.get("Type", "Load Balancer"), item.get("LoadBalancerArn"),
                    item.get("LoadBalancerName"), item.get("State", {}).get("Code"), (item.get("AvailabilityZones") or [{}])[0].get("ZoneName", region_name),
                    item.get("LoadBalancerArn"), details={"scheme": item.get("Scheme"), "vpc_id": item.get("VpcId"), "dns_name": item.get("DNSName")}))
        return result
    resources += _call(warnings, "Load balancers", load_balancers)

    # Stable dedupe across collectors and a compact service summary.
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for item in resources:
        unique[(item["service"], item["resource_id"])] = item
    resources = sorted(unique.values(), key=lambda item: (item["service"].lower(), item["name"].lower()))
    service_counts: dict[str, int] = {}
    for item in resources:
        service_counts[item["service"]] = service_counts.get(item["service"], 0) + 1
    return {
        "source": "aws",
        "region": region_name,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "count": len(resources),
        "services_monitored": sorted(service_counts),
        "service_counts": service_counts,
        "resources": resources,
        "warnings": warnings,
        "coverage_note": "Best-effort inventory for supported services. CloudTrail management events can cover additional AWS services; inventory requires a read-only adapter and IAM permissions per service.",
    }


_MUTATION_PREFIXES = (
    "create", "delete", "modify", "update", "put", "authorize", "revoke",
    "attach", "detach", "restore", "start", "stop", "reboot", "runinstances",
    "terminate", "launch", "tag", "untag", "add", "remove", "associate",
    "disassociate", "enable", "disable", "rotate", "register", "deregister",
    "change", "reset", "set", "import", "export", "promote", "failover",
)


def _parse_cloudtrail_event(item: dict[str, Any]) -> dict[str, Any]:
    try:
        raw = json.loads(item.get("CloudTrailEvent", "{}"))
    except (TypeError, json.JSONDecodeError):
        raw = {}
    identity = raw.get("userIdentity") or {}
    session = identity.get("sessionContext", {}).get("sessionIssuer", {}) or {}
    username = identity.get("userName") or identity.get("principalId") or session.get("userName") or "Unknown"
    resources = item.get("Resources") or raw.get("resources") or []
    resource_ids: list[str] = []
    resource_types: list[str] = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        rid = resource.get("ResourceName") or resource.get("ARN") or resource.get("resourceName") or resource.get("arn")
        rtype = resource.get("ResourceType") or resource.get("resourceType")
        if rid and rid not in resource_ids:
            resource_ids.append(str(rid))
        if rtype and rtype not in resource_types:
            resource_types.append(str(rtype))
    params = raw.get("requestParameters") or {}
    # Extract common identifiers when CloudTrail's Resources array is absent.
    aliases = {
        "bucketName": "S3 bucket", "Bucket": "S3 bucket", "bucket": "S3 bucket",
        "instanceId": "EC2 instance", "instanceIds": "EC2 instance", "DBInstanceIdentifier": "RDS DB instance",
        "DBClusterIdentifier": "RDS DB cluster", "functionName": "Lambda function", "clusterName": "Container/Kubernetes cluster",
        "roleName": "IAM role", "userName": "IAM user", "groupId": "Security group", "loadBalancerArn": "Load balancer",
        "tableName": "DynamoDB table", "queueUrl": "SQS queue", "topicArn": "SNS topic", "repositoryName": "ECR repository",
    }
    def walk(obj: Any):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in aliases:
                    values = value if isinstance(value, list) else [value]
                    for v in values:
                        if isinstance(v, (str, int)) and str(v) not in resource_ids:
                            resource_ids.append(str(v))
                            resource_types.append(aliases[key])
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
    walk(params)
    event_name = item.get("EventName") or raw.get("eventName") or "UnknownEvent"
    event_source = item.get("EventSource") or raw.get("eventSource") or ""
    # Authentication/session token events are not resource changes. Keep them
    # out of the customer-facing resource feed even when their name starts with Create.
    if event_source.lower() in {"signin.amazonaws.com", "sts.amazonaws.com"} and any(token in event_name.lower() for token in ("oauth2token", "assumerole", "getsessiontoken", "federationtoken")):
        return {}
    error_code = raw.get("errorCode") or raw.get("errorCodeId")
    read_only = raw.get("readOnly")
    lower = event_name.lower()
    if error_code:
        action = "failed"
    elif read_only is True or lower.startswith(("get", "describe", "list", "lookup", "head", "check", "validate", "search", "query")):
        action = "observed"
    elif lower.startswith(("delete", "terminate", "remove", "deregister")):
        action = "deleted"
    elif lower.startswith(("create", "runinstances", "launch", "register", "put")):
        action = "created_or_updated"
    elif lower.startswith(_MUTATION_PREFIXES):
        action = "modified"
    else:
        action = "other"
    # Only resource mutations appear in the default feed. Keep the raw event
    # available in CloudTrail itself; don't turn routine auth/read events into activity noise.
    if action in ("observed", "other"):
        return {}
    event_time = item.get("EventTime") or raw.get("eventTime")
    if isinstance(event_time, datetime):
        event_time = event_time.astimezone(timezone.utc).isoformat()
    return {
        "event_id": item.get("EventId") or raw.get("eventID"),
        "event_name": event_name,
        "event_source": item.get("EventSource") or raw.get("eventSource"),
        "action": action,
        "resource_id": resource_ids[0] if resource_ids else None,
        "resource_ids": resource_ids,
        "resource_type": resource_types[0] if resource_types else None,
        "timestamp": str(event_time) if event_time else None,
        "event_time": str(event_time) if event_time else None,
        "aws_region": item.get("AwsRegion") or raw.get("awsRegion"),
        "actor": username,
        "username": username,
        "identity_type": identity.get("type"),
        "actor_arn": identity.get("arn"),
        "source_ip": raw.get("sourceIPAddress"),
        "read_only": read_only,
        "error_code": error_code,
        "event_category": raw.get("eventCategory"),
        "evidence_source": "CloudTrail",
        "assessment_status": "unassessed",
    }


def get_resource_changes(profile_name: str = DEFAULT_PROFILE, region_name: str = DEFAULT_REGION,
                         max_results: int = 50) -> dict[str, Any]:
    """Return meaningful resource mutation events from CloudTrail management history."""
    try:
        client = _session(profile_name, region_name).client("cloudtrail")
        response = client.lookup_events(MaxResults=max(1, min(int(max_results), 50)))
        events = [_parse_cloudtrail_event(item) for item in response.get("Events", [])]
        changes = [event for event in events if event]
        seen: set[str] = set()
        unique = []
        for event in changes:
            key = str(event.get("event_id") or "|".join([
                str(event.get("event_name")), str(event.get("event_source")),
                str(event.get("resource_id")), str(event.get("timestamp")),
            ]))
            if key not in seen:
                seen.add(key)
                unique.append(event)
        unique.sort(key=lambda event: event.get("timestamp") or "", reverse=True)
        return {
            "source": "aws", "region": region_name,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "count": len(unique), "changes": unique,
            "summary": {"events_with_detected_changes": len(unique),
                        "resource_change_records": sum(max(1, len(e.get("resource_ids") or [])) for e in unique)},
            "coverage_note": "CloudTrail Event History returns recent management events for this region. S3 object and other data events require an appropriately configured trail/event data store and are not guaranteed here.",
        }
    except (BotoCoreError, ClientError) as exc:
        code = exc.response.get("Error", {}).get("Code", type(exc).__name__) if isinstance(exc, ClientError) else type(exc).__name__
        return {"source": "aws", "region": region_name, "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "count": 0, "changes": [], "summary": {"events_with_detected_changes": 0, "resource_change_records": 0},
                "error": f"CloudTrail is unavailable ({code}). Check read-only IAM permissions and region configuration."}
