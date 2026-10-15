"""Resource Activity: high-impact CloudTrail management events (read-only).

Uses CloudTrail Event History (LookupEvents), which is free. Two things keep
real changes such as CreateBucket / DeleteBucket from being crowded out:

* the request asks CloudTrail for write events only (ReadOnly=false), so
  List*/Describe*/Get* polling never takes up result slots; and
* results are paginated over a bounded time window instead of reading a
  single page of the newest 50 events.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app import settings
from app.inventory.schema import CLIENT_CONFIG

# Resource Activity shows only changes that matter most to an account owner.
# Anything not listed here (key pairs, tags, index/view setup, MFA enrolment,
# volume detach, ...) is intentionally left out. Edit this table to tune it.
IMPACT_EVENTS: dict[str, str] = {
    # Deletions: data or infrastructure that may be gone for good.
    **dict.fromkeys((
        "DeleteBucket", "TerminateInstances", "DeleteVolume", "DeleteSnapshot",
        "DeleteVpc", "DeleteSecurityGroup", "DeregisterImage", "DeleteDBInstance",
        "DeleteDBCluster", "DeleteDBSnapshot", "DeleteTable", "DeleteBackup",
        "DeleteFunction", "DeleteCluster", "DeleteNodegroup", "DeleteLoadBalancer",
        "DeleteQueue", "DeleteTopic", "DeleteSecret", "ScheduleKeyDeletion",
        "DeleteUser", "DeleteRole",
    ), "deletion"),
    # Security and access: exposure, permissions, encryption and audit trail.
    **dict.fromkeys((
        "AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules",
        "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
        "PutBucketEncryption", "DeleteBucketEncryption", "ModifySnapshotAttribute",
        "ModifyDBInstance", "CreateUser", "CreateAccessKey", "CreateLoginProfile",
        "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
        "UpdateAssumeRolePolicy", "DeactivateMFADevice", "DeleteVirtualMFADevice",
        "DisableKey", "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    ), "security"),
    # Lifecycle: resources created, started or stopped (availability and cost).
    **dict.fromkeys((
        "CreateBucket", "RunInstances", "StartInstances", "StopInstances",
        "CreateDBInstance", "CreateDBCluster", "CreateCluster", "CreateNatGateway",
        "CreateLoadBalancer",
    ), "lifecycle"),
}

# A failed attempt is shown only if an impactful action was refused (a possible
# probing or misconfiguration signal). Other failures, such as a bucket name
# that already exists, are noise.
_DENIED_MARKERS = ("denied", "unauthorized")

# Lambda event names carry an API-version suffix, e.g. DeleteFunction20150331.
_VERSION_SUFFIX = re.compile(r"\d{8}(?:v\d+)?$")

COVERAGE_NOTE = (
    "Shows high-impact management events only: deletions, security and access "
    "changes, and resources created, started or stopped. Routine reads and "
    "minor changes are omitted. Source: CloudTrail Event History for this "
    "region within the lookback window; S3 object-level and other data events "
    "need a configured trail. Zero results means no qualifying events were "
    "found, not that nothing happened."
)


def _canonical_name(event_name: str) -> str:
    return _VERSION_SUFFIX.sub("", event_name or "")


def impact_category(event_name: str | None) -> str | None:
    return IMPACT_EVENTS.get(_canonical_name(event_name or ""))


def is_high_impact(event_name: str | None) -> bool:
    return impact_category(event_name) is not None


def _classify(event_name: str, error_code: Any) -> str:
    lower = event_name.lower()
    if error_code:
        return "failed"
    if lower.startswith(("delete", "terminate", "remove", "deregister")):
        return "deleted"
    if lower.startswith(("create", "runinstances", "launch", "register", "put")):
        return "created_or_updated"
    return "modified"


def _extract_resources(item: dict, raw: dict) -> tuple[list[str], list[str]]:
    ids: list[str] = []
    types: list[str] = []

    for resource in item.get("Resources") or raw.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        rid = (resource.get("ResourceName") or resource.get("ARN")
               or resource.get("resourceName") or resource.get("arn"))
        rtype = resource.get("ResourceType") or resource.get("resourceType")
        if rid and str(rid) not in ids:
            ids.append(str(rid))
        if rtype and str(rtype) not in types:
            types.append(str(rtype))

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in resource:
                    for v in value if isinstance(value, list) else [value]:
                        if isinstance(v, (str, int)) and str(v) not in ids:
                            ids.append(str(v))
                            types.append(resource[key])
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(raw.get("requestParameters") or {})
    return ids, types


def parse_event(item: dict[str, Any]) -> dict[str, Any]:
    """Normalize one LookupEvents record. Returns {} unless it is a high-impact change."""
    try:
        raw = json.loads(item.get("CloudTrailEvent", "{}"))
    except (TypeError, json.JSONDecodeError):
        raw = {}

    event_name = item.get("EventName") or raw.get("eventName") or "UnknownEvent"
    event_source = item.get("EventSource") or raw.get("eventSource") or ""

    category = impact_category(event_name)
    read_only = raw.get("readOnly")
    if category is None or read_only is True:
        return {}

    error_code = raw.get("errorCode") or raw.get("errorCodeId")
    if error_code and not any(m in str(error_code).lower() for m in _DENIED_MARKERS):
        return {}
    action = _classify(event_name, error_code)

    identity = raw.get("userIdentity") or {}
    issuer = identity.get("sessionContext", {}).get("sessionIssuer", {}) or {}
    username = (identity.get("userName") or identity.get("principalId")
                or issuer.get("userName") or "Unknown")

    resource_ids, resource_types = _extract_resources(item, raw)

    event_time = item.get("EventTime") or raw.get("eventTime")
    if isinstance(event_time, datetime):
        event_time = event_time.astimezone(timezone.utc).isoformat()

    return {
        "event_id": item.get("EventId") or raw.get("eventID"),
        "event_name": event_name,
        "event_source": event_source or None,
        "action": action,
        "impact_category": category,
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


def get_resource_changes(
    session: boto3.Session | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    region = region or settings.AWS_REGION
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=settings.ACTIVITY_LOOKBACK_DAYS)
    window = {"start": start.isoformat(), "end": now.isoformat(),
              "lookback_days": settings.ACTIVITY_LOOKBACK_DAYS}

    scanned = 0
    truncated = False
    changes: dict[str, dict] = {}  # keyed by CloudTrail event ID

    try:
        session = session or settings.get_session()
        client = session.client("cloudtrail", config=CLIENT_CONFIG)
        pages = client.get_paginator("lookup_events").paginate(
            LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
            StartTime=start,
            EndTime=now,
            PaginationConfig={"PageSize": 50},
        )
        for page in pages:
            for item in page.get("Events", []):
                if scanned >= settings.ACTIVITY_MAX_EVENTS:
                    truncated = True
                    break
                scanned += 1
                event = parse_event(item)
                if not event:
                    continue
                key = str(event.get("event_id") or "|".join(
                    str(event.get(f)) for f in ("event_name", "event_source", "resource_id", "timestamp")
                ))
                changes.setdefault(key, event)
            if truncated:
                break
    except (BotoCoreError, ClientError) as exc:
        code = (exc.response.get("Error", {}).get("Code", type(exc).__name__)
                if isinstance(exc, ClientError) else type(exc).__name__)
        # A failure is reported as a failure, never as "no events".
        return {
            "source": "aws", "region": region, "retrieved_at": now.isoformat(),
            "status": "failed", "window": window, "count": 0, "changes": [],
            "summary": {"events_with_detected_changes": 0, "resource_change_records": 0},
            "error": f"CloudTrail is unavailable ({code}). Check read-only IAM permissions and region configuration.",
        }

    ordered = sorted(changes.values(), key=lambda e: e.get("timestamp") or "", reverse=True)
    return {
        "source": "aws", "region": region, "retrieved_at": now.isoformat(),
        "status": "partial" if truncated else "ok",
        "window": window, "scanned_events": scanned, "truncated": truncated,
        "count": len(ordered), "changes": ordered,
        "summary": {
            "events_with_detected_changes": len(ordered),
            "resource_change_records": sum(max(1, len(e["resource_ids"])) for e in ordered),
        },
        "coverage_note": COVERAGE_NOTE,
    }