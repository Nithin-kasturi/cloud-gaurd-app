from copy import deepcopy
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from app.services.aws_sts import get_aws_identity
from app.services.aws_ec2 import get_ec2_instances
from app.services.aws_cloudtrail import get_cloudtrail_events
from app.services.aws_resource_monitor import get_resource_changes
from app.services.mock_data import get_mock_ec2_instances
from app.services.mock_events import get_mock_cloudtrail_events
from app.services.risk_engine import generate_findings
from app.services.mongodb import check_mongodb_connection
from app.services.aws_resource_monitor import get_resource_inventory
from app.services.inventory_repository import (
    save_inventory_snapshot,
    get_latest_inventory_snapshot,
    get_inventory_history,
)
from app.services.cloudtrail_repository import (
    save_cloudtrail_events,
    get_recent_cloudtrail_events,
)
from app.services.event_correlation import (
    correlate_cloudtrail_with_inventory,
)
from app.services.inventory_diff import compare_latest_snapshots


app = FastAPI(title="CloudGuard AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# These events indicate possible resource mutations.
# Routine describe/list/get/lookup calls are intentionally excluded.
MUTATION_PREFIXES = (
    "create",
    "delete",
    "modify",
    "update",
    "put",
    "authorize",
    "revoke",
    "attach",
    "detach",
    "restore",
    "start",
    "stop",
    "reboot",
    "runinstances",
    "terminate",
    "launch",
    "tag",
    "untag",
    "add",
    "remove",
    "associate",
    "disassociate",
    "enable",
    "disable",
    "rotate",
    "register",
    "deregister",
    "change",
    "reset",
    "set",
)


def is_resource_change_event(event: dict) -> bool:
    """Keep potential mutation events; exclude routine read operations."""
    event_name = str(event.get("event_name") or "").lower()

    if not event_name:
        return False

    if event.get("read_only") is True:
        return False

    return event_name.startswith(MUTATION_PREFIXES)


def get_source_data(source: str):
    if source == "mock":
        return get_mock_ec2_instances(), get_mock_cloudtrail_events()

    if source == "aws":
        try:
            instances = get_ec2_instances()
            events = get_cloudtrail_events()
            return instances, events
        except (RuntimeError, BotoCoreError, ClientError) as exc:
            raise HTTPException(
                status_code=502,
                detail="Unable to retrieve live AWS data.",
            ) from exc

    raise HTTPException(
        status_code=400,
        detail="source must be 'mock' or 'aws'",
    )


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "cloudguard-api",
    }


@app.get("/api/aws/identity")
def aws_identity():
    try:
        return {
            "connected": True,
            "identity": get_aws_identity(),
        }
    except NoCredentialsError as exc:
        raise HTTPException(
            status_code=401,
            detail="AWS credentials are not configured.",
        ) from exc
    except (ClientError, BotoCoreError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to verify AWS identity.",
        ) from exc


@app.get("/aws/ec2/instances")
def list_ec2_instances(source: str = "aws"):
    if source == "mock":
        instances = get_mock_ec2_instances()
    elif source == "aws":
        try:
            instances = get_ec2_instances()
        except (RuntimeError, BotoCoreError, ClientError) as exc:
            raise HTTPException(
                status_code=502,
                detail="Unable to retrieve live EC2 instances.",
            ) from exc
    else:
        raise HTTPException(
            status_code=400,
            detail="source must be 'mock' or 'aws'",
        )

    return {
        "source": source,
        "count": len(instances),
        "instances": instances,
    }


@app.get("/aws/cloudtrail/events")
def list_cloudtrail_events(source: str = "mock"):
    if source == "mock":
        events = get_mock_cloudtrail_events()
    elif source == "aws":
        try:
            events = get_cloudtrail_events()
        except (RuntimeError, BotoCoreError, ClientError) as exc:
            raise HTTPException(
                status_code=502,
                detail="Unable to retrieve CloudTrail events.",
            ) from exc
    else:
        raise HTTPException(
            status_code=400,
            detail="source must be 'mock' or 'aws'",
        )

    # Defense in depth: don't send routine API calls to the UI.
    filtered_events = [
        event for event in events
        if is_resource_change_event(event)
    ]

    return {
        "source": source,
        "count": len(filtered_events),
        "events": filtered_events,
    }


@app.get("/aws/resource-changes")
def list_resource_changes(source: str = "aws"):
    """
    Unified change feed. Uses the centralized monitor for live AWS data.
    """
    if source == "mock":
        events = get_mock_cloudtrail_events()
        changes = [
            {
                **event,
                "action": "detected",
                "evidence_source": "CloudTrail (mock)",
            }
            for event in events
            if is_resource_change_event(event)
        ]

        return {
            "source": "mock",
            "changes": changes,
            "count": len(changes),
        }

    if source != "aws":
        raise HTTPException(
            status_code=400,
            detail="source must be 'mock' or 'aws'",
        )

    try:
        
        result = get_resource_changes()

        changes = result.get("changes", [])

        def should_show_activity(event: dict) -> bool:
            read_only = event.get("read_only", event.get("ReadOnly", False))

            if isinstance(read_only, str):
                read_only = read_only.strip().lower() == "true"

            if read_only is True:
                return False

            event_name = event.get("event_name") or event.get("EventName")
            if not event_name:
                return False

            resource_id = event.get("resource_id")
            resource_ids = event.get("resource_ids") or []
            resource_type = event.get("resource_type")

            # Include only events tied to an identifiable resource.
            if not (resource_id or any(resource_ids) or resource_type):
                return False

            return True

        filtered_changes = [
            event for event in changes
            if should_show_activity(event)
        ]

        response = {
            key: value
            for key, value in result.items()
            if key not in {"changes", "count", "summary"}
        }

        response["changes"] = filtered_changes
        response["count"] = len(filtered_changes)
        response["summary"] = {
            "events_with_detected_changes": len(filtered_changes),
            "resource_change_records": len(filtered_changes),
        }

        return {
            "source": "aws",
            **response,
        }

    except (RuntimeError, BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve AWS resource changes.",
        ) from exc



@app.get("/aws/findings")
def list_findings(source: str = "mock"):
    instances, events = get_source_data(source)

    relevant_events = [
        event for event in events
        if is_resource_change_event(event)
    ]

    findings = generate_findings(instances, relevant_events)

    return {
        "source": source,
        "count": len(findings),
        "findings": findings,
    }


@app.get("/aws/findings/summary")
def get_findings_summary(source: str = "mock"):
    instances, events = get_source_data(source)

    relevant_events = [
        event for event in events
        if is_resource_change_event(event)
    ]

    findings = generate_findings(instances, relevant_events)

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    category_counts = {}

    for finding in findings:
        severity = str(finding.get("severity", "low")).lower()
        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

        category = finding.get("category", "other")
        category_counts[category] = (
            category_counts.get(category, 0) + 1
        )

    return {
        "source": source,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
    }


@app.get("/aws/ec2/inventory")
def get_ec2_inventory(source: str = "mock"):
    if source == "mock":
        instances = get_mock_ec2_instances()
    elif source == "aws":
        try:
            instances = get_ec2_instances()
        except (RuntimeError, BotoCoreError, ClientError) as exc:
            raise HTTPException(
                status_code=502,
                detail="Unable to retrieve EC2 inventory from AWS.",
            ) from exc
    else:
        raise HTTPException(
            status_code=400,
            detail="source must be 'mock' or 'aws'",
        )

    state_counts = {}

    for instance in instances:
        state = instance.get("state", "unknown")
        state_counts[state] = state_counts.get(state, 0) + 1

    return {
        "source": source,
        "count": len(instances),
        "state_counts": state_counts,
        "instances": instances,
    }


@app.get("/db/health")
def database_health():
    try:
        return check_mongodb_connection()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="MongoDB connection failed. Check database configuration.",
        ) from exc


@app.post("/db/inventory/snapshots")
def create_inventory_snapshot():
    instances = get_mock_ec2_instances()

    return save_inventory_snapshot(
        instances=instances,
        source="mock",
    )


@app.get("/db/inventory/snapshots/latest")
def latest_inventory_snapshot():
    snapshot = get_latest_inventory_snapshot()

    if snapshot is None:
        raise HTTPException(
            status_code=404,
            detail="No inventory snapshots found.",
        )

    return snapshot


@app.get("/db/inventory/snapshots/history")
def inventory_snapshot_history(limit: int = 10):
    if not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    snapshots = get_inventory_history(limit)

    return {
        "count": len(snapshots),
        "snapshots": snapshots,
    }


@app.get("/db/inventory/changes")
def inventory_changes():
    return compare_latest_snapshots()


@app.post("/dev/inventory/simulate-change")
def simulate_inventory_change():
    # Development-only endpoint. Do not expose in production.
    instances = deepcopy(get_mock_ec2_instances())

    if instances:
        instances[0]["state"] = (
            "stopped"
            if instances[0]["state"] == "running"
            else "running"
        )

    instances.append({
        "instance_id": "i-mock004",
        "instance_type": "t3.micro",
        "state": "running",
        "availability_zone": "us-east-1a",
        "launch_time": datetime.now(timezone.utc).isoformat(),
        "name": "simulated-new-server",
    })

    return save_inventory_snapshot(
        instances=instances,
        source="mock",
    )


@app.post("/db/cloudtrail/sync")
def sync_cloudtrail_events():
    events = get_mock_cloudtrail_events()

    return save_cloudtrail_events(
        events=events,
        source="mock",
    )


@app.get("/db/cloudtrail/events")
def stored_cloudtrail_events(limit: int = 20):
    if not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    events = get_recent_cloudtrail_events(limit)

    filtered_events = [
        event for event in events
        if is_resource_change_event(event)
    ]

    return {
        "count": len(filtered_events),
        "events": filtered_events,
    }


@app.get("/db/cloudtrail/correlations")
def cloudtrail_inventory_correlations():
    return correlate_cloudtrail_with_inventory()



@app.get("/aws/resources")
def aws_resources(source: str = "aws"):
    if source == "mock":
        # Reuse your existing mock inventory/event fixtures. Map them to the
        # generic resource shape used by frontend/src/api.ts; don't call AWS.
        resources = []
        for item in MOCK_EC2_INSTANCES:  # replace with your existing mock list name
            resources.append({
                "resource_id": item.get("instance_id", "unknown"),
                "name": item.get("name") or item.get("instance_id", "Unnamed EC2 instance"),
                "service": "EC2",
                "resource_type": "Instance",
                "status": item.get("state", "Unknown"),
                "region": item.get("availability_zone"),
                "arn": None,
                "updated_at": item.get("launch_time"),
                "details": {"instance_type": item.get("instance_type")},
            })
        counts = {}
        for resource in resources:
            counts[resource["service"]] = counts.get(resource["service"], 0) + 1
        return {"source": "mock", "count": len(resources),
                "services_monitored": sorted(counts), "service_counts": counts,
                "resources": resources, "warnings": [],
                "coverage_note": "Demo inventory. Live AWS inventory supports multiple services."}

    result = get_resource_inventory(profile_name="cloudguard-dev", region_name="us-east-1")
    return result
