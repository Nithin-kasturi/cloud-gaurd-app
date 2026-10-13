
from fastapi import FastAPI, HTTPException
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
)
from copy import deepcopy
from fastapi.middleware.cors import CORSMiddleware
from app.services.aws_sts import get_aws_identity
from app.services.aws_ec2 import get_ec2_instances
from app.services.mock_data import get_mock_ec2_instances
from app.services.mock_events import get_mock_cloudtrail_events
from app.services.aws_cloudtrail import get_cloudtrail_events
from app.services.risk_engine import generate_findings
from app.services.mongodb import check_mongodb_connection
from datetime import datetime, timezone
from app.services.inventory_repository import (
    save_inventory_snapshot,
    get_latest_inventory_snapshot,
)
from app.services.mock_data import get_mock_ec2_instances
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
from app.services.mock_events import get_mock_cloudtrail_events
from app.services.inventory_diff import compare_latest_snapshots
app = FastAPI(title="CloudGuard AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    except NoCredentialsError:
        raise HTTPException(
            status_code=401,
            detail="AWS credentials are not configured.",
        )
    except (ClientError, BotoCoreError):
        raise HTTPException(
            status_code=502,
            detail="Unable to verify AWS identity.",
        )

        
@app.get("/aws/ec2/instances")
def list_ec2_instances(source: str = "mock"):
    if source == "mock":
        instances = get_mock_ec2_instances()

    elif source == "aws":
        try:
            instances = get_ec2_instances()
        except RuntimeError as exc:
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
        except RuntimeError as exc:
            raise HTTPException(
                status_code=502,
                detail="Unable to retrieve CloudTrail events.",
            ) from exc

    else:
        raise HTTPException(
            status_code=400,
            detail="source must be 'mock' or 'aws'",
        )

    return {
        "source": source,
        "count": len(events),
        "events": events,
    }
@app.get("/aws/findings")
def list_findings(source: str = "mock"):
    if source != "mock":
        raise HTTPException(
            status_code=400,
            detail="Only source='mock' is supported for findings currently.",
        )

    findings = generate_findings()

    return {
        "source": source,
        "count": len(findings),
        "findings": findings,
    }

@app.get("/aws/findings/summary")
def get_findings_summary(source: str = "mock"):
    if source != "mock":
        raise HTTPException(
            status_code=400,
            detail="Only source='mock' is supported for findings currently.",
        )

    findings = generate_findings()

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    category_counts = {}

    for finding in findings:
        severity = finding.get("severity", "low")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        category = finding.get("category", "other")
        category_counts[category] = category_counts.get(category, 0) + 1

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
        except RuntimeError as exc:
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
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="MongoDB connection failed. Check database configuration.",
        )


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
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    return {
        "count": len(get_inventory_history(limit)),
        "snapshots": get_inventory_history(limit),
    }

@app.get("/db/inventory/changes")
def inventory_changes():
    return compare_latest_snapshots()

@app.post("/dev/inventory/simulate-change")
def simulate_inventory_change():
    # Development-only endpoint. Never enable in production.
    instances = deepcopy(get_mock_ec2_instances())

    if instances:
        # Simulate a state change for the first instance.
        instances[0]["state"] = (
            "stopped"
            if instances[0]["state"] == "running"
            else "running"
        )

    # Simulate a newly observed EC2 instance.
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
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    events = get_recent_cloudtrail_events(limit)

    return {
        "count": len(events),
        "events": events,
    }

@app.get("/db/cloudtrail/correlations")
def cloudtrail_inventory_correlations():
    return correlate_cloudtrail_with_inventory()
