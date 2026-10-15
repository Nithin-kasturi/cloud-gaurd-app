"""Inventory routes: current state, snapshot history and diffs.

All AWS access here is read-only. Saving a snapshot writes to CloudGuard's own
database only, never to the customer's AWS account.
"""
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, HTTPException

from app import settings
from app.cache import cached
from app.inventory.diff import diff_snapshots
from app.inventory.service import collect_inventory, get_account_id
from app.inventory.snapshot_store import STORE_ERRORS, get_store
from app.mock import get_mock_ec2_instances

router = APIRouter()


def _require_source(source: str) -> None:
    if source not in ("mock", "aws"):
        raise HTTPException(status_code=400, detail="source must be 'mock' or 'aws'")


def _mock_inventory() -> dict:
    resources = [
        {
            "resource_id": item.get("instance_id", "unknown"),
            "name": item.get("name") or item.get("instance_id", "Unnamed EC2 instance"),
            "service": "EC2",
            "resource_type": "Instance",
            "status": item.get("state", "Unknown"),
            "region": item.get("availability_zone"),
            "arn": None,
            "updated_at": item.get("launch_time"),
            "details": {"instance_type": item.get("instance_type")},
        }
        for item in get_mock_ec2_instances()
    ]
    return {
        "source": "mock",
        "status": "ok",
        "count": len(resources),
        "services_monitored": ["EC2"] if resources else [],
        "service_counts": {"EC2": len(resources)} if resources else {},
        "resources": resources,
        "coverage": [],
        "warnings": [],
        "coverage_note": "Demo inventory. Live AWS inventory supports multiple services.",
    }


def _collect_live() -> dict:
    try:
        inventory = collect_inventory(settings.get_session(), settings.AWS_REGION)
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail="Unable to create an AWS session."
        ) from exc

    if inventory["status"] == "failed":
        raise HTTPException(
            status_code=502,
            detail="Every inventory collector failed. Check the read-only IAM permissions.",
        )
    return inventory


def _live_inventory(refresh: bool = False) -> dict:
    return cached(
        f"inventory:{settings.DEV_TENANT_ID}:{settings.AWS_REGION}",
        settings.CACHE_TTL_SECONDS,
        _collect_live,
        refresh=refresh,
        # Only complete results are cached; a partial one is retried next time.
        should_cache=lambda inventory: inventory["status"] == "ok",
    )


@router.get("/aws/resources")
def list_resources(source: str = "aws", refresh: bool = False):
    """Current state of every resource, plus per-collector coverage.

    Results are cached briefly; pass refresh=true to force a new AWS query.
    """
    _require_source(source)
    return _mock_inventory() if source == "mock" else _live_inventory(refresh)


@router.post("/aws/resources/snapshot")
def create_snapshot():
    """Collect live inventory, store it, and diff it against the previous snapshot."""
    inventory = _live_inventory(refresh=True)  # snapshots always use fresh data
    if not inventory["account_id"]:
        raise HTTPException(
            status_code=409,
            detail="AWS account identity could not be verified; snapshot not saved.",
        )

    try:
        store = get_store()
        previous = store.latest(
            settings.DEV_TENANT_ID, inventory["account_id"], inventory["region"], limit=1
        )
        saved = store.save(settings.DEV_TENANT_ID, inventory)
    except STORE_ERRORS as exc:
        raise HTTPException(status_code=503, detail="Snapshot storage is unavailable.") from exc

    return {
        "snapshot_id": saved["snapshot_id"],
        "collected_at": saved["collected_at"],
        "status": saved["status"],
        "count": inventory["count"],
        "changes": diff_snapshots(previous[0], saved) if previous else None,
        "message": None if previous else "First snapshot saved; nothing to compare yet.",
    }


@router.get("/aws/resources/changes")
def inventory_changes():
    """Diff of the two most recent stored snapshots for the connected account."""
    try:
        session = settings.get_session()
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502, detail="Unable to create an AWS session."
        ) from exc

    account_id, error_code = get_account_id(session)
    if not account_id:
        raise HTTPException(
            status_code=502, detail=f"AWS account identity could not be verified ({error_code})."
        )

    try:
        snapshots = get_store().latest(
            settings.DEV_TENANT_ID, account_id, settings.AWS_REGION, limit=2
        )
    except STORE_ERRORS as exc:
        raise HTTPException(status_code=503, detail="Snapshot storage is unavailable.") from exc

    if len(snapshots) < 2:
        return {
            "changes": None,
            "snapshot_count": len(snapshots),
            "message": "At least two snapshots are needed to show changes.",
        }

    newest, previous = snapshots
    return {
        "changes": diff_snapshots(previous, newest),
        "snapshot_count": len(snapshots),
        "message": None,
    }