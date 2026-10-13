
from datetime import datetime, timezone

from app.services.mongodb import database


def save_inventory_snapshot(
    instances: list[dict],
    source: str = "mock",
    account_id: str | None = None,
) -> dict:
    """Persist an EC2 inventory snapshot in MongoDB."""

    collection = database["inventory_snapshots"]

    snapshot = {
        "source": source,
        "account_id": account_id,
        "resource_type": "ec2",
        "instance_count": len(instances),
        "instances": instances,
        "created_at": datetime.now(timezone.utc),
    }

    result = collection.insert_one(snapshot)

    return {
        "snapshot_id": str(result.inserted_id),
        "source": source,
        "resource_type": "ec2",
        "instance_count": len(instances),
        "created_at": snapshot["created_at"].isoformat(),
    }


def get_latest_inventory_snapshot() -> dict | None:
    """Return the latest EC2 inventory snapshot."""

    collection = database["inventory_snapshots"]

    snapshot = collection.find_one(
        {"resource_type": "ec2"},
        sort=[("created_at", -1)],
    )

    if snapshot is None:
        return None

    return {
        "snapshot_id": str(snapshot["_id"]),
        "source": snapshot["source"],
        "account_id": snapshot.get("account_id"),
        "resource_type": snapshot["resource_type"],
        "instance_count": snapshot["instance_count"],
        "instances": snapshot["instances"],
        "created_at": snapshot["created_at"].isoformat(),
    }

def get_inventory_history(limit: int = 10) -> list[dict]:
    """Return recent EC2 inventory snapshots, newest first."""

    collection = database["inventory_snapshots"]

    snapshots = collection.find(
        {"resource_type": "ec2"}
    ).sort("created_at", -1).limit(limit)

    return [
        {
            "snapshot_id": str(snapshot["_id"]),
            "source": snapshot["source"],
            "account_id": snapshot.get("account_id"),
            "resource_type": snapshot["resource_type"],
            "instance_count": snapshot["instance_count"],
            "created_at": snapshot["created_at"].isoformat(),
        }
        for snapshot in snapshots
    ]
