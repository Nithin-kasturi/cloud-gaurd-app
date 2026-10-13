
from app.services.mongodb import database


TRACKED_FIELDS = [
    "instance_type",
    "state",
    "availability_zone",
    "name",
]


def compare_latest_snapshots() -> dict:
    """Compare the two latest EC2 inventory snapshots."""

    collection = database["inventory_snapshots"]

    snapshots = list(
        collection.find(
            {"resource_type": "ec2"}
        )
        .sort("created_at", -1)
        .limit(2)
    )

    if len(snapshots) < 2:
        return {
            "message": "At least two snapshots are required.",
            "new_instances": [],
            "missing_instances": [],
            "changed_instances": [],
            "unchanged_count": 0,
        }

    latest, previous = snapshots[0], snapshots[1]

    # Do not compare inventories from different AWS accounts.
    if latest.get("account_id") != previous.get("account_id"):
        return {
            "message": (
                "Snapshots belong to different accounts "
                "and cannot be compared."
            ),
            "new_instances": [],
            "missing_instances": [],
            "changed_instances": [],
            "unchanged_count": 0,
        }

    previous_instances = {
        instance["instance_id"]: instance
        for instance in previous.get("instances", [])
    }

    latest_instances = {
        instance["instance_id"]: instance
        for instance in latest.get("instances", [])
    }

    new_instances = []
    missing_instances = []
    changed_instances = []
    unchanged_count = 0

    for instance_id, current in latest_instances.items():
        old = previous_instances.get(instance_id)

        if old is None:
            new_instances.append(current)
            continue

        changes = {
            field: {
                "previous": old.get(field),
                "current": current.get(field),
            }
            for field in TRACKED_FIELDS
            if old.get(field) != current.get(field)
        }

        if changes:
            changed_instances.append({
                "instance_id": instance_id,
                "changes": changes,
            })
        else:
            unchanged_count += 1

    for instance_id, old in previous_instances.items():
        if instance_id not in latest_instances:
            missing_instances.append(old)

    return {
        "previous_snapshot_id": str(previous["_id"]),
        "latest_snapshot_id": str(latest["_id"]),
        "previous_snapshot_at": previous["created_at"].isoformat(),
        "latest_snapshot_at": latest["created_at"].isoformat(),
        "new_instances": new_instances,
        "missing_instances": missing_instances,
        "changed_instances": changed_instances,
        "unchanged_count": unchanged_count,
    }
