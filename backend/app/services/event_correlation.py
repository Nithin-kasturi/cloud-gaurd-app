
import json

from app.services.mongodb import database


def correlate_cloudtrail_with_inventory() -> dict:
    """Match CloudTrail event resource IDs to EC2 inventory records."""

    events_collection = database["cloudtrail_events"]
    snapshots_collection = database["inventory_snapshots"]

    latest_snapshot = snapshots_collection.find_one(
        {"resource_type": "ec2"},
        sort=[("created_at", -1)],
    )

    if latest_snapshot is None:
        return {
            "message": "No EC2 inventory snapshot is available.",
            "correlations": [],
        }

    instances = {
        instance["instance_id"]: instance
        for instance in latest_snapshot.get("instances", [])
        if instance.get("instance_id")
    }

    events = list(
        events_collection.find(
            {"source": "mock"},
            {"_id": 0},
        ).sort("event_time", -1).limit(100)
    )

    correlations = []

    for event in events:
        raw_event = event.get("cloudtrail_event")
        event_resource_ids = set()

        # CloudTrail's raw event payload is usually a JSON string.
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except json.JSONDecodeError:
                raw_event = {}

        if isinstance(raw_event, dict):
            for resource in raw_event.get("resources", []):
                resource_name = resource.get("resourceName")
                if resource_name:
                    event_resource_ids.add(resource_name)

            request_parameters = raw_event.get("requestParameters") or {}
            instance_ids = request_parameters.get("instancesSet", {}).get(
                "items", []
            )

            for item in instance_ids:
                instance_id = item.get("instanceId")
                if instance_id:
                    event_resource_ids.add(instance_id)

        # Some mock events may expose resource_id directly.
        if event.get("resource_id"):
            event_resource_ids.add(event["resource_id"])

        for resource_id in event_resource_ids:
            if resource_id not in instances:
                continue

            instance = instances[resource_id]

            correlations.append({
                "event_id": event.get("event_id"),
                "event_name": event.get("event_name"),
                "event_time": event.get("event_time"),
                "resource_id": resource_id,
                "instance_name": instance.get("name"),
                "current_state": instance.get("state"),
                "evidence": (
                    "CloudTrail event references an instance present "
                    "in the latest inventory snapshot."
                ),
                "causal_relationship_confirmed": False,
            })

    return {
        "snapshot_id": str(latest_snapshot["_id"]),
        "inventory_instance_count": len(instances),
        "correlation_count": len(correlations),
        "correlations": correlations,
    }
