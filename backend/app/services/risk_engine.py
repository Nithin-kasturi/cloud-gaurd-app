
from datetime import datetime, timedelta, timezone

from app.services.mock_data import get_mock_ec2_instances
from app.services.mock_events import get_mock_cloudtrail_events


def generate_findings() -> list[dict]:
    """Generate explainable, read-only CloudGuard findings."""
    instances = get_mock_ec2_instances()
    events = get_mock_cloudtrail_events()

    findings = []

    # Rule 1: Stopped EC2 instances
    for instance in instances:
        if instance.get("state") == "stopped":
            findings.append({
                "finding_id": f"stopped-{instance['instance_id']}",
                "category": "stopped_instance",
                "severity": "medium",
                "resource_id": instance["instance_id"],
                "resource_type": "AWS::EC2::Instance",
                "title": "Stopped EC2 instance",
                "description": (
                    f"Instance {instance['instance_id']} is stopped."
                ),
                "recommendation": (
                    "Confirm whether this instance is still needed. "
                    "Stopped instances can still incur EBS storage charges."
                ),
            })

    # Rule 2: Instances that may warrant a sizing review
    # Instance type alone does not prove that a resource is oversized.
    larger_instance_types = {
        "m5.large",
        "m5.xlarge",
        "m5.2xlarge",
        "m5.4xlarge",
        "m5.8xlarge",
        "m5.12xlarge",
        "m5.16xlarge",
        "m5.24xlarge",
    }

    for instance in instances:
        if instance.get("instance_type") in larger_instance_types:
            findings.append({
                "finding_id": f"sizing-{instance['instance_id']}",
                "category": "sizing_review",
                "severity": "low",
                "resource_id": instance["instance_id"],
                "resource_type": "AWS::EC2::Instance",
                "title": "Review instance sizing",
                "description": (
                    f"Instance {instance['instance_id']} uses "
                    f"{instance['instance_type']}."
                ),
                "recommendation": (
                    "Review CPU and memory utilization, workload "
                    "requirements, and cost before considering a "
                    "smaller instance type."
                ),
            })

    # Rule 3: Recent resource changes from CloudTrail
    now = datetime.now(timezone.utc)
    recent_window = now - timedelta(hours=24)

    tracked_events = {
        "RunInstances",
        "StopInstances",
        "TerminateInstances",
    }

    for event in events:
        if event.get("event_name") not in tracked_events:
            continue

        event_time = event.get("event_time")
        if not event_time:
            continue

        try:
            parsed_time = datetime.fromisoformat(
                event_time.replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            continue

        if parsed_time < recent_window or parsed_time > now:
            continue

        resource_id = event.get("resource_id")
        event_name = event["event_name"]

        descriptions = {
            "RunInstances": "An EC2 instance launch was recorded.",
            "StopInstances": "An EC2 instance stop was recorded.",
            "TerminateInstances": (
                "An EC2 instance termination event was recorded."
            ),
        }

        findings.append({
            "finding_id": f"event-{event['event_id']}",
            "category": "resource_change",
            "severity": "low",
            "resource_id": resource_id,
            "resource_type": event.get(
                "resource_type", "AWS::EC2::Instance"
            ),
            "title": f"Recent change: {event_name}",
            "description": descriptions[event_name],
            "recommendation": (
                "Verify that this change was expected and authorized. "
                "Refresh the inventory to confirm the resource's "
                "current state."
            ),
            "event_time": event_time,
        })

    return findings
