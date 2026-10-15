
from datetime import datetime, timedelta, timezone


def generate_findings(
    instances: list[dict],
    events: list[dict],
) -> list[dict]:
    """Generate explainable advisory findings without modifying AWS."""

    findings = []
    now = datetime.now(timezone.utc)
    recent_window = now - timedelta(hours=24)

    def parse_event_time(event: dict):
        value = event.get("event_time")
        if not value:
            return None

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (ValueError, TypeError, AttributeError):
            return None

    def is_recent(event: dict) -> bool:
        event_time = parse_event_time(event)
        return event_time is not None and recent_window <= event_time <= now

    def add_event_finding(
        event: dict,
        category: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
    ):
        event_id = event.get("event_id")
        if not event_id:
            return

        findings.append({
            "finding_id": f"{category}-{event_id}",
            "category": category,
            "severity": severity,
            "resource_id": event.get("resource_id"),
            "resource_type": event.get(
                "resource_type", "AWS resource"
            ),
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "event_time": event.get("event_time"),
        })

    # Rule 1: Stopped EC2 instances
    for instance in instances:
        if instance.get("state", "").lower() == "stopped":
            instance_id = instance.get("instance_id", "unknown")
            findings.append({
                "finding_id": f"stopped-{instance_id}",
                "category": "stopped_instance",
                "severity": "medium",
                "resource_id": instance_id,
                "resource_type": "AWS::EC2::Instance",
                "title": "Stopped EC2 instance",
                "description": (
                    f"Instance {instance_id} is currently stopped."
                ),
                "recommendation": (
                    "Confirm whether the instance is still needed. "
                    "EBS volumes and other attached resources may "
                    "continue to incur charges."
                ),
            })

    # Rule 2: Potential EC2 sizing review
    larger_instance_types = {
        "m5.large", "m5.xlarge", "m5.2xlarge", "m5.4xlarge",
        "m5.8xlarge", "m5.12xlarge", "m5.16xlarge", "m5.24xlarge",
    }

    for instance in instances:
        instance_type = instance.get("instance_type")
        if instance_type in larger_instance_types:
            instance_id = instance.get("instance_id", "unknown")
            findings.append({
                "finding_id": f"sizing-{instance_id}",
                "category": "sizing_review",
                "severity": "low",
                "resource_id": instance_id,
                "resource_type": "AWS::EC2::Instance",
                "title": "Review instance sizing",
                "description": (
                    f"Instance {instance_id} uses {instance_type}; "
                    "its workload utilization has not been evaluated."
                ),
                "recommendation": (
                    "Review CloudWatch CPU and memory-related metrics, "
                    "workload requirements, and costs before resizing."
                ),
            })

    # Rule 3: Recent resource-changing and security-sensitive events
    event_rules = {
        "RunInstances": (
            "resource_change", "low", "EC2 instance launch recorded",
            "CloudTrail recorded an EC2 instance launch operation.",
            "Confirm the launch was authorized and reconcile the "
            "event with current EC2 inventory and cost."
        ),
        "StopInstances": (
            "resource_change", "low", "EC2 instance stop recorded",
            "CloudTrail recorded an EC2 instance stop operation.",
            "Verify that the stop was expected and check the "
            "instance's current state."
        ),
        "TerminateInstances": (
            "resource_change", "medium",
            "EC2 termination operation recorded",
            "CloudTrail recorded an EC2 instance termination operation.",
            "Verify authorization and confirm the current inventory. "
            "This event alone does not prove termination succeeded."
        ),
        "CreateSecurityGroup": (
            "security_change", "medium", "Security group created",
            "A security group creation operation was recorded.",
            "Confirm the change was authorized and review the group's "
            "inbound and outbound rules."
        ),
        "AuthorizeSecurityGroupIngress": (
            "security_change", "medium",
            "Inbound security-group rule change",
            "An operation to authorize an inbound security-group rule "
            "was recorded. The allowed ports and source ranges have "
            "not been evaluated by this rule.",
            "Inspect the resulting rule. Pay particular attention to "
            "sensitive ports exposed to 0.0.0.0/0 or ::/0."
        ),
        "CreateKeyPair": (
            "security_change", "low", "EC2 key pair created",
            "An EC2 key-pair creation operation was recorded.",
            "Verify who requested it and ensure private-key material "
            "is handled securely."
        ),
    }

    seen_event_ids = set()

    for event in events:
        event_name = event.get("event_name")
        event_id = event.get("event_id")

        if not event_id or event_id in seen_event_ids:
            continue
        seen_event_ids.add(event_id)

        if not is_recent(event):
            continue

        # Do not treat failed operations as confirmed changes.
        error_code = event.get("error_code")
        if error_code:
            continue

        rule = event_rules.get(event_name)
        if rule:
            category, severity, title, description, recommendation = rule
            add_event_finding(
                event, category, severity, title, description,
                recommendation,
            )
    # Consolidate root activity into one advisory per evaluation.
    root_events = [
        event for event in events
        if event.get("identity_type") == "Root"
        and is_recent(event)
        and not event.get("error_code")
    ]

    if root_events:
        latest_root_event = max(
            root_events,
            key=lambda event: parse_event_time(event) or now,
        )

        add_event_finding(
            latest_root_event,
            "root_account_activity",
            "medium",
            "Root account activity observed",
            (
                f"{len(root_events)} successful-looking CloudTrail event(s) "
                "were recorded under the AWS root identity in the last 24 hours. "
                "An absent error code does not independently prove success."
            ),
            (
                "Verify that the activity was expected. Use a least-privilege "
                "IAM identity for routine development and reserve root access "
                "for tasks that require it."
            ),
        )
    return findings
