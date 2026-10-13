
from datetime import datetime, timedelta, timezone


def get_mock_cloudtrail_events() -> list[dict]:
    """Return sample CloudTrail events for development."""

    now = datetime.now(timezone.utc)

    return [
        {
            "event_id": "event-mock-001",
            "event_name": "RunInstances",
            "event_source": "ec2.amazonaws.com",
            "event_time": (now - timedelta(hours=2)).isoformat(),
            "aws_region": "us-east-1",
            "resource_type": "AWS::EC2::Instance",
            "resource_id": "i-mock001",
            "username": "developer",
        },
        {
            "event_id": "event-mock-002",
            "event_name": "StopInstances",
            "event_source": "ec2.amazonaws.com",
            "event_time": (now - timedelta(hours=5)).isoformat(),
            "aws_region": "us-east-1",
            "resource_type": "AWS::EC2::Instance",
            "resource_id": "i-mock002",
            "username": "developer",
        },
        {
            "event_id": "event-mock-003",
            "event_name": "TerminateInstances",
            "event_source": "ec2.amazonaws.com",
            "event_time": (now - timedelta(days=1)).isoformat(),
            "aws_region": "us-east-1",
            "resource_type": "AWS::EC2::Instance",
            "resource_id": "i-mock003",
            "username": "admin",
        },
    ]
