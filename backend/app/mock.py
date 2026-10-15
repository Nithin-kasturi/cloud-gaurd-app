"""Demo data for the "Demo data" source. Never mixed with live AWS data."""


def get_mock_ec2_instances() -> list[dict]:
    return [
        {"instance_id": "i-mock001", "name": "web-server", "state": "running",
         "instance_type": "t3.micro", "availability_zone": "us-east-1a",
         "launch_time": "2026-09-01T08:00:00+00:00"},
        {"instance_id": "i-mock002", "name": "batch-worker", "state": "stopped",
         "instance_type": "t3.small", "availability_zone": "us-east-1b",
         "launch_time": "2026-09-10T09:30:00+00:00"},
        {"instance_id": "i-mock003", "name": "database-proxy", "state": "running",
         "instance_type": "t3.medium", "availability_zone": "us-east-1a",
         "launch_time": "2026-09-15T11:15:00+00:00"},
    ]


def get_mock_cloudtrail_events() -> list[dict]:
    return [
        {"event_id": "mock-evt-1", "event_name": "CreateBucket",
         "event_source": "s3.amazonaws.com", "timestamp": "2026-10-14T12:00:00+00:00",
         "resource_id": "demo-assets-bucket", "resource_ids": ["demo-assets-bucket"],
         "resource_type": "S3 bucket", "actor": "demo-admin", "aws_region": "us-east-1",
         "read_only": False, "error_code": None},
        {"event_id": "mock-evt-2", "event_name": "StopInstances",
         "event_source": "ec2.amazonaws.com", "timestamp": "2026-10-14T13:30:00+00:00",
         "resource_id": "i-mock002", "resource_ids": ["i-mock002"],
         "resource_type": "EC2 instance", "actor": "demo-admin", "aws_region": "us-east-1",
         "read_only": False, "error_code": None},
        {"event_id": "mock-evt-3", "event_name": "DescribeInstances",
         "event_source": "ec2.amazonaws.com", "timestamp": "2026-10-14T13:31:00+00:00",
         "resource_id": None, "resource_ids": [], "resource_type": None,
         "actor": "demo-admin", "aws_region": "us-east-1", "read_only": True,
         "error_code": None},
    ]