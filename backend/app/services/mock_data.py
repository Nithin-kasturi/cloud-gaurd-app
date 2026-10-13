
def get_mock_ec2_instances() -> list[dict]:
    """Sample EC2 inventory for CloudGuard development."""

    return [
        {
            "instance_id": "i-mock001",
            "instance_type": "t3.micro",
            "state": "running",
            "availability_zone": "us-east-1a",
            "launch_time": "2026-10-01T10:00:00+00:00",
            "name": "dev-web-server",
        },
        {
            "instance_id": "i-mock002",
            "instance_type": "t3.small",
            "state": "stopped",
            "availability_zone": "us-east-1b",
            "launch_time": "2026-09-20T08:30:00+00:00",
            "name": "test-server",
        },
        {
            "instance_id": "i-mock003",
            "instance_type": "m5.large",
            "state": "running",
            "availability_zone": "us-east-1c",
            "launch_time": "2026-09-15T12:00:00+00:00",
            "name": "analytics-server",
        },
    ]
