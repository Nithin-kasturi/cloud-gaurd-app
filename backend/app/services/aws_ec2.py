
import boto3
from botocore.exceptions import BotoCoreError, ClientError


def get_ec2_instances(
    profile_name: str = "cloudguard-dev",
    region_name: str = "us-east-1",
) -> list[dict]:
    """Retrieve EC2 instance metadata without modifying any resources."""

    try:
        session = boto3.Session(
            profile_name=profile_name,
            region_name=region_name,
        )
        ec2 = session.client("ec2")

        instances = []

        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instances.append({
                        "instance_id": instance["InstanceId"],
                        "instance_type": instance.get("InstanceType"),
                        "state": instance.get("State", {}).get("Name"),
                        "availability_zone": (
                            instance.get("Placement", {}).get(
                                "AvailabilityZone"
                            )
                        ),
                        "launch_time": (
                            instance["LaunchTime"].isoformat()
                            if instance.get("LaunchTime")
                            else None
                        ),
                        "name": next(
                            (
                                tag["Value"]
                                for tag in instance.get("Tags", [])
                                if tag["Key"] == "Name"
                            ),
                            None,
                        ),
                    })

        return instances

    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(
            f"Unable to retrieve EC2 instances: {exc}"
        ) from exc
