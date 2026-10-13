
import boto3
from botocore.exceptions import BotoCoreError, ClientError


def get_cloudtrail_events(
    profile_name: str = "cloudguard-dev",
    region_name: str = "us-east-1",
    max_results: int = 20,
) -> list[dict]:
    """Read recent CloudTrail management events."""

    try:
        session = boto3.Session(
            profile_name=profile_name,
            region_name=region_name,
        )
        client = session.client("cloudtrail")

        response = client.lookup_events(
            MaxResults=max_results
        )

        events = []

        for item in response.get("Events", []):
            events.append({
                "event_id": item.get("EventId"),
                "event_name": item.get("EventName"),
                "event_source": item.get("EventSource"),
                "event_time": (
                    item["EventTime"].isoformat()
                    if item.get("EventTime")
                    else None
                ),
                "aws_region": item.get("AwsRegion"),
                "username": item.get("Username"),
                "cloudtrail_event": item.get("CloudTrailEvent"),
            })

        return events

    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(
            f"Unable to retrieve CloudTrail events: {exc}"
        ) from exc
