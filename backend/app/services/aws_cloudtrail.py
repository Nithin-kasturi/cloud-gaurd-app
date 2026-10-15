
import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def get_cloudtrail_events(
    profile_name: str = "cloudguard-dev",
    region_name: str = "us-east-1",
    max_results: int = 20,
) -> list[dict]:
    """Read recent CloudTrail management events safely."""

    try:
        session = boto3.Session(
            profile_name=profile_name,
            region_name=region_name,
        )
        client = session.client("cloudtrail")

        response = client.lookup_events(
            MaxResults=max(1, min(max_results, 50))
        )

        events = []

        for item in response.get("Events", []):
            raw_event = item.get("CloudTrailEvent")
            parsed_event = {}

            # Parse internally; never return the raw payload.
            if raw_event:
                try:
                    parsed_event = json.loads(raw_event)
                except (json.JSONDecodeError, TypeError):
                    parsed_event = {}

            identity = parsed_event.get("userIdentity") or {}

            username = item.get("Username")

            if not username:
                username = identity.get("userName")

            if not username:
                session_context = identity.get("sessionContext") or {}
                session_issuer = session_context.get("sessionIssuer") or {}

                username = (
                    session_issuer.get("userName")
                    or identity.get("principalId")
                    or identity.get("arn")
                    or identity.get("invokedBy")
                    or identity.get("type")
                    or "Unknown"
                )
            event_time = item.get("EventTime")

            events.append({
                "event_id": item.get("EventId"),
                "event_name": item.get("EventName"),
                "event_source": item.get("EventSource"),
                "event_time": (
                    event_time.isoformat() if event_time else None
                ),
                "aws_region": (
                    item.get("AwsRegion")
                    or parsed_event.get("awsRegion")
                ),
                "username": username,
                "identity_type": identity.get("type"),
                "actor_arn": identity.get("arn"),
                "read_only": parsed_event.get("readOnly"),
                "error_code": parsed_event.get("errorCode"),
                "event_category": parsed_event.get("eventCategory"),
                "source_ip": parsed_event.get("sourceIPAddress"),
            })

        return events

    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(
            f"Unable to retrieve CloudTrail events: {exc}"
        ) from exc
