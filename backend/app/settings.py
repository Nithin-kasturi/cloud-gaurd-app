"""Runtime configuration. Override with environment variables; no secrets here."""
import os

import boto3

AWS_PROFILE = os.getenv("CLOUDGUARD_AWS_PROFILE", "cloudguard-dev")
AWS_REGION = os.getenv("CLOUDGUARD_AWS_REGION", "us-east-1")

# Resource Activity (CloudTrail Event History, management events only).
ACTIVITY_LOOKBACK_DAYS = int(os.getenv("CLOUDGUARD_ACTIVITY_LOOKBACK_DAYS", "14"))
ACTIVITY_MAX_EVENTS = int(os.getenv("CLOUDGUARD_ACTIVITY_MAX_EVENTS", "500"))

# Responses are cached briefly so reloading the page is fast. The Refresh
# button bypasses the cache. Set to 0 to disable caching.
CACHE_TTL_SECONDS = int(os.getenv("CLOUDGUARD_CACHE_TTL_SECONDS", "60"))

# Placeholder until authentication exists. Every snapshot query is already
# scoped by tenant_id, so real auth only has to supply this value.
DEV_TENANT_ID = os.getenv("CLOUDGUARD_DEV_TENANT_ID", "dev")


def get_session() -> boto3.Session:
    """Single place that builds the AWS session.

    When STS AssumeRole is added, only this function changes; collectors
    receive a session and never build their own.
    """
    return boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)