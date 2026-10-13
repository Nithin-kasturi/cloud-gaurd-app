
import boto3
from botocore.exceptions import BotoCoreError, ClientError


def get_aws_identity(profile_name: str = "cloudguard-dev") -> dict:
    """
    Return the AWS identity associated with the local development profile.
    Intended for local development, not customer-account connections.
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client("sts")

        identity = sts.get_caller_identity()

        return {
            "account": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }

    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(
            f"Unable to retrieve AWS identity: {exc}"
        ) from exc
