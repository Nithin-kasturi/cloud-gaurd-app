
from datetime import datetime, timezone

from pymongo.errors import PyMongoError

from app.services.mongodb import database


def save_cloudtrail_events(events: list[dict], source: str = "mock") -> dict:
    """Save CloudTrail events while avoiding duplicate event IDs."""

    collection = database["cloudtrail_events"]

    inserted_count = 0
    duplicate_count = 0

    for event in events:
        event_id = event.get("event_id")

        if not event_id:
            # Don't persist records without a stable event identifier.
            continue

        document = {
            **event,
            "source": source,
            "stored_at": datetime.now(timezone.utc),
        }

        
        try:
            result = collection.update_one(
                {
                    "event_id": event_id,
                    "source": source,
                },
                {"$setOnInsert": document},
                upsert=True,
            )

            if result.upserted_id is not None:
                inserted_count += 1
            else:
                duplicate_count += 1

        except PyMongoError as exc:
            raise RuntimeError(
                f"Unable to save CloudTrail event {event_id}"
            ) from exc

    return {
        "source": source,
        "received_count": len(events),
        "processed_count": inserted_count,
        "duplicate_count": duplicate_count,
    }


def get_recent_cloudtrail_events(limit: int = 20) -> list[dict]:
    """Return recently stored CloudTrail events."""

    collection = database["cloudtrail_events"]

    documents = collection.find(
        {},
        {"_id": 0},
    ).sort("event_time", -1).limit(limit)

    return list(documents)
