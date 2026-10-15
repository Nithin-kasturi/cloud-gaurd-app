from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app import settings
from app.activity import get_resource_changes, is_high_impact
from app.cache import cached
from app.mock import get_mock_cloudtrail_events
from app.routes_inventory import router as inventory_router

app = FastAPI(title="CloudGuard AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inventory: /aws/resources, /aws/resources/snapshot, /aws/resources/changes
app.include_router(inventory_router)


def is_identifiable_activity(event: dict) -> bool:
    """A change must point at a resource to be useful in the feed."""
    return bool(
        event.get("resource_id")
        or any(event.get("resource_ids") or [])
        or event.get("resource_type")
    )


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "cloudguard-api"}


@app.get("/aws/resource-changes")
def list_resource_changes(source: str = "aws", refresh: bool = False):
    """High-impact resource activity (deletions, security changes, lifecycle).

    Results are cached briefly; pass refresh=true to force a new CloudTrail query.
    """
    if source not in ("mock", "aws"):
        raise HTTPException(status_code=400, detail="source must be 'mock' or 'aws'")

    if source == "mock":
        changes = [
            {**event, "action": "detected", "evidence_source": "CloudTrail (mock)"}
            for event in get_mock_cloudtrail_events()
            if is_high_impact(event.get("event_name")) and event.get("read_only") is not True
        ]
        return {"source": "mock", "changes": changes, "count": len(changes)}

    try:
        result = cached(
            f"activity:{settings.DEV_TENANT_ID}:{settings.AWS_REGION}",
            settings.CACHE_TTL_SECONDS,
            get_resource_changes,
            refresh=refresh,
            # Never cache a failure: the next request should retry AWS.
            should_cache=lambda value: value.get("status") == "ok",
        )
    except (RuntimeError, BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve AWS resource changes.",
        ) from exc

    changes = [e for e in result.get("changes", []) if is_identifiable_activity(e)]

    return {
        **{k: v for k, v in result.items() if k not in {"changes", "count", "summary"}},
        "source": "aws",
        "changes": changes,
        "count": len(changes),
        "summary": {
            "events_with_detected_changes": len(changes),
            "resource_change_records": len(changes),
        },
    }