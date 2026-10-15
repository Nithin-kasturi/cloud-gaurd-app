"""MongoDB persistence for inventory snapshots.

Every query is scoped by tenant_id and account_id. Customer AWS credentials
are never stored; a snapshot holds only inventory metadata.

Config: MONGODB_URI (required) and MONGODB_DB (default "cloudguard").
If your project already exposes a shared Mongo `database`, replace
`get_store()` to use `database["inventory_snapshots"]` instead.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

try:
    from pymongo import DESCENDING, MongoClient
    from pymongo.errors import PyMongoError
except ImportError:  # pragma: no cover - reported at call time
    MongoClient = None
    DESCENDING = -1

    class PyMongoError(Exception):
        pass

COLLECTION = "inventory_snapshots"


class SnapshotStoreUnavailable(RuntimeError):
    """The snapshot database is not configured or cannot be reached."""


# Everything a route should translate into "snapshot storage unavailable".
STORE_ERRORS = (SnapshotStoreUnavailable, PyMongoError)


class SnapshotStore:
    def __init__(self, collection):
        self._collection = collection

    def save(self, tenant_id: str, inventory: dict[str, Any]) -> dict[str, Any]:
        if not inventory.get("account_id"):
            raise ValueError("A verified AWS account ID is required to save a snapshot.")

        document = {
            "tenant_id": tenant_id,
            "account_id": inventory["account_id"],
            "region": inventory["region"],
            "collected_at": datetime.now(timezone.utc),
            "status": inventory["status"],
            "resources": inventory["resources"],
            "coverage": inventory["coverage"],
        }
        inserted = self._collection.insert_one(document)
        return self._public(document, inserted.inserted_id)

    def latest(
        self, tenant_id: str, account_id: str, region: str, limit: int = 2
    ) -> list[dict[str, Any]]:
        cursor = (
            self._collection.find(
                {"tenant_id": tenant_id, "account_id": account_id, "region": region}
            )
            .sort("collected_at", DESCENDING)
            .limit(limit)
        )
        return [self._public(doc, doc.get("_id")) for doc in cursor]

    @staticmethod
    def _public(document: dict, snapshot_id: Any) -> dict[str, Any]:
        public = {k: v for k, v in document.items() if k != "_id"}
        public["snapshot_id"] = str(snapshot_id)
        collected = public["collected_at"]
        public["collected_at"] = (
            collected.isoformat() if isinstance(collected, datetime) else collected
        )
        return public


_store: SnapshotStore | None = None


def get_store() -> SnapshotStore:
    global _store
    if _store is not None:
        return _store

    uri = os.getenv("MONGODB_URI")
    if MongoClient is None or not uri:
        raise SnapshotStoreUnavailable(
            "Snapshot storage is not configured (install pymongo and set MONGODB_URI)."
        )

    client = MongoClient(uri, serverSelectionTimeoutMS=3000)
    collection = client[os.getenv("MONGODB_DB", "cloudguard")][COLLECTION]
    collection.create_index(
        [("tenant_id", 1), ("account_id", 1), ("region", 1), ("collected_at", -1)]
    )
    _store = SnapshotStore(collection)
    return _store