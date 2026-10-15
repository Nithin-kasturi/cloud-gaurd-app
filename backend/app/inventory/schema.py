"""Shared inventory schema and collector plumbing (read-only AWS access)."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.config import Config

# Adaptive retries handle throttling without custom retry code in each collector.
CLIENT_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})

# Collectors run in parallel; creating clients from one Session is not thread-safe.
_CLIENT_LOCK = threading.Lock()


def iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def make_resource(
    service: str,
    resource_type: str,
    resource_id: str | None,
    name: str | None = None,
    status: str | None = None,
    region: str | None = None,
    arn: str | None = None,
    updated_at: Any = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "resource_id": resource_id or name or "unknown",
        "name": name or resource_id or "Unnamed resource",
        "service": service,
        "resource_type": resource_type,
        "status": status or "Unknown",
        "region": region,
        "arn": arn,
        "updated_at": iso(updated_at),
        "details": details or {},
    }


@dataclass
class CollectionContext:
    """What a collector receives. `notes` marks a result as partial."""

    session: boto3.Session
    region: str
    notes: list[str] = field(default_factory=list)

    def client(self, service_name: str):
        with _CLIENT_LOCK:
            return self.session.client(service_name, config=CLIENT_CONFIG)


@dataclass
class CollectorReport:
    """Per-collector coverage, so a failure is never read as 'no resources'."""

    collector: str
    service: str
    status: str  # "ok" | "partial" | "failed"
    resource_count: int
    permissions: list[str]
    error_code: str | None = None
    message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "collector": self.collector,
            "service": self.service,
            "status": self.status,
            "resource_count": self.resource_count,
            "permissions": self.permissions,
            "error_code": self.error_code,
            "message": self.message,
        }