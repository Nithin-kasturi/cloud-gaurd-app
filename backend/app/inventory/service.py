"""Runs the registered collectors and reports honest coverage."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.inventory.collectors import COLLECTORS, Collector
from app.inventory.schema import CollectionContext, CollectorReport

MAX_PARALLEL_COLLECTORS = 8

COVERAGE_NOTE = (
    "Best-effort inventory for the supported services listed in `coverage`. "
    "A collector marked partial or failed means its resources may be missing "
    "or incomplete; that is not the same as the account having none."
)


def _error_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "ClientError")
    return type(exc).__name__


def get_account_id(session: boto3.Session) -> tuple[str | None, str | None]:
    """Verify identity with STS. Returns (account_id, error_code)."""
    try:
        identity = session.client("sts").get_caller_identity()
        return identity.get("Account"), None
    except (BotoCoreError, ClientError) as exc:
        return None, _error_code(exc)


def run_collector(collector: Collector, session: boto3.Session, region: str):
    ctx = CollectionContext(session=session, region=region)
    try:
        resources = collector.fn(ctx)
    except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as exc:
        code = _error_code(exc)
        # Only the error code is surfaced: SDK messages can contain request data.
        return [], CollectorReport(
            collector.label, collector.service, "failed", 0,
            list(collector.permissions), code,
            f"{collector.label}: unavailable ({code}). "
            "Check read-only IAM permissions and region support.",
        )

    status = "partial" if ctx.notes else "ok"
    return resources, CollectorReport(
        collector.label, collector.service, status, len(resources),
        list(collector.permissions), None,
        f"{collector.label}: {'; '.join(ctx.notes)}" if ctx.notes else None,
    )


def collect_inventory(
    session: boto3.Session,
    region: str,
    collectors: list[Collector] | None = None,
) -> dict[str, Any]:
    collectors = COLLECTORS if collectors is None else collectors
    account_id, identity_error = get_account_id(session)

    resources: list[dict] = []
    reports: list[CollectorReport] = []
    # Collectors are independent network calls; run them in parallel.
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_COLLECTORS) as pool:
        outcomes = list(pool.map(lambda c: run_collector(c, session, region), collectors))
    for found, report in outcomes:  # map() preserves collector order
        resources.extend(found)
        reports.append(report)

    unique = {(r["service"], r["resource_type"], r["resource_id"]): r for r in resources}
    resources = sorted(
        unique.values(), key=lambda r: (r["service"].lower(), r["name"].lower())
    )

    service_counts: dict[str, int] = {}
    for item in resources:
        service_counts[item["service"]] = service_counts.get(item["service"], 0) + 1

    warnings = [r.message for r in reports if r.status != "ok" and r.message]
    if identity_error:
        warnings.append(
            f"Account identity could not be verified ({identity_error}); "
            "snapshots are disabled."
        )

    if reports and all(r.status == "failed" for r in reports):
        status = "failed"
    elif any(r.status != "ok" for r in reports):
        status = "partial"
    else:
        status = "ok"

    return {
        "source": "aws",
        "account_id": account_id,
        "region": region,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "count": len(resources),
        "services_monitored": sorted(service_counts),
        "service_counts": service_counts,
        "resources": resources,
        "coverage": [r.as_dict() for r in reports],
        "warnings": warnings,
        "coverage_note": COVERAGE_NOTE,
    }