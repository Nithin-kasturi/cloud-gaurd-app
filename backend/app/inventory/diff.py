"""Compare two inventory snapshots.

Only services that were collected successfully in BOTH snapshots are compared.
Otherwise a failed collector (e.g. AccessDenied) would make every resource of
that service look deleted.
"""
from __future__ import annotations

from typing import Any

TRACKED_FIELDS = ("name", "status", "region")

# Counters that change constantly and would flag every resource as "changed".
VOLATILE_DETAIL_KEYS = {"item_count", "size_bytes", "running_tasks", "pending_tasks"}


def resource_key(resource: dict) -> tuple[str, str, str]:
    return (resource["service"], resource["resource_type"], resource["resource_id"])


def comparable_services(snapshot: dict) -> set[str]:
    """Services whose every collector finished with status 'ok'."""
    by_service: dict[str, list[str]] = {}
    for report in snapshot.get("coverage", []):
        by_service.setdefault(report["service"], []).append(report["status"])
    return {s for s, statuses in by_service.items() if all(x == "ok" for x in statuses)}


def _field_changes(previous: dict, current: dict) -> dict[str, dict[str, Any]]:
    changes: dict[str, dict[str, Any]] = {}
    for field in TRACKED_FIELDS:
        if previous.get(field) != current.get(field):
            changes[field] = {"previous": previous.get(field), "current": current.get(field)}

    old, new = previous.get("details") or {}, current.get("details") or {}
    for key in sorted((set(old) | set(new)) - VOLATILE_DETAIL_KEYS):
        if old.get(key) != new.get(key):
            changes[f"details.{key}"] = {"previous": old.get(key), "current": new.get(key)}
    return changes


def diff_snapshots(previous: dict, current: dict) -> dict[str, Any]:
    compared = comparable_services(previous) & comparable_services(current)
    all_services = {r["service"] for r in previous.get("coverage", [])} | {
        r["service"] for r in current.get("coverage", [])
    }
    skipped = sorted(all_services - compared)

    def scoped(snapshot: dict) -> dict[tuple, dict]:
        return {
            resource_key(r): r
            for r in snapshot.get("resources", [])
            if r["service"] in compared
        }

    before, after = scoped(previous), scoped(current)

    added = [after[k] for k in sorted(after.keys() - before.keys())]
    removed = [before[k] for k in sorted(before.keys() - after.keys())]
    changed = []
    unchanged = 0
    for key in sorted(before.keys() & after.keys()):
        changes = _field_changes(before[key], after[key])
        if changes:
            changed.append({"resource": after[key], "changes": changes})
        else:
            unchanged += 1

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": unchanged,
        "compared_services": sorted(compared),
        "skipped_services": skipped,
        "previous_collected_at": previous.get("collected_at"),
        "current_collected_at": current.get("collected_at"),
    }