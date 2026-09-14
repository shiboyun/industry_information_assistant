"""Append-only in-memory audit chain for generic security hook events."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class HookAuditStore:
    """Small local audit store used when no database session is attached."""

    def __init__(self):
        self._events: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _hash(value: Dict[str, Any]) -> str:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def append(self, trace_id: str, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            events = self._events.setdefault(trace_id, [])
            previous_hash = events[-1]["event_hash"] if events else None
            event_hash = self._hash({
                "trace_id": trace_id,
                "event_type": event_type,
                "payload": payload,
                "previous_event_hash": previous_hash,
            })
            event = {
                "seq": len(events) + 1,
                "trace_id": trace_id,
                "event_type": event_type,
                "payload": payload,
                "previous_event_hash": previous_hash,
                "event_hash": event_hash,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            events.append(event)
            return dict(event)

    def list_events(self, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if trace_id:
                return [dict(item) for item in self._events.get(trace_id, [])]
            return [dict(item) for events in self._events.values() for item in events]

    def verify(self, trace_id: str) -> Dict[str, Any]:
        with self._lock:
            events = self._events.get(trace_id, [])
            previous_hash = None
            for event in events:
                expected = self._hash({
                    "trace_id": event["trace_id"],
                    "event_type": event["event_type"],
                    "payload": event["payload"],
                    "previous_event_hash": previous_hash,
                })
                if event["previous_event_hash"] != previous_hash or event["event_hash"] != expected:
                    return {"valid": False, "event_count": len(events), "seq": event["seq"]}
                previous_hash = event["event_hash"]
            return {"valid": True, "event_count": len(events)}

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


_hook_audit_store = HookAuditStore()


def get_hook_audit_store() -> HookAuditStore:
    return _hook_audit_store
