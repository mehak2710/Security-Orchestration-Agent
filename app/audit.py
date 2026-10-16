import hashlib, json, threading, time
from . import db

_lock = threading.Lock()

def _hash(prev, ts, event, iid, body):
    return hashlib.sha256(f"{prev}|{ts!r}|{event}|{iid}|{body}".encode()).hexdigest()

def log(event, incident_id, payload):
    with _lock:
        last = db.one("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
        prev = last["hash"] if last else "GENESIS"
        ts, body = time.time(), json.dumps(payload, sort_keys=True, default=str)
        db.insert("audit_log", {"ts": ts, "event": event, "incident_id": incident_id, "payload": body,
                                "prev_hash": prev, "hash": _hash(prev, ts, event, incident_id, body)})

def verify():
    prev = "GENESIS"
    rows = db.q("SELECT * FROM audit_log ORDER BY id")
    for r in rows:
        if r["prev_hash"] != prev or r["hash"] != _hash(prev, r["ts"], r["event"], r["incident_id"], r["payload"]):
            return {"valid": False, "entries": len(rows), "broken_at": r["id"]}
        prev = r["hash"]
    return {"valid": True, "entries": len(rows), "broken_at": None}