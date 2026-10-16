import json, os, time
from pathlib import Path
import requests, yaml
from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel
from . import actuators, audit, blast, db, explain
from ml.predict import Detector

POLICY_PATH = Path(os.getenv("POLICY_PATH", Path(__file__).resolve().parent.parent / "policy.yaml"))
N8N_URL = os.getenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/soar-incident")

app = FastAPI(title="Security Orchestration Agent")
detector = None

@app.on_event("startup")
def startup():
    global detector
    db.init()
    detector = Detector()

def policy():
    return yaml.safe_load(POLICY_PATH.read_text())  # re-read each call -> editable without code changes

class FlowIn(BaseModel):
    src_ip: str
    dst_host: str
    account: str = "unknown"
    flow_ts: float | None = None
    features: dict[str, float]

class Approval(BaseModel):
    approved_by: str | None = None

def severity(risk):
    return "critical" if risk >= 75 else "high" if risk >= 55 else "medium" if risk >= 35 else "low"

def notify_n8n(payload):
    try:
        requests.post(N8N_URL, json=payload, timeout=5)
    except Exception as e:
        audit.log("n8n_unreachable", payload["incident_id"], {"error": str(e)})

def get_incident(iid):
    inc = db.one("SELECT * FROM incidents WHERE id=?", (iid,))
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc

# ---------- detection -> decision ----------
@app.post("/analyze")
def analyze(f: FlowIn, bg: BackgroundTasks):
    pol, now = policy(), time.time()
    res = detector.analyze(f.features, pol["malicious_threshold"])
    if not res["malicious"]:
        return {"malicious": False, "p_malicious": res["p_malicious"]}
    fam, conf = res["family"], res["confidence"]
    rule, destructive = pol["families"][fam], pol["destructive_actions"]
    risk = round(100 * rule["weight"] * (0.6 * res["p_malicious"] + 0.4 * conf), 1)

    action = policy_action = rule["action"]
    b = blast.assess(action, f.src_ip, f.dst_host, action in destructive)
    downgraded = False
    if action in destructive and conf < pol["downgrade"]["min_confidence"] and b["impact"] >= pol["downgrade"]["impact_threshold"]:
        action, downgraded = rule["downgrade_to"], True
        b = blast.assess(action, f.src_ip, f.dst_host, action in destructive)
    needs_approval = action in destructive
    text, status = explain.explain(fam, conf, res["top_features"])

    iid = db.insert("incidents", {
        "created_at": now, "flow_ts": f.flow_ts or now, "src_ip": f.src_ip, "dst_host": f.dst_host, "account": f.account,
        "family": fam, "confidence": conf, "p_malicious": res["p_malicious"], "risk": risk, "severity": severity(risk),
        "policy_action": policy_action, "final_action": action, "target": actuators.target_for(action, f.src_ip, f.dst_host, f.account),
        "ttl_minutes": rule["ttl_minutes"], "downgraded": int(downgraded), "impact": b["impact"],
        "blast_json": json.dumps(b), "shap_json": json.dumps(res["top_features"]), "explanation": text,
        "explanation_status": status, "requires_approval": int(needs_approval),
        "status": "pending_approval" if needs_approval else "open"})
    audit.log("detection", iid, {"family": fam, "confidence": conf, "p_malicious": res["p_malicious"], "risk": risk})
    audit.log("decision", iid, {"policy_action": policy_action, "final_action": action, "downgraded": downgraded, "blast": b["summary"]})
    audit.log("explanation", iid, {"status": status})
    inc = get_incident(iid)
    bg.add_task(notify_n8n, {
        "incident_id": iid, "family": fam, "confidence": round(conf, 3), "severity": inc["severity"], "final_action": action,
        "target": inc["target"], "ttl_minutes": inc["ttl_minutes"], "requires_approval": bool(needs_approval),
        "downgraded": downgraded, "blast_summary": b["summary"], "explanation": text})
    return {"malicious": True, "incident": inc}

# ---------- playbook steps (called by n8n) ----------
@app.post("/incidents/{iid}/execute")
def execute(iid: int, a: Approval | None = None):
    inc = get_incident(iid)
    if inc["status"] not in ("pending_approval", "open"):
        raise HTTPException(409, f"cannot execute from status {inc['status']}")
    now = time.time()
    if inc["requires_approval"]:
        if not (a and a.approved_by):
            raise HTTPException(403, "destructive action requires approval (gate 1)")
        db.update("incidents", iid, {"approval1_by": a.approved_by, "approval1_at": now})
        audit.log("approval_gate1", iid, {"approved_by": a.approved_by})
    detail = actuators.apply(inc["final_action"], inc["target"])
    db.insert("actions", {"incident_id": iid, "kind": inc["final_action"], "target": inc["target"], "executed_at": now,
                          "expires_at": now + inc["ttl_minutes"] * 60, "state": "active", "detail": detail})
    db.update("incidents", iid, {"status": "active", "responded_at": now})
    audit.log("action_executed", iid, {"detail": detail, "ttl_minutes": inc["ttl_minutes"]})
    return get_incident(iid)

@app.post("/incidents/{iid}/reject")
def reject(iid: int, a: Approval | None = None):
    inc = get_incident(iid)
    if inc["status"] != "pending_approval":
        raise HTTPException(409, "not pending approval")
    db.update("incidents", iid, {"status": "rejected", "approval1_at": time.time(), "approval1_by": (a.approved_by if a else None)})
    audit.log("approval_gate1_rejected", iid, {})
    return get_incident(iid)

@app.post("/incidents/{iid}/confirm")
def confirm(iid: int, a: Approval | None = None):
    inc = get_incident(iid)
    act = db.one("SELECT * FROM actions WHERE incident_id=? AND state='active'", (iid,))
    if not act:
        raise HTTPException(409, "no active action to confirm")
    now = time.time()
    db.update("actions", act["id"], {"state": "confirmed", "closed_at": now, "reason": "analyst_confirmed"})
    db.update("incidents", iid, {"status": "confirmed", "approval2_at": now, "approval2_by": (a.approved_by if a else None)})
    audit.log("approval_gate2_confirmed", iid, {"by": a.approved_by if a else None})
    return get_incident(iid)

def _rollback(act, reason):
    detail = actuators.undo(act["kind"], act["target"])
    db.update("actions", act["id"], {"state": "rolled_back", "closed_at": time.time(), "reason": reason})
    db.update("incidents", act["incident_id"], {"status": "rolled_back"})
    audit.log("rollback", act["incident_id"], {"reason": reason, "detail": detail})

@app.post("/incidents/{iid}/rollback")
def rollback(iid: int, reason: str = "analyst_rollback"):
    get_incident(iid)
    act = db.one("SELECT * FROM actions WHERE incident_id=? AND state='active'", (iid,))
    if not act:
        raise HTTPException(409, "no active action to roll back")
    _rollback(act, reason)
    return get_incident(iid)

@app.post("/sweep")
def sweep():
    """Called every minute by n8n's Schedule Trigger: roll back unconfirmed actions whose TTL expired."""
    expired = db.q("SELECT * FROM actions WHERE state='active' AND expires_at<=?", (time.time(),))
    for act in expired:
        _rollback(act, "ttl_expired")
    return {"rolled_back": [a["incident_id"] for a in expired]}

# ---------- read APIs ----------
@app.get("/incidents")
def incidents(status: str | None = None):
    if status:
        return db.q("SELECT * FROM incidents WHERE status=? ORDER BY id DESC", (status,))
    return db.q("SELECT * FROM incidents ORDER BY id DESC LIMIT 200")

@app.get("/incidents/{iid}")
def incident(iid: int):
    return get_incident(iid)

@app.get("/actuators/state")
def actuator_state():
    return db.q("SELECT * FROM actions WHERE state='active' ORDER BY id DESC")

@app.get("/audit")
def audit_trail(limit: int = 100):
    return db.q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

@app.get("/audit/verify")
def audit_verify():
    return audit.verify()

@app.get("/metrics")
def metrics():
    def avg(sql):
        v = db.one(sql)["v"]
        return round(v, 2) if v is not None else None
    total = db.one("SELECT COUNT(*) n FROM incidents")["n"]
    passed = db.one("SELECT COUNT(*) n FROM incidents WHERE explanation_status IN ('pass','regenerated')")["n"]
    return {
        "incidents": total,
        "mttd_sec": avg("SELECT AVG(created_at - flow_ts) v FROM incidents"),
        "mttr_sec": avg("SELECT AVG(responded_at - created_at) v FROM incidents WHERE responded_at IS NOT NULL"),
        "approval_latency_sec": avg("SELECT AVG(approval1_at - created_at) v FROM incidents WHERE approval1_at IS NOT NULL"),
        "auto_resolved": db.one("SELECT COUNT(*) n FROM incidents WHERE requires_approval=0")["n"],
        "human_handled": db.one("SELECT COUNT(*) n FROM incidents WHERE requires_approval=1")["n"],
        "rollbacks": db.one("SELECT COUNT(*) n FROM actions WHERE state='rolled_back'")["n"],
        "downgrades": db.one("SELECT COUNT(*) n FROM incidents WHERE downgraded=1")["n"],
        "explanation_pass_rate": round(passed / total, 3) if total else None,
    }