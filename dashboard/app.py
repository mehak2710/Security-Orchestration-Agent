import json, os, time
import pandas as pd, requests, streamlit as st

API = os.getenv("API_URL", "http://localhost:8000")
st.set_page_config(page_title="SOC Dashboard", layout="wide")
st.title("🛡️ Security Orchestration Agent - SOC Dashboard")

def get(path):
    try:
        return requests.get(API + path, timeout=5).json()
    except Exception as e:
        st.error(f"API unreachable: {e}"); st.stop()

def post(path, body=None):
    r = requests.post(API + path, json=body or {}, timeout=10)
    st.toast(f"{path} -> {r.status_code}")

auto = st.sidebar.checkbox("Auto-refresh (5s)", value=False)
m = get("/metrics")
st.subheader("SOC performance")
c = st.columns(6)
fmt = lambda v, u="s": "-" if v is None else f"{v:.1f}{u}"
c[0].metric("Mean time to detect", fmt(m["mttd_sec"]))
c[1].metric("Mean time to respond", fmt(m["mttr_sec"]))
c[2].metric("Approval latency", fmt(m["approval_latency_sec"]))
c[3].metric("Auto vs human", f"{m['auto_resolved']} / {m['human_handled']}")
c[4].metric("Rollbacks", m["rollbacks"])
c[5].metric("Explanation pass rate", "-" if m["explanation_pass_rate"] is None else f"{m['explanation_pass_rate']:.0%}")

audit = get("/audit/verify")
st.sidebar.markdown("### Audit trail")
(st.sidebar.success if audit["valid"] else st.sidebar.error)(
    f"Chain intact ({audit['entries']} entries)" if audit["valid"] else f"TAMPERED at entry {audit['broken_at']}")

inc = pd.DataFrame(get("/incidents"))
tab1, tab2, tab3, tab4 = st.tabs(["Incidents", "Pending approvals", "Active responses", "Audit log"])

with tab1:
    if inc.empty:
        st.info("No incidents yet. Run: python -m scripts.simulate -n 10")
    else:
        st.dataframe(inc[["id", "family", "confidence", "severity", "risk", "policy_action", "final_action", "downgraded",
                          "target", "impact", "status", "explanation_status"]], use_container_width=True, hide_index=True)
        pick = st.selectbox("Inspect incident", inc["id"])
        row = inc[inc.id == pick].iloc[0]
        st.write("**Explanation:**", row["explanation"])
        st.write("**Blast radius:**", json.loads(row["blast_json"])["summary"])
        shap = pd.DataFrame(json.loads(row["shap_json"])).set_index("feature")["shap"]
        st.bar_chart(shap)

with tab2:
    pend = inc[inc.status == "pending_approval"] if not inc.empty else inc
    if pend.empty:
        st.success("Nothing waiting for approval.")
    for _, r in pend.iterrows():
        with st.container(border=True):
            st.markdown(f"**#{r.id} {r.family}** ({r.confidence:.0%}) → `{r.final_action}` on `{r.target}` | {r.severity}")
            st.caption(json.loads(r.blast_json)["summary"])
            a, b = st.columns(2)
            if a.button("Approve (manual gate 1)", key=f"a{r.id}"): post(f"/incidents/{r.id}/execute", {"approved_by": "dashboard"})
            if b.button("Reject", key=f"r{r.id}"): post(f"/incidents/{r.id}/reject", {"approved_by": "dashboard"})
    st.caption("Normally approvals arrive via Telegram/Slack through n8n; these buttons are a manual fallback.")

with tab3:
    act = pd.DataFrame(get("/actuators/state"))
    if act.empty:
        st.info("No active simulated actions.")
    else:
        act["seconds_to_rollback"] = (act["expires_at"] - time.time()).round()
        st.dataframe(act[["incident_id", "kind", "target", "seconds_to_rollback", "detail"]], use_container_width=True, hide_index=True)
        for _, r in act.iterrows():
            a, b = st.columns(2)
            if a.button(f"Confirm #{r.incident_id} (gate 2)", key=f"c{r.id}"): post(f"/incidents/{r.incident_id}/confirm", {"approved_by": "dashboard"})
            if b.button(f"Roll back #{r.incident_id}", key=f"b{r.id}"): post(f"/incidents/{r.incident_id}/rollback")

with tab4:
    log = pd.DataFrame(get("/audit?limit=100"))
    if log.empty:
        st.info("No audit entries yet.")
    else:
        st.dataframe(log[["id", "event", "incident_id", "payload", "hash"]], use_container_width=True, hide_index=True)

if auto:
    time.sleep(5); st.rerun()