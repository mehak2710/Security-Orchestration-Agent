from . import db

def assess(action, src_ip, dst_host, destructive):
    """Impact 0-100 = 40% benign-traffic share + 35% dependent services + 25% asset criticality."""
    ts = db.one("SELECT benign_share FROM traffic_stats WHERE src_ip=?", (src_ip,))
    share = ts["benign_share"] if ts else 0.05
    asset = db.one("SELECT criticality, role FROM assets WHERE host=?", (dst_host,)) or {"criticality": 1, "role": "unknown"}
    deps = db.one("""SELECT COUNT(DISTINCT s.name) n FROM services s
                     LEFT JOIN dependencies d ON d.service = s.name
                     WHERE s.host = ? OR d.depends_on_host = ?""", (dst_host, dst_host))["n"]
    impact = 40 * share + 35 * min(deps / 5, 1) + 25 * asset["criticality"] / 5
    if not destructive:
        impact *= 0.3  # rate limiting degrades rather than cuts off
    impact = round(impact, 1)
    summary = (f"{action} -> impact {impact}/100: {share:.0%} of {src_ip}'s traffic is benign, "
               f"{deps} service(s) depend on {dst_host}, asset criticality {asset['criticality']}/5 ({asset['role']}).")
    return {"impact": impact, "benign_share": share, "dependent_services": deps,
            "criticality": asset["criticality"], "summary": summary}