import argparse, os, random, time
from pathlib import Path
import pandas as pd, requests
from ml.config import FEATURES

API = os.getenv("API_URL", "http://localhost:8000")
SRC = ["203.0.113.10", "198.51.100.7", "192.0.2.44", "192.0.2.45", "192.0.2.46", "45.33.32.156"]
HOSTS = ["web-01", "db-01", "auth-01", "mail-01", "file-01", "hr-ws-02", "dev-ws-07", "printer-01"]
ACCTS = ["svc-backup", "j.doe", "a.khan", "admin", "m.lee"]

ap = argparse.ArgumentParser()
ap.add_argument("-n", type=int, default=10)
ap.add_argument("--family")
ap.add_argument("--benign-ratio", type=float, default=0.2)
ap.add_argument("--ambiguous", action="store_true", help="blend with another class -> lower confidence")
ap.add_argument("--src"); ap.add_argument("--host")
a = ap.parse_args()

df = pd.read_csv(Path(__file__).resolve().parent.parent / "data" / "sample_flows.csv")
for _ in range(a.n):
    pool = df[df.family == a.family] if a.family else (df[df.family == "Benign"] if random.random() < a.benign_ratio else df[df.family != "Benign"])
    row = pool.sample(1).iloc[0]
    feats = {f: float(row[f]) for f in FEATURES}
    if a.ambiguous:  # geometric blend with a flow of another class
        other = df[(df.family != row.family) & (df.family != "Benign")].sample(1).iloc[0]
        w = random.uniform(0.3, 0.5)
        feats = {f: (max(feats[f], 1e-6) ** (1 - w)) * (max(float(other[f]), 1e-6) ** w) for f in FEATURES}
    body = {"src_ip": a.src or random.choice(SRC), "dst_host": a.host or random.choice(HOSTS), "account": random.choice(ACCTS),
            "flow_ts": time.time() - random.uniform(2, 40), "features": feats}
    r = requests.post(f"{API}/analyze", json=body).json()
    if not r["malicious"]:
        print(f"[{row.family:>12}] -> benign (p_mal={r['p_malicious']:.2f})")
    else:
        i = r["incident"]
        print(f"[{row.family:>12}] -> #{i['id']} {i['family']} {i['confidence']:.0%} | {i['policy_action']}"
              f"{' -> ' + i['final_action'] + ' (DOWNGRADED)' if i['downgraded'] else ''} on {i['target']} | impact {i['impact']} | {i['status']}")