import os, sqlite3
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", str(Path(__file__).resolve().parent.parent / "data" / "soar.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets(host TEXT PRIMARY KEY, role TEXT, criticality INTEGER);
CREATE TABLE IF NOT EXISTS services(name TEXT PRIMARY KEY, host TEXT);
CREATE TABLE IF NOT EXISTS dependencies(service TEXT, depends_on_host TEXT);
CREATE TABLE IF NOT EXISTS traffic_stats(src_ip TEXT PRIMARY KEY, benign_share REAL, note TEXT);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL, flow_ts REAL, src_ip TEXT, dst_host TEXT, account TEXT,
  family TEXT, confidence REAL, p_malicious REAL, risk REAL, severity TEXT,
  policy_action TEXT, final_action TEXT, target TEXT, ttl_minutes INTEGER, downgraded INTEGER,
  impact REAL, blast_json TEXT, shap_json TEXT, explanation TEXT, explanation_status TEXT,
  requires_approval INTEGER, status TEXT,
  approval1_by TEXT, approval1_at REAL, approval2_by TEXT, approval2_at REAL, responded_at REAL);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, kind TEXT, target TEXT,
  executed_at REAL, expires_at REAL, state TEXT, closed_at REAL, reason TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, event TEXT, incident_id INTEGER, payload TEXT, prev_hash TEXT, hash TEXT);
"""

SEED = """
INSERT INTO assets VALUES('web-01','web server',4),('db-01','database',5),('auth-01','identity provider',5),
 ('mail-01','mail server',3),('file-01','file server',3),('hr-ws-02','workstation',2),('dev-ws-07','workstation',1),('printer-01','printer',1);
INSERT INTO services VALUES('storefront','web-01'),('orders-api','web-01'),('postgres','db-01'),('sso','auth-01'),('mail','mail-01'),('shares','file-01');
INSERT INTO dependencies VALUES('storefront','db-01'),('storefront','auth-01'),('orders-api','db-01'),('orders-api','auth-01'),('shares','auth-01'),('mail','auth-01');
INSERT INTO traffic_stats VALUES('203.0.113.10',0.92,'partner VPN gateway'),('198.51.100.7',0.85,'office NAT'),
 ('192.0.2.44',0.05,'unknown'),('192.0.2.45',0.03,'unknown'),('192.0.2.46',0.10,'unknown'),('45.33.32.156',0.02,'scanner');
"""

def conn():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c

def init():
    with conn() as c:
        c.executescript(SCHEMA)
        if not c.execute("SELECT 1 FROM assets").fetchone():
            c.executescript(SEED)

def q(sql, args=()):
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]

def one(sql, args=()):
    r = q(sql, args)
    return r[0] if r else None

def insert(table, row):
    with conn() as c:
        cur = c.execute(f"INSERT INTO {table}({','.join(row)}) VALUES({','.join('?' * len(row))})", list(row.values()))
        return cur.lastrowid

def update(table, id_, row):
    with conn() as c:
        c.execute(f"UPDATE {table} SET {','.join(k + '=?' for k in row)} WHERE id=?", [*row.values(), id_])