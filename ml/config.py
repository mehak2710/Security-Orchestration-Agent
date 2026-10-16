import re

def snake(s):
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")

RAW_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "Flow IAT Mean", "SYN Flag Count", "ACK Flag Count", "PSH Flag Count",
    "Average Packet Size", "Packet Length Std", "Init_Win_bytes_forward", "Down/Up Ratio",
]
FEATURES = [snake(f) for f in RAW_FEATURES]
FAMILIES = ["DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration"]

def to_family(label):
    l = str(label).lower()
    if "benign" in l: return "Benign"
    if "ddos" in l: return "DDoS"
    if "dos" in l: return "DoS"
    if "portscan" in l: return "PortScan"
    if "web attack" in l or "sql" in l or "xss" in l: return "WebAttack"
    if "patator" in l: return "BruteForce"
    if l.strip() == "bot": return "Botnet"
    if "infiltration" in l or "heartbleed" in l: return "Infiltration"
    return None