def target_for(kind, src_ip, dst_host, account):
    return {"block_ip": src_ip, "rate_limit": src_ip, "quarantine_host": dst_host, "disable_account": account}[kind]

_APPLY = {
    "block_ip": lambda t: f"[SIM] firewall: DROP all traffic from {t}",
    "rate_limit": lambda t: f"[SIM] gateway: rate-limit {t} to 10 req/s",
    "quarantine_host": lambda t: f"[SIM] NAC: moved host {t} to quarantine VLAN",
    "disable_account": lambda t: f"[SIM] IdP: disabled account {t}",
}
_UNDO = {
    "block_ip": lambda t: f"[SIM] firewall: removed DROP rule for {t}",
    "rate_limit": lambda t: f"[SIM] gateway: removed rate-limit for {t}",
    "quarantine_host": lambda t: f"[SIM] NAC: restored host {t} to production VLAN",
    "disable_account": lambda t: f"[SIM] IdP: re-enabled account {t}",
}
def apply(kind, target): return _APPLY[kind](target)
def undo(kind, target): return _UNDO[kind](target)