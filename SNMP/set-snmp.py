#!/usr/bin/env python3
import getpass, csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from netmiko import ConnectHandler

# --- Fixed inputs (edit here only if you ever need to) ---
DEVICES_FILE = "devices.txt"
WORKERS = 20  # concurrency (no CLI args)
CMD1 = "set firewall family inet filter controlplane-filter term snmp_allow_in from source-address 10.0.0.0/24"
CMD2 = "set firewall family inet filter controlplane-filter term snmp_allow_in from source-address 10.1.0.0/24"
VERIFY_BASE = "set firewall family inet filter controlplane-filter term snmp_allow_in from source-address"
TIMEOUTS = dict(timeout=120, auth_timeout=90, banner_timeout=90, conn_timeout=90)
SUMMARY_CSV = "summary.csv"
# ---------------------------------------------------------

def load_hosts(path: str) -> list[str]:
    p = Path(path)
    if not p.exists(): raise FileNotFoundError(f"{path} not found")
    return [ln.split(",")[0].strip() for ln in p.read_text().splitlines()
            if (ln:=ln.strip()) and not ln.startswith("#")]

def verify(conn) -> bool:
    out = conn.send_command(f'show configuration firewall family inet | display set | match "{VERIFY_BASE}" | no-more')
    have = {" ".join(l.split()) for l in out.splitlines()}
    need = {" ".join(CMD1.split()), " ".join(CMD2.split())}
    return need.issubset(have)

def apply_one(host: str, user: str, pw: str):
    conn = None
    try:
        conn = ConnectHandler(device_type="juniper", host=host, username=user, password=pw,
                              fast_cli=False, global_delay_factor=1, **TIMEOUTS)
        try: conn.send_command("set cli screen-length 0")
        except: pass
        conn.config_mode()
        conn.send_config_set([CMD1, CMD2], exit_config_mode=False)
        commit = conn.send_command_timing("commit")
        try: conn.exit_config_mode()
        except: pass
        ok = verify(conn)
        committed = "commit complete" in commit.lower()
        return (host, True, committed, ok, "")
    except Exception as e:
        return (host, False, False, False, str(e))
    finally:
        try:
            if conn: conn.disconnect()
        except: pass

def main():
    hosts = load_hosts(DEVICES_FILE)
    user = input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    print(f"Applying to {len(hosts)} devices …")

    rows = []
    with ThreadPoolExecutor(max_workers=max(1, WORKERS)) as ex:
        futs = [ex.submit(apply_one, h, user, pw) for h in hosts]
        for f in as_completed(futs):
            host, connected, committed, verified, err = f.result()
            status = "OK" if (connected and committed and verified) else "FAIL"
            extra = "" if status=="OK" else (f" error={err}" if not connected else f" committed={committed} verified={verified}")
            print(f"[{host}] {status}{(' ' + extra) if extra else ''}")
            rows.append((host, connected, committed, verified, err))

    with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host","connected","committed","verified","error"])
        w.writerows(rows)

    total = len(rows)
    ok = sum(1 for _,c,m,v,_ in rows if c and m and v)
    ver = sum(1 for *_,v,_ in rows if v)
    print(f"\nSummary: total={total} ok={ok} verified={ver} csv={SUMMARY_CSV}")

if __name__ == "__main__":
    main()
