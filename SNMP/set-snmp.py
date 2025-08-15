#!/usr/bin/env python3
import getpass, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from netmiko import ConnectHandler

# --- Fixed settings (edit if needed) ---
DEVICES_FILE = "devices.txt"
WORKERS = 20
CMD1 = "set firewall family inet filter controlplane-filter term snmp_allow_in from source-address 10.0.0.0/24"
CMD2 = "set firewall family inet filter controlplane-filter term snmp_allow_in from source-address 10.1.0.0/24"
TIMEOUTS = dict(timeout=120, auth_timeout=90, banner_timeout=90, conn_timeout=90)
# ---------------------------------------

print_lock = threading.Lock()
def log(host, msg):
    with print_lock:
        print(f"[{host}] {msg}", flush=True)

def load_hosts(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found")
    hosts: list[str] = []
    for line in p.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        hosts.append(s.split(",")[0].strip())
    return hosts

def apply_host(host: str, user: str, pw: str):
    conn = None
    try:
        log(host, "connecting…")
        conn = ConnectHandler(device_type="juniper", host=host, username=user, password=pw,
                              fast_cli=False, global_delay_factor=1, **TIMEOUTS)
        log(host, "connected")
        try:
            conn.send_command("set cli screen-length 0")
        except Exception:
            pass

        log(host, "entering config mode")
        conn.config_mode()

        log(host, "pushing config")
        conn.send_config_set([CMD1, CMD2], exit_config_mode=False)

        log(host, "committing")
        commit = conn.send_command_timing("commit")
        ok = "commit complete" in commit.lower()

        try:
            conn.exit_config_mode()
        except Exception:
            pass

        log(host, "disconnecting")
        conn.disconnect()

        log(host, "DONE ✓" if ok else "DONE ✗ (commit not confirmed)")
        return (host, ok, "" if ok else "commit not confirmed")
    except Exception as e:
        log(host, f"ERROR: {e}")
        return (host, False, str(e))
    finally:
        try:
            if conn:
                conn.disconnect()
        except Exception:
            pass

def main():
    hosts = load_hosts(DEVICES_FILE)
    with print_lock:
        print(f"Applying to {len(hosts)} devices with {WORKERS} workers…", flush=True)
    user = input("Username: ").strip()
    pw = getpass.getpass("Password: ")

    results = []
    with ThreadPoolExecutor(max_workers=max(1, WORKERS)) as ex:
        futs = [ex.submit(apply_host, h, user, pw) for h in hosts]
        for f in as_completed(futs):
            results.append(f.result())

    total = len(results)
    ok = sum(1 for _, s, _ in results if s)
    fails = [h for h, s, _ in results if not s]
    with print_lock:
        print(f"\nSummary: total={total} success={ok} failed={total-ok}", flush=True)
        if fails:
            print("Failed hosts:")
            for h in sorted(fails):
                print(f"  - {h}")

if __name__ == "__main__":
    main()
