# 🛡️ AEGIS — Endpoint Deployment & Multi-Machine Setup Guide

This guide details how to deploy and operate **AEGIS (Active Endpoint Guardian & Interception System)** on a dedicated host or inside an isolated virtual machine (e.g., Windows 10/11 or Ubuntu/Debian), connecting back to the **SPECTER** Threat Intelligence & SOAR backend.

---

## 🏗️ Architecture Overview

```
┌───────────────────────────────────────┐            ┌────────────────────────────────────────┐
│     SPECTER SERVER (Host / Cloud)     │            │    AEGIS ENDPOINT (VM / Target Host)   │
│                                       │            │                                        │
│  • FastAPI Backend (:8000)            │   REST     │  • aegis.py (Behavioral Interceptor)   │
│  • Neo4j Knowledge Graph (:7687)      │ ◄────────  │    - Shannon Entropy Scanner (~8.0)    │
│  • Celery + Redis Decay Engine        │  Telemetry │    - Write Velocity Sliding Window     │
│  • React + Vite Frontend (:3000)      │   Stream   │    - VSS Deletion Interceptor          │
│  • Cowrie SSH Honeypot (:2222)        │            │    - Extension Churn Detector          │
│                                       │            │  • Process Tree & Memory Dumper        │
│                                       │            │  • Local Score API (:8001)             │
└───────────────────────────────────────┘            └────────────────────────────────────────┘
```

---

## 📋 Prerequisites

### On the SPECTER Server Machine:
- Docker & Docker Compose installed and running.
- Network accessibility (LAN IP or domain reachable by the AEGIS endpoint).
- Port `8000` open to accept telemetry from the AEGIS agent.

### On the AEGIS Endpoint Machine (VM or Dedicated Device):
- Python 3.10+ (Python 3.11 recommended).
- Network access to the SPECTER server IP.
- Administrator or `root` privileges (recommended so malware cannot terminate AEGIS).

---

## 🚀 Setup Scenario 1: Isolated Windows VM (Malware Lab)

If you are running live ransomware samples (e.g., WannaCry, LockBit) for research or demonstration:

### 1. VM Provisioning & Isolation
1. Create a Windows 10/11 VM in VirtualBox, VMware, or Proxmox (Allocations: 4 vCPU, 4GB RAM, 60GB Disk).
2. **Network Isolation**: Set the VM network adapter to **Host-Only** or an isolated **Internal Network**.
   > ⚠️ **CRITICAL**: Never execute live ransomware on a bridged or NAT adapter connected to your local home/work network or public internet.
3. Test isolation inside the VM:
   ```cmd
   ping 8.8.8.8
   # Must return "Destination host unreachable" or timeout
   ```
4. **Take Snapshot Immediately**: Create a baseline snapshot named `CLEAN_BASELINE`. You will revert to this snapshot after every malware execution.

### 2. Configure Host-to-VM Connectivity
1. Note the Host-Only adapter IP of your SPECTER host machine (e.g., `192.168.56.1` on VirtualBox).
2. Inside the VM, verify you can reach the SPECTER API:
   ```cmd
   curl http://192.168.56.1:8000/health
   # Expected response: {"status":"ok","version":"7.0.0"}
   ```

### 3. Install AEGIS Dependencies in VM
Transfer the `aegis.py` file and the `backend/aegis/` folder into the VM (via VirtualBox Shared Folder or USB passthrough):
```powershell
pip install -r backend/aegis/requirements.txt
```

### 4. Launch AEGIS Interceptor
Start AEGIS pointing to your user directory and directing kill telemetry to the SPECTER host:
```powershell
python aegis.py --watch "C:\Users\victim\Documents" --threshold 65 --specter-url http://192.168.56.1:8000 --demo
```

---

## 🐧 Setup Scenario 2: Remote Linux Machine / Endpoint

AEGIS runs cross-platform on Linux endpoints to protect sensitive server shares and web directories.

### 1. Clone or Copy AEGIS to Endpoint
```bash
git clone https://github.com/<your-username>/specter-aegis.git
cd specter-aegis
```

### 2. Install Requirements in a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/aegis/requirements.txt
```

### 3. Run AEGIS with Root Permissions
Ransomware executing under a standard user cannot suspend or terminate a root process:
```bash
sudo ./venv/bin/python aegis.py \
    --watch /home/victim/data \
    --threshold 65 \
    --specter-url http://<SPECTER_SERVER_IP>:8000 \
    --demo
```

### 4. Optional: Process Persistence Watchdog
To ensure AEGIS restarts automatically if intentionally terminated:
```bash
cat << 'EOF' > watchdog.sh
#!/bin/bash
while true; do
    if ! pgrep -f "aegis.py" > /dev/null; then
        echo "[WATCHDOG] AEGIS terminated — restarting daemon"
        python3 aegis.py --watch /home/victim/data --threshold 65 --specter-url http://<SPECTER_SERVER_IP>:8000 &
    fi
    sleep 2
done
EOF
chmod +x watchdog.sh
./watchdog.sh &
```

---

## 🧪 Safe Testing & Verification (Synthetic Mode)

You do **not** need real malware to verify the full behavioral pipeline! AEGIS includes a built-in synthetic ransomware simulator:

```bash
# 1. Create a dummy victims folder
mkdir -p ~/victim_files

# 2. Run AEGIS in self-test mode
python aegis.py --watch ~/victim_files --threshold 65 --test --demo
```

### What Happens During the Test:
1. **Normal Activity Stage**: Writes normal text files; score remains below 10.
2. **Acceleration Stage**: Increases write velocity; score reaches warning range (20–40).
3. **Ransomware Emulation Stage**: Generates high-entropy encrypted payloads and renames files to `.wncry`.
4. **Interception**: Once the behavioral score crosses the threshold (65), the kill switch suspends the writing process, extracts memory/network evidence, dumps an artifact JSON report in `./evidence/`, and posts telemetry to the SPECTER server.

---

## 🖥️ SPECTER Dashboard Configuration

1. Open the SPECTER web dashboard at `http://localhost:3000`.
2. Navigate to the **AEGIS** tab.
3. In the top-right header, click the **Host** pill (`Host: localhost:8001`) and enter the IP address of your remote AEGIS agent (e.g., `http://192.168.56.10:8001`).
4. The status badge will turn green (**AEGIS ONLINE**), streaming live Shannon entropy scores, write velocity, and kill switch logs in real time.
