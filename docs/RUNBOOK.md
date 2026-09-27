# 🕹️ SPECTER x AEGIS — SOC & Demo Runbook

This runbook outlines end-to-end operational procedures, demonstration flows, database resets, and simulated attack playbooks.

---

## 🚀 1. Complete Environment Startup

### Terminal 1: Core Platform (SPECTER Backend & Containers)
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Start Cowrie honeypot & the automatic log watcher sidecar
docker-compose up -d cowrie cowrie_watcher
```

### Terminal 2: Web Interface (React + Vite)
```bash
cd frontend
npm install
npm run dev
# Dashboard accessible at http://localhost:3000
```

### Terminal 3: Attacker Simulation (Honeypot Trigger)
```bash
# Simulates an SSH brute-force attack against Cowrie on port 2222
python scripts/simulate_attack.py --quick
```

### Terminal 4: Database Clean Slate (Pre-Demo Reset)
```bash
# Resets Neo4j knowledge graph and flushes Redis cache
bash ./scripts/reset_db.sh
```

### Terminal 5: Remote Access / Discord Bot Tunnel (Optional)
```bash
ngrok http 8000
# Update Discord Interactions URL with your ngrok HTTPS forwarding address
```

---

## 🎯 2. AEGIS Ransomware Interceptor Runbook

### Synthetic Safe Demonstration (No Live Malware Needed)
```bash
# 1. Prepare synthetic victim directory
mkdir -p ~/victims
rm -f ~/victims/* 2>/dev/null

# Generate 200 mock victim documents
for i in $(seq 1 200); do
    echo "Confidential business document $i - critical financial report." > ~/victims/document_${i}.docx
    echo "Quarterly audit data row $i" > ~/victims/spreadsheet_${i}.xlsx
done

# 2. Launch AEGIS with live CLI telemetry
python aegis.py --demo --test --watch ~/victims --threshold 65
```

---

## 🔬 3. Live Malware Analysis Protocol (Isolated Lab Only)

> ⚠️ **CAUTION**: ONLY execute within a dedicated, host-only or isolated virtual machine. Never connect to public internet or execute on production hosts.

1. **Snapshot Confirmation**: Verify the VM state is restored to `CLEAN_BASELINE`.
2. **Network Verification**: Verify `ping 8.8.8.8` returns unreachable.
3. **Generate Victim Corpus**:
   ```bash
   mkdir -p ~/victims
   for i in $(seq 1 400); do
       printf "Confidential contract record %d\n" $i > ~/victims/contract_${i}.docx
   done
   ```
4. **Start AEGIS as Administrator/Root**:
   ```bash
   sudo python3 aegis.py --demo --watch ~/victims --threshold 65 --specter-url http://<SPECTER_HOST_IP>:8000
   ```
5. **Execute Sample**: Run the ransomware binary (e.g., WannaCry / LockBit).
6. **Telemetry & Verification**:
   - Shannon entropy rises from 4.5 to 7.9+ bits/byte.
   - Process tree suspended in < 850ms.
   - Forensic bundle output to `./evidence/evidence_<timestamp>.json`.
   - Threat intelligence automatically ingested into SPECTER's Diamond Model graph.
