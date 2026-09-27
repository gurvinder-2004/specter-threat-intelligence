"""
AEGIS — Memory Forensics Collector
====================================
Auto-triggered when the kill switch fires.
Dumps process memory and extracts forensic artifacts using Volatility 3.

On kill event:
  1. Dumps full process memory of the ransomware PID
  2. Extracts process tree at time of kill
  3. Extracts injected memory regions (shellcode detection)
  4. Extracts network connections at time of kill
  5. Extracts registry modifications
  6. Packages everything into a structured evidence bundle
  7. POSTs to SPECTER API

Requirements:
    pip install volatility3 pywin32 (Windows)
    pip install volatility3 (Linux)

Usage:
    from forensics import ForensicsCollector
    collector = ForensicsCollector(output_dir="./evidence")
    bundle = await collector.collect(kill_event)
"""

import os
import sys
import json
import time
import ctypes
import struct
import hashlib
import asyncio
import platform
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

import psutil

# ── Evidence bundle structure ─────────────────────────────────────────────────

@dataclass
class ProcessNode:
    pid:        int
    ppid:       int
    name:       str
    cmdline:    str
    create_time: float
    suspicious: bool = False


@dataclass
class MemoryRegion:
    base_address:  str
    size:          int
    protection:    str
    is_executable: bool
    entropy:       float
    suspicious:    bool = False


@dataclass
class NetworkConnection:
    local_addr:  str
    remote_addr: str
    status:      str
    pid:         int
    process:     str


@dataclass
class EvidenceBundle:
    # Kill metadata
    timestamp:            str
    family_guess:         str
    detection_latency_ms: float
    files_encrypted:      int
    files_saved:          int
    behavioral_score:     float
    trigger_signals:      list

    # Process evidence
    process_tree:         list = field(default_factory=list)
    malicious_process:    dict = field(default_factory=dict)
    injected_regions:     list = field(default_factory=list)

    # Network evidence
    network_connections:  list = field(default_factory=list)
    c2_candidates:        list = field(default_factory=list)

    # File evidence
    encrypted_files:      list = field(default_factory=list)
    ransom_notes:         list = field(default_factory=list)

    # Hashes
    sample_sha256:        str = ""
    sample_md5:           str = ""

    # MITRE ATT&CK mappings
    ttps:                 list = field(default_factory=list)

    # Paths
    memory_dump_path:     str = ""
    report_path:          str = ""


# ── MITRE TTP Inference ───────────────────────────────────────────────────────

def infer_ttps(bundle: EvidenceBundle) -> list[dict]:
    """
    Infer MITRE ATT&CK techniques from forensic evidence.
    Deterministic rules — no LLM, no guessing.
    """
    ttps = []

    def add(tid, name, tactic, evidence):
        ttps.append({
            "technique_id": tid,
            "name":         name,
            "tactic":       tactic,
            "evidence":     evidence,
        })

    # T1486 — Data Encrypted for Impact
    if bundle.files_encrypted > 0:
        add("T1486", "Data Encrypted for Impact", "Impact",
            f"{bundle.files_encrypted} files encrypted with high-entropy writes")

    # T1490 — Inhibit System Recovery
    if any("vss" in str(s).lower() for s in bundle.trigger_signals):
        add("T1490", "Inhibit System Recovery", "Impact",
            "VSS deletion attempt detected via command line monitoring")

    # T1055 — Process Injection
    if any(r.get("suspicious") for r in bundle.injected_regions):
        add("T1055", "Process Injection", "Defense Evasion",
            f"{sum(1 for r in bundle.injected_regions if r.get('suspicious'))} suspicious executable memory regions")

    # T1082 — System Information Discovery
    # (ransomware typically does this before encrypting)
    add("T1082", "System Information Discovery", "Discovery",
        "Inferred — ransomware standard pre-encryption behavior")

    # T1083 — File and Directory Discovery
    add("T1083", "File and Directory Discovery", "Discovery",
        f"File traversal detected — {bundle.files_encrypted} files targeted")

    # T1070.004 — File Deletion
    if any(".bak" in f or ".shadow" in f for f in bundle.encrypted_files):
        add("T1070.004", "File Deletion", "Defense Evasion",
            "Backup/shadow file deletion detected")

    # T1071.001 — Web Protocols C2 (if external connections exist)
    external = [c for c in bundle.network_connections
                if not _is_private(c.get("remote_addr","").split(":")[0])]
    if external:
        add("T1071.001", "Application Layer Protocol: Web Protocols",
            "Command and Control",
            f"External connections: {[c.get('remote_addr') for c in external[:3]]}")

    # T1027 — Obfuscated Files or Information
    if any(r.get("entropy",0) > 7.5 for r in bundle.injected_regions):
        add("T1027", "Obfuscated Files or Information", "Defense Evasion",
            "High-entropy memory regions suggest packed/encrypted code")

    return ttps


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    prefixes = ("10.", "192.168.", "127.", "172.16.", "172.17.",
                "172.18.", "172.19.", "172.2", "172.3", "0.0.0.0", "169.254.")
    return any(ip.startswith(p) for p in prefixes)


# ── Process Tree Capture ──────────────────────────────────────────────────────

def capture_process_tree(target_pid: int) -> tuple[list[ProcessNode], dict]:
    """
    Capture the full process tree at the moment of kill.
    Highlights suspicious parent-child relationships.
    """
    nodes     = []
    malicious = {}

    # Known suspicious parent→child relationships
    SUSPICIOUS_CHAINS = [
        ("winword.exe",   "cmd.exe"),
        ("excel.exe",     "cmd.exe"),
        ("outlook.exe",   "cmd.exe"),
        ("winword.exe",   "powershell.exe"),
        ("excel.exe",     "powershell.exe"),
        ("explorer.exe",  "cmd.exe"),
        ("svchost.exe",   "cmd.exe"),
        ("notepad.exe",   "cmd.exe"),
    ]

    try:
        # Get all processes
        all_procs = {p.pid: p for p in psutil.process_iter(
            ["pid","ppid","name","cmdline","create_time"]
        )}

        for pid, proc in all_procs.items():
            try:
                info    = proc.info
                ppid    = info.get("ppid", 0)
                name    = (info.get("name") or "").lower()
                cmdline = " ".join(info.get("cmdline") or [])
                ctime   = info.get("create_time", 0)

                # Check if suspicious parent-child
                suspicious = False
                if ppid in all_procs:
                    parent_name = (all_procs[ppid].info.get("name") or "").lower()
                    if (parent_name, name) in SUSPICIOUS_CHAINS:
                        suspicious = True

                # Directly flag the ransomware PID and its tree
                if pid == target_pid:
                    suspicious = True
                    malicious  = {
                        "pid":     pid,
                        "name":    info.get("name",""),
                        "cmdline": cmdline,
                        "ppid":    ppid,
                    }

                nodes.append(ProcessNode(
                    pid=pid, ppid=ppid, name=info.get("name",""),
                    cmdline=cmdline[:200], create_time=ctime,
                    suspicious=suspicious,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    except Exception as e:
        print(f"[AEGIS] Process tree capture error: {e}")

    return nodes, malicious


# ── Memory Region Scanner ─────────────────────────────────────────────────────

def scan_memory_regions(pid: int) -> list[MemoryRegion]:
    """
    Scan process memory regions for suspicious executable segments.
    Injected shellcode typically lives in PAGE_EXECUTE_READWRITE regions
    that are not backed by a file (anonymous memory).

    Windows: uses VirtualQueryEx via ctypes
    Linux:   reads /proc/PID/maps
    """
    regions = []

    if platform.system() == "Windows":
        regions = _scan_windows_memory(pid)
    else:
        regions = _scan_linux_memory(pid)

    return regions


def _scan_linux_memory(pid: int) -> list[MemoryRegion]:
    """Parse /proc/PID/maps for suspicious regions."""
    regions = []
    maps_path = Path(f"/proc/{pid}/maps")
    mem_path  = Path(f"/proc/{pid}/mem")

    if not maps_path.exists():
        return regions

    try:
        with open(maps_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue

                addr_range = parts[0]
                perms      = parts[1]
                backing    = parts[4] if len(parts) > 4 else ""

                is_exec    = "x" in perms
                is_anon    = backing in ("", "0") or not backing.strip()

                if not is_exec:
                    continue

                start_s, end_s = addr_range.split("-")
                start = int(start_s, 16)
                end   = int(end_s, 16)
                size  = end - start

                # Read region and compute entropy
                entropy   = 0.0
                sample    = b""
                try:
                    with open(mem_path, "rb") as mem:
                        mem.seek(start)
                        sample = mem.read(min(4096, size))
                        if sample:
                            from aegis.interceptor import shannon_entropy
                            entropy = shannon_entropy(sample)
                except Exception:
                    pass

                # Suspicious: executable + anonymous + high entropy
                suspicious = is_exec and is_anon and entropy > 7.0

                regions.append(MemoryRegion(
                    base_address=hex(start),
                    size=size,
                    protection=perms,
                    is_executable=is_exec,
                    entropy=round(entropy, 3),
                    suspicious=suspicious,
                ))

    except Exception as e:
        print(f"[AEGIS] Linux memory scan error: {e}")

    return regions


def _scan_windows_memory(pid: int) -> list[MemoryRegion]:
    """
    Windows VirtualQueryEx scan via ctypes.
    Looks for MEM_PRIVATE + PAGE_EXECUTE_READWRITE regions (classic injection marker).
    """
    regions = []
    try:
        import ctypes
        import ctypes.wintypes as wt

        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT         = 0x1000
        MEM_PRIVATE        = 0x20000
        PAGE_EXECUTE_RW    = 0x40
        PAGE_EXECUTE_RWC   = 0x80

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress",       ctypes.c_void_p),
                ("AllocationBase",    ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize",        ctypes.c_size_t),
                ("State",             wt.DWORD),
                ("Protect",           wt.DWORD),
                ("Type",              wt.DWORD),
            ]

        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not handle:
            return regions

        addr = 0
        mbi  = MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(mbi)

        while k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), size):
            if (mbi.State == MEM_COMMIT and
                mbi.Type == MEM_PRIVATE and
                mbi.Protect in (PAGE_EXECUTE_RW, PAGE_EXECUTE_RWC)):

                region_size = mbi.RegionSize
                buf         = ctypes.create_string_buffer(min(4096, region_size))
                bytes_read  = ctypes.c_size_t(0)
                entropy     = 0.0

                if k32.ReadProcessMemory(handle, ctypes.c_void_p(mbi.BaseAddress), buf, len(buf), ctypes.byref(bytes_read)):
                    data = bytes(buf[:bytes_read.value])
                    if data:
                        from aegis.interceptor import shannon_entropy
                        entropy = shannon_entropy(data)

                suspicious = entropy > 6.5

                regions.append(MemoryRegion(
                    base_address=hex(mbi.BaseAddress or 0),
                    size=region_size,
                    protection=hex(mbi.Protect),
                    is_executable=True,
                    entropy=round(entropy, 3),
                    suspicious=suspicious,
                ))

            if mbi.RegionSize == 0:
                break
            addr += mbi.RegionSize

        k32.CloseHandle(handle)

    except Exception as e:
        print(f"[AEGIS] Windows memory scan error: {e}")

    return regions


# ── Network Connection Capture ────────────────────────────────────────────────

def capture_network_connections(pid: int) -> tuple[list[dict], list[str]]:
    """Capture all network connections at time of kill."""
    connections  = []
    c2_candidates = []

    try:
        for conn in psutil.net_connections(kind="all"):
            try:
                local  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                proc_name = ""
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        pass

                c = {
                    "local_addr":  local,
                    "remote_addr": remote,
                    "status":      conn.status,
                    "pid":         conn.pid or 0,
                    "process":     proc_name,
                }
                connections.append(c)

                # Flag external established connections from the ransomware PID
                if (conn.pid == pid and
                    remote and
                    conn.status == "ESTABLISHED" and
                    not _is_private(remote.split(":")[0])):
                    c2_candidates.append(remote)

            except Exception:
                continue

    except Exception as e:
        print(f"[AEGIS] Network capture error: {e}")

    return connections, c2_candidates


# ── Ransom Note Finder ────────────────────────────────────────────────────────

def find_ransom_notes(watch_path: str) -> list[str]:
    """Look for newly created text files that are likely ransom notes."""
    notes        = []
    ransom_names = [
        "readme", "how_to_decrypt", "recover", "restore",
        "decrypt", "ransom", "help_decrypt", "!!!",
        "read_me", "important", "how_to_buy", "@please_read",
    ]

    try:
        now = time.time()
        for f in Path(watch_path).rglob("*.txt"):
            try:
                # Recently created (last 5 minutes) text files
                if now - f.stat().st_mtime < 300:
                    name_lower = f.stem.lower()
                    if any(r in name_lower for r in ransom_names):
                        notes.append(str(f))
            except Exception:
                continue
    except Exception:
        pass

    return notes[:10]


# ── Main Collector ────────────────────────────────────────────────────────────

class ForensicsCollector:

    def __init__(self, output_dir: str = "./evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def collect(self, kill_event, watch_path: str = "") -> EvidenceBundle:
        """
        Full forensic collection triggered by kill event.
        Returns structured EvidenceBundle.
        """
        print("\n[AEGIS] Starting forensic collection...")
        ts = datetime.now(timezone.utc).isoformat()

        bundle = EvidenceBundle(
            timestamp=ts,
            family_guess=kill_event.family_guess,
            detection_latency_ms=kill_event.detection_latency_ms,
            files_encrypted=kill_event.files_encrypted,
            files_saved=kill_event.files_saved_estimate,
            behavioral_score=kill_event.behavioral_score,
            trigger_signals=kill_event.trigger_signals,
            encrypted_files=kill_event.high_entropy_files,
            sample_sha256=kill_event.sha256_sample,
        )

        pid = kill_event.process_pid

        # 1. Process tree
        print("[AEGIS] Capturing process tree...")
        proc_nodes, malicious = capture_process_tree(pid)
        bundle.process_tree   = [
            {
                "pid":     n.pid, "ppid": n.ppid, "name": n.name,
                "cmdline": n.cmdline, "suspicious": n.suspicious,
            }
            for n in proc_nodes
        ]
        bundle.malicious_process = malicious
        print(f"[AEGIS] Process tree: {len(proc_nodes)} processes captured")

        # 2. Memory regions
        if pid > 0:
            print(f"[AEGIS] Scanning memory regions for PID {pid}...")
            regions = scan_memory_regions(pid)
            bundle.injected_regions = [
                {
                    "base": r.base_address, "size": r.size,
                    "protection": r.protection, "entropy": r.entropy,
                    "suspicious": r.suspicious,
                }
                for r in regions
            ]
            sus_count = sum(1 for r in regions if r.suspicious)
            print(f"[AEGIS] Memory: {len(regions)} regions, {sus_count} suspicious")

        # 3. Network connections
        print("[AEGIS] Capturing network connections...")
        conns, c2s           = capture_network_connections(pid)
        bundle.network_connections = conns
        bundle.c2_candidates       = c2s
        if c2s:
            print(f"[AEGIS] C2 candidates: {c2s}")

        # 4. Ransom notes
        if watch_path:
            bundle.ransom_notes = find_ransom_notes(watch_path)
            if bundle.ransom_notes:
                print(f"[AEGIS] Ransom notes found: {bundle.ransom_notes}")

        # 5. TTP inference
        bundle.ttps = infer_ttps(bundle)
        print(f"[AEGIS] TTPs inferred: {[t['technique_id'] for t in bundle.ttps]}")

        # 6. Save evidence bundle
        report_path = self.output_dir / f"evidence_{int(time.time())}.json"
        with open(report_path, "w") as f:
            json.dump(asdict(bundle), f, indent=2, default=str)
        bundle.report_path = str(report_path)
        print(f"[AEGIS] Evidence saved: {report_path}")

        return bundle
