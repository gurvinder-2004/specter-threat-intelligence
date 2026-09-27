"""
AEGIS — Filesystem Behavioral Interceptor
==========================================
Watches file system activity in real time and computes behavioral
signals that identify ransomware purely from what it DOES, not what it IS.

Run this on your HOST machine pointing at a shared folder with the VM,
OR run directly inside the VM via Python (no kernel driver needed).

Signals computed:
  1. Shannon entropy per write (encrypted = ~8.0 bits/byte)
  2. Write velocity (files/sec in sliding 2s window)
  3. VSS deletion attempt detection (process command line watch)
  4. File extension churn (rename ratio)
  5. Process tree anomaly (non-shell parent spawning cmd.exe)

Usage:
    python interceptor.py --watch C:\\Users --threshold 70
    python interceptor.py --watch /mnt/windows/Users --threshold 70
"""

import os
import sys
import math
import time
import hashlib
import argparse
import threading
import subprocess
import collections
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
# Dependencies check (psutil & watchdog)
try:
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileMovedEvent
except ImportError:
    print("[AEGIS] Installing required dependencies (watchdog, psutil)...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "watchdog", "psutil"])
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileMovedEvent

# ── Constants ─────────────────────────────────────────────────────────────────

# Entropy thresholds
ENTROPY_RANSOMWARE_MIN  = 7.0   # bits/byte — encrypted content
ENTROPY_NORMAL_MAX      = 6.0   # bits/byte — normal documents/executables
ENTROPY_SAMPLE_BYTES    = 4096  # bytes to read per file for entropy calc

# Velocity thresholds
VELOCITY_WINDOW_SECONDS = 1.0   # sliding window
VELOCITY_WARN_THRESHOLD = 15    # files/sec — suspicious
VELOCITY_KILL_THRESHOLD = 40    # files/sec — almost certainly ransomware

# Known ransomware extensions (supplementary signal only — NOT used as primary)
RANSOMWARE_EXTENSIONS = {
    ".wncry", ".wcry", ".wncryt",         # WannaCry
    ".lock", ".locked", ".lockbit",        # LockBit
    ".encrypt", ".encrypted",              # Generic
    ".crypt", ".crypted",                  # CryptXXX
    ".cerber", ".cerber2", ".cerber3",     # Cerber
    ".zepto", ".locky",                    # Locky
    ".osiris", ".diablo6",                 # Osiris/Locky variants
    ".ryk",                                # Ryuk
    ".conti",                              # Conti
    ".avos2", ".avoslinux",                # AvosLocker
    ".BlackMatter",                        # BlackMatter
    ".hive",                               # Hive
    ".rhysida",                            # Rhysida
}

# VSS deletion patterns
VSS_PATTERNS = [
    "vssadmin delete shadows",
    "vssadmin.exe delete",
    "wmic shadowcopy delete",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "bcdedit /set {default} recoveryenabled no",
    "wbadmin delete catalog",
    "diskshadow /s",
]

# Legitimate high-entropy processes (whitelist to reduce false positives)
ENTROPY_WHITELIST_PROCESSES = {
    "7z.exe", "7zfm.exe", "winzip.exe", "winrar.exe",
    "ffmpeg.exe", "handbrake.exe", "vlc.exe",
    "veracrypt.exe", "bitlocker",
    "python.exe", "pythonw.exe",  # compression libs
    "git.exe",                     # git pack objects
    "msiexec.exe",                 # installer compression
}

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class FileEvent:
    path:      str
    event_type: str   # "write", "create", "rename", "delete"
    timestamp: float
    entropy:   float = 0.0
    old_ext:   str   = ""
    new_ext:   str   = ""
    pid:       int   = 0
    process:   str   = ""


@dataclass
class BehavioralScore:
    total:              float = 0.0
    entropy_score:      float = 0.0
    velocity_score:     float = 0.0
    vss_score:          float = 0.0
    extension_score:    float = 0.0
    process_score:      float = 0.0
    high_entropy_count: int   = 0
    total_writes:       int   = 0
    files_per_sec:      float = 0.0
    vss_detected:       bool  = False
    suspicious_renames: int   = 0
    timestamp:          float = field(default_factory=time.time)


@dataclass
class KillEvent:
    timestamp:          str
    family_guess:       str
    detection_latency_ms: float
    files_encrypted:    int
    files_saved_estimate: int
    behavioral_score:   float
    trigger_signals:    list
    process_pid:        int
    process_name:       str
    process_cmdline:    str
    high_entropy_files: list
    memory_dump_path:   str = ""
    sha256_sample:      str = ""


# ── Shannon Entropy Calculator ────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte string.
    Returns bits per byte (0.0 to 8.0).
    8.0 = perfectly random = encrypted or compressed.
    """
    if not data:
        return 0.0
    freq = collections.Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str) -> float:
    """Read first ENTROPY_SAMPLE_BYTES of a file and compute entropy."""
    try:
        with open(path, "rb") as f:
            data = f.read(ENTROPY_SAMPLE_BYTES)
        if len(data) < 16:
            return 0.0
        return shannon_entropy(data)
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0


# ── Process Inspector ─────────────────────────────────────────────────────────

def get_process_for_file(path: str) -> tuple[int, str, str]:
    """
    Best-effort: find which process last touched a file.
    Uses psutil to scan open file handles.
    Returns (pid, name, cmdline).
    """
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline", "open_files"]):
            try:
                ofiles = proc.open_files()
                for f in ofiles:
                    if f.path.lower() == path.lower():
                        cmd = " ".join(proc.cmdline() or [])
                        return proc.pid, proc.name(), cmd
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return 0, "", ""


def check_vss_deletion() -> tuple[bool, str]:
    """
    Scan running processes for VSS deletion commands.
    These are near-definitive ransomware indicators.
    """
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmdline = " ".join(proc.cmdline() or []).lower()
                for pattern in VSS_PATTERNS:
                    if pattern.lower() in cmdline:
                        return True, cmdline
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return False, ""


def guess_family(events: list[FileEvent], vss: bool) -> str:
    """
    Heuristically guess the ransomware family from behavioral signals.
    NOT used for detection — used for the kill event report only.
    """
    extensions = {e.new_ext for e in events if e.new_ext}
    if ".wncry" in extensions or ".wcry" in extensions:
        return "WannaCry"
    if ".lockbit" in extensions or ".lock" in extensions:
        return "LockBit"
    if ".ryk" in extensions:
        return "Ryuk"
    if ".conti" in extensions:
        return "Conti"
    if ".hive" in extensions:
        return "Hive"
    if vss:
        return "Unknown (VSS deletion detected)"
    return "Unknown"


# ── Filesystem Event Handler ──────────────────────────────────────────────────

class AEGISEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler. Called on every filesystem event in the watched path.
    Computes entropy, logs events, feeds into the scoring engine.
    """

    def __init__(self, scoring_engine):
        super().__init__()
        self.engine = scoring_engine

    def on_modified(self, event):
        if event.is_directory:
            return
        self.engine.record_event(FileEvent(
            path=event.src_path,
            event_type="write",
            timestamp=time.time(),
            entropy=file_entropy(event.src_path),
        ))

    def on_created(self, event):
        if event.is_directory:
            return
        self.engine.record_event(FileEvent(
            path=event.src_path,
            event_type="create",
            timestamp=time.time(),
            entropy=file_entropy(event.src_path),
        ))

    def on_moved(self, event):
        if event.is_directory:
            return
        old_ext = Path(event.src_path).suffix.lower()
        new_ext = Path(event.dest_path).suffix.lower()
        self.engine.record_event(FileEvent(
            path=event.dest_path,
            event_type="rename",
            timestamp=time.time(),
            entropy=file_entropy(event.dest_path),
            old_ext=old_ext,
            new_ext=new_ext,
        ))

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.engine.record_event(FileEvent(
            path=event.src_path,
            event_type="delete",
            timestamp=time.time(),
        ))


# ── Scoring Engine ─────────────────────────────────────────────────────────────

class BehavioralScoringEngine:
    """
    Core AEGIS scoring engine.
    Maintains a sliding window of filesystem events and computes
    a behavioral threat score every 500ms.

    Score 0-100:
      0-30:  Normal activity
      30-60: Suspicious — monitor closely
      60-80: High confidence ransomware behavior
      80+:   KILL — fire immediately
    """

    def __init__(
        self,
        watch_path: str,
        kill_threshold: float = 75.0,
        on_kill_callback = None,
        on_score_callback = None,
    ):
        self.watch_path        = watch_path
        self.kill_threshold    = kill_threshold
        self.on_kill_callback  = on_kill_callback
        self.on_score_callback = on_score_callback

        self._events: list[FileEvent]           = []
        self._events_lock                       = threading.Lock()
        self._recent_writes: collections.deque = collections.deque()
        self._killed                            = False
        self._start_time                        = time.time()
        self._kill_event: Optional[KillEvent]   = None

        self.current_score = BehavioralScore()

        # Score history for ROC curve generation
        self.score_history: list[tuple[float, float]] = []  # (timestamp, score)

        # Scoring thread
        self._scoring_thread = threading.Thread(target=self._scoring_loop, daemon=True)
        self._scoring_thread.start()

        # VSS check thread
        self._vss_thread = threading.Thread(target=self._vss_loop, daemon=True)
        self._vss_thread.start()

        self._vss_detected    = False
        self._vss_cmdline     = ""

    def record_event(self, event: FileEvent):
        """Called by the filesystem handler on every file event."""
        if self._killed:
            return
        with self._events_lock:
            self._events.append(event)
            if event.event_type in ("write", "create"):
                self._recent_writes.append(event.timestamp)

    def _scoring_loop(self):
        """Runs every 500ms, recomputes behavioral score."""
        while not self._killed:
            time.sleep(0.5)
            score = self._compute_score()
            self.current_score = score
            self.score_history.append((time.time(), score.total))

            if self.on_score_callback:
                self.on_score_callback(score)

            if score.total >= self.kill_threshold and not self._killed:
                self._fire_kill(score)

    def _vss_loop(self):
        """Checks for VSS deletion attempts every 2 seconds."""
        while not self._killed:
            time.sleep(2.0)
            detected, cmdline = check_vss_deletion()
            if detected and not self._vss_detected:
                self._vss_detected = True
                self._vss_cmdline  = cmdline
                print(f"\n[AEGIS] ⚠ VSS DELETION DETECTED: {cmdline}")

    def _compute_score(self) -> BehavioralScore:
        score = BehavioralScore()
        now   = time.time()

        with self._events_lock:
            # Clean up events older than 10 seconds
            cutoff = now - 4.0
            self._events = [e for e in self._events if e.timestamp > cutoff]
            while self._recent_writes and self._recent_writes[0] < now - VELOCITY_WINDOW_SECONDS:
                self._recent_writes.popleft()

            events = list(self._events)
            recent_write_count = len(self._recent_writes)

        score.total_writes      = len(events)
        score.files_per_sec     = recent_write_count / VELOCITY_WINDOW_SECONDS
        score.vss_detected      = self._vss_detected

        # ── Signal 1: Shannon Entropy ─────────────────────────────────────────
        write_events = [e for e in events if e.event_type in ("write","create") and e.entropy > 0]
        if write_events:
            high_entropy = [e for e in write_events if e.entropy >= ENTROPY_RANSOMWARE_MIN]
            ratio = len(high_entropy) / len(write_events)
            score.high_entropy_count = len(high_entropy)
            # Score scales with ratio: 50% high-entropy writes → score 30, 90% → score 55
                        # Fixed - scores faster when high entropy detected
            if ratio >= 0.8:       # 80%+ writes are high entropy
                score.entropy_score = 55.0
            elif ratio >= 0.6:     # 60-80%
                score.entropy_score = 40.0
            elif ratio >= 0.4:     # 40-60%
                score.entropy_score = 25.0
            elif ratio >= 0.2:     # 20-40%
                score.entropy_score = 10.0
            else:
                score.entropy_score = ratio * 20.0

        # ── Signal 2: Write Velocity ──────────────────────────────────────────
        fps = score.files_per_sec
        if fps >= VELOCITY_KILL_THRESHOLD:
            score.velocity_score = 30.0
        elif fps >= VELOCITY_WARN_THRESHOLD:
            score.velocity_score = 15.0 + (fps - VELOCITY_WARN_THRESHOLD) / (VELOCITY_KILL_THRESHOLD - VELOCITY_WARN_THRESHOLD) * 15.0
        else:
            score.velocity_score = max(0, fps / VELOCITY_WARN_THRESHOLD * 8.0)

        # ── Signal 3: VSS Deletion ────────────────────────────────────────────
        # Near-definitive signal — immediate large score contribution
        score.vss_score = 35.0 if self._vss_detected else 0.0

        # ── Signal 4: File Extension Churn ────────────────────────────────────
        rename_events = [e for e in events if e.event_type == "rename"]
        if rename_events:
            # Ransomware extension additions
            known_ransom_renames = [e for e in rename_events if e.new_ext in RANSOMWARE_EXTENSIONS]
            score.suspicious_renames = len(known_ransom_renames)
            if known_ransom_renames:
                score.extension_score = min(40.0, len(known_ransom_renames) * 8.0)
            else:
                # Even unknown extensions — high rename volume is suspicious
                if len(rename_events) > 10:
                    score.extension_score = min(20.0, len(rename_events) * 1.5)

        # ── Signal 5: Process Anomaly ──────────────────────────────────────────
        # Check if any event came from a suspicious process
        # (We spot-check rather than resolving every event to avoid perf hit)
        score.process_score = 0.0
        if write_events:
            sample = write_events[-1]  # check most recent
            pid, pname, pcmd = get_process_for_file(sample.path)
            if pname and pname.lower() not in ENTROPY_WHITELIST_PROCESSES:
                if pid > 0 and score.entropy_score > 20:
                    score.process_score = 5.0

        # ── Total: weighted sum, capped at 100 ───────────────────────────────
        # VSS is near-definitive so it alone can push to kill threshold
        # Entropy + velocity together should also push to threshold
        score.total = min(100.0,
            score.entropy_score +
            score.velocity_score +
            score.vss_score +
            score.extension_score +
            score.process_score
        )

        return score

    def _fire_kill(self, score: BehavioralScore):
        """
        Kill switch: suspend the ransomware process tree immediately.
        Then collect forensic evidence.
        """
        if self._killed:
            return
        self._killed = True

        detection_time = time.time()
        latency_ms     = (detection_time - self._start_time) * 1000

        print(f"\n{'='*60}")
        print(f"  AEGIS KILL SWITCH FIRED")
        print(f"  Score: {score.total:.1f}/100")
        print(f"  Detection latency: {latency_ms:.0f}ms")
        print(f"{'='*60}\n")

        # Determine which signals triggered
        triggers = []
        if score.entropy_score > 20:  triggers.append(f"high_entropy ({score.high_entropy_count} files)")
        if score.velocity_score > 10: triggers.append(f"write_velocity ({score.files_per_sec:.1f} files/sec)")
        if score.vss_score > 0:       triggers.append("vss_deletion")
        if score.extension_score > 0: triggers.append(f"extension_churn ({score.suspicious_renames} renames)")

        # Find and suspend suspicious high-entropy writing processes
        killed_pid, killed_name, killed_cmd = 0, "unknown", ""
        with self._events_lock:
            recent = [e for e in self._events if e.entropy >= ENTROPY_RANSOMWARE_MIN]

        if recent:
            pid, pname, pcmd = get_process_for_file(recent[-1].path)
            if pid > 0:
                killed_pid, killed_name, killed_cmd = pid, pname, pcmd
                try:
                    proc = psutil.Process(pid)
                    # Suspend the entire process tree
                    children = proc.children(recursive=True)
                    for child in children:
                        try:
                            child.suspend()
                            print(f"  Suspended child: {child.name()} (PID {child.pid})")
                        except Exception:
                            pass
                    proc.suspend()
                    print(f"  Suspended: {pname} (PID {pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"  Could not suspend PID {pid}: {e}")

        # Count encrypted files (high entropy writes in this session)
        with self._events_lock:
            encrypted_files = [e for e in self._events if e.entropy >= ENTROPY_RANSOMWARE_MIN]
            high_entropy_paths = [e.path for e in encrypted_files[:20]]

        files_encrypted = len(encrypted_files)

        # Estimate files saved (heuristic: safely count without blocking on deep or permission-denied trees)
        try:
            total_files = 0
            for root, _, files in os.walk(self.watch_path):
                total_files += len(files)
                if total_files >= 2000:
                    break
            files_saved = max(0, total_files - files_encrypted)
        except Exception:
            files_saved = max(0, 500 - files_encrypted)

        family = guess_family(self._events, self._vss_detected)

        kill_event = KillEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            family_guess=family,
            detection_latency_ms=round(latency_ms, 2),
            files_encrypted=files_encrypted,
            files_saved_estimate=files_saved,
            behavioral_score=score.total,
            trigger_signals=triggers,
            process_pid=killed_pid,
            process_name=killed_name,
            process_cmdline=killed_cmd,
            high_entropy_files=high_entropy_paths,
        )

        self._kill_event = kill_event

        if self.on_kill_callback:
            self.on_kill_callback(kill_event)


# ── Observer / Main runner ────────────────────────────────────────────────────

class AEGISInterceptor:
    """Top-level coordinator. Use this in your integration code."""

    def __init__(
        self,
        watch_path: str,
        kill_threshold: float = 75.0,
        on_kill = None,
        on_score = None,
    ):
        self.watch_path     = watch_path
        self.engine         = BehavioralScoringEngine(
            watch_path=watch_path,
            kill_threshold=kill_threshold,
            on_kill_callback=on_kill,
            on_score_callback=on_score,
        )
        self.handler        = AEGISEventHandler(self.engine)
        self.observer       = Observer()
        self.observer.schedule(self.handler, watch_path, recursive=True)

    def start(self):
        self.observer.start()
        print(f"[AEGIS] Interceptor started → watching {self.watch_path}")
        print(f"[AEGIS] Kill threshold: {self.engine.kill_threshold}/100")
        print(f"[AEGIS] Press Ctrl+C to stop\n")

    def stop(self):
        self.observer.stop()
        self.observer.join()

    @property
    def current_score(self) -> BehavioralScore:
        return self.engine.current_score

    @property
    def kill_event(self) -> Optional[KillEvent]:
        return self.engine._kill_event

    @property
    def score_history(self):
        return self.engine.score_history


# ── CLI entrypoint ────────────────────────────────────────────────────────────

def _print_score(score: BehavioralScore):
    bar_len = 40
    filled  = int(score.total / 100 * bar_len)
    bar     = "█" * filled + "░" * (bar_len - filled)
    color   = "\033[91m" if score.total >= 75 else "\033[93m" if score.total >= 40 else "\033[92m"
    reset   = "\033[0m"
    print(
        f"\r{color}[{bar}] {score.total:5.1f}/100{reset} | "
        f"entropy:{score.entropy_score:4.1f} "
        f"vel:{score.velocity_score:4.1f} "
        f"vss:{score.vss_score:4.1f} "
        f"ext:{score.extension_score:4.1f} | "
        f"{score.files_per_sec:.1f}f/s | "
        f"H:{score.high_entropy_count}",
        end="", flush=True
    )


def _on_kill(kill_event: KillEvent):
    import json
    print(f"\n\n{'='*60}")
    print(f"  ☠  RANSOMWARE KILLED — {kill_event.family_guess}")
    print(f"{'='*60}")
    print(f"  Detection latency : {kill_event.detection_latency_ms:.0f}ms")
    print(f"  Files encrypted   : {kill_event.files_encrypted}")
    print(f"  Files saved       : {kill_event.files_saved_estimate}")
    print(f"  Behavioral score  : {kill_event.behavioral_score:.1f}/100")
    print(f"  Trigger signals   : {', '.join(kill_event.trigger_signals)}")
    print(f"  Process killed    : {kill_event.process_name} (PID {kill_event.process_pid})")
    print(f"\n  Sample encrypted files:")
    for p in kill_event.high_entropy_files[:5]:
        print(f"    {p}")

    # Save kill report
    report_path = f"aegis_kill_{int(time.time())}.json"
    import dataclasses
    with open(report_path, "w") as f:
        json.dump(dataclasses.asdict(kill_event), f, indent=2)
    print(f"\n  Kill report saved: {report_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Ransomware Behavioral Interceptor")
    parser.add_argument("--watch",     default="C:\\Users", help="Directory to monitor")
    parser.add_argument("--threshold", type=float, default=75.0, help="Kill threshold (0-100)")
    args = parser.parse_args()

    interceptor = AEGISInterceptor(
        watch_path=args.watch,
        kill_threshold=args.threshold,
        on_kill=_on_kill,
        on_score=_print_score,
    )

    interceptor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[AEGIS] Stopping...")
        interceptor.stop()
