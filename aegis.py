"""
AEGIS — Main Orchestrator
==========================
Single entry point that wires together:
  - Filesystem interceptor (behavioral scoring)
  - Memory forensics collector (evidence on kill)
  - SPECTER integration (threat graph + Discord)
  - Real-time score API (for dashboard)

Run this INSIDE the Windows VM (or on host watching a shared folder).

Usage:
    # Basic — watch C:\\Users, kill at score 75
    python aegis.py

    # Custom path and threshold
    python aegis.py --watch "C:\\Users\\victim" --threshold 70

    # Demo mode — lower threshold, verbose output
    python aegis.py --demo

    # Test mode — run against synthetic ransomware simulator
    python aegis.py --test
"""

import os
import sys
import json
import time
import asyncio
import argparse
import threading
import platform
from pathlib import Path
from datetime import datetime, timezone

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from aegis.interceptor import AEGISInterceptor, BehavioralScore, KillEvent
from aegis.forensics   import ForensicsCollector
from aegis.specter_bridge import post_kill_to_specter

# ── FastAPI score server (lets the SPECTER dashboard poll live score) ─────────
try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

# ── Global state ──────────────────────────────────────────────────────────────

_interceptor: AEGISInterceptor = None
_latest_score: dict            = {}
_kill_events:  list            = []
_score_history: list           = []
_args: argparse.Namespace      = None


# ── Score callback ────────────────────────────────────────────────────────────

def on_score_update(score: BehavioralScore):
    global _latest_score, _score_history

    _latest_score = {
        "total":              round(score.total, 1),
        "entropy_score":      round(score.entropy_score, 1),
        "velocity_score":     round(score.velocity_score, 1),
        "vss_score":          round(score.vss_score, 1),
        "extension_score":    round(score.extension_score, 1),
        "process_score":      round(score.process_score, 1),
        "high_entropy_count": score.high_entropy_count,
        "files_per_sec":      round(score.files_per_sec, 2),
        "total_writes":       score.total_writes,
        "vss_detected":       score.vss_detected,
        "suspicious_renames": score.suspicious_renames,
        "timestamp":          time.time(),
        "status":             _status_label(score.total),
    }

    _score_history.append({
        "t":     time.time(),
        "score": round(score.total, 1),
    })
    # Keep last 500 data points
    if len(_score_history) > 500:
        _score_history.pop(0)

    # Print to terminal
    if _args and _args.demo:
        _print_score_bar(score)


def _status_label(score: float) -> str:
    if score >= 75: return "KILL_FIRED"
    if score >= 60: return "CRITICAL"
    if score >= 40: return "WARNING"
    if score >= 20: return "SUSPICIOUS"
    return "NORMAL"


def _print_score_bar(score: BehavioralScore):
    bar_len = 35
    filled  = int(score.total / 100 * bar_len)
    bar     = "█" * filled + "░" * (bar_len - filled)
    colors  = {
        "KILL_FIRED": "\033[91m", "CRITICAL": "\033[91m",
        "WARNING":    "\033[93m", "SUSPICIOUS": "\033[93m",
        "NORMAL":     "\033[92m",
    }
    c = colors.get(_status_label(score.total), "\033[0m")
    r = "\033[0m"
    print(
        f"\r{c}AEGIS [{bar}] {score.total:5.1f}{r} | "
        f"E:{score.entropy_score:.0f} V:{score.velocity_score:.0f} "
        f"VSS:{score.vss_score:.0f} EXT:{score.extension_score:.0f} | "
        f"{score.files_per_sec:.1f}f/s",
        end="", flush=True
    )


# ── Kill callback ──────────────────────────────────────────────────────────────

def on_kill(kill_event: KillEvent):
    print(f"\n\n{'='*60}")
    print(f"  ☠  AEGIS KILL SWITCH FIRED")
    print(f"  Family:    {kill_event.family_guess}")
    print(f"  Latency:   {kill_event.detection_latency_ms:.0f}ms")
    print(f"  Encrypted: {kill_event.files_encrypted} files")
    print(f"  Saved:     {kill_event.files_saved_estimate} files")
    print(f"  Score:     {kill_event.behavioral_score:.1f}/100")
    print(f"  Signals:   {', '.join(kill_event.trigger_signals)}")
    print(f"{'='*60}\n")

    _kill_events.append({
        "timestamp":          kill_event.timestamp,
        "family":             kill_event.family_guess,
        "latency_ms":         kill_event.detection_latency_ms,
        "files_encrypted":    kill_event.files_encrypted,
        "files_saved":        kill_event.files_saved_estimate,
        "score":              kill_event.behavioral_score,
        "triggers":           kill_event.trigger_signals,
        "pid":                kill_event.process_pid,
        "process_name":       kill_event.process_name,
    })

    # Run forensics + SPECTER bridge in background
    asyncio.run(_post_kill_async(kill_event))


async def _post_kill_async(kill_event: KillEvent):
    watch_path = _args.watch if _args else "."
    collector  = ForensicsCollector(output_dir="./evidence")

    print("[AEGIS] Collecting forensic evidence...")
    bundle = await collector.collect(kill_event, watch_path=watch_path)

    print("[AEGIS] Posting to SPECTER...")
    import dataclasses
    specter_url = getattr(_args, "specter_url", None)
    success = await post_kill_to_specter(dataclasses.asdict(bundle), specter_api=specter_url)
    if success:
        print("[AEGIS] ✓ Kill event posted to SPECTER threat graph")
    else:
        target = specter_url or "http://localhost:8000"
        print(f"[AEGIS] ✗ SPECTER post failed — check that SPECTER is running at {target}")


# ── FastAPI score server ───────────────────────────────────────────────────────

if HAS_FASTAPI:
    app = FastAPI(title="AEGIS Score API")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/aegis/score")
    async def get_score():
        return _latest_score or {"total": 0, "status": "NORMAL", "timestamp": time.time()}

    @app.get("/aegis/history")
    async def get_history():
        return {"history": _score_history[-120:]}  # last 60 seconds at 500ms intervals

    @app.get("/aegis/kills")
    async def get_kills():
        return {"kills": _kill_events, "count": len(_kill_events)}

    @app.get("/aegis/status")
    async def get_status():
        return {
            "running":    _interceptor is not None,
            "watch_path": _args.watch if _args else "",
            "threshold":  _args.threshold if _args else 75,
            "kills":      len(_kill_events),
            "score":      _latest_score.get("total", 0),
            "status":     _latest_score.get("status", "NORMAL"),
        }

    def _run_api():
        uvicorn.run(app, host="0.0.0.0", port=8001, log_level="error")


# ── Test mode: synthetic ransomware simulator ─────────────────────────────────

def run_synthetic_test(watch_path: str):
    """
    Simulates ransomware behavior by writing high-entropy files
    to the watched directory. Use this to test AEGIS without real malware.

    Stages:
      1. Slow warmup (normal writes)
      2. Acceleration (increasing write velocity)
      3. Ransomware behavior (high entropy + high velocity + renames)
    """
    import random
    import struct

    test_dir = Path(watch_path) / "aegis_test_victims"
    test_dir.mkdir(exist_ok=True)

    print(f"\n[AEGIS TEST] Creating victim files in {test_dir}...")
    # Create some "normal" files to encrypt
    for i in range(50):
        victim = test_dir / f"document_{i:03d}.docx"
        victim.write_text(f"Normal document content {i} " * 100)
    print(f"[AEGIS TEST] Created 50 victim files")

    time.sleep(2)
    print(f"[AEGIS TEST] Stage 1: Normal activity (5 sec)...")

    # Stage 1: normal writes
    for i in range(10):
        f = test_dir / f"normal_write_{i}.tmp"
        f.write_text("normal content " * 50)
        time.sleep(0.5)

    print(f"[AEGIS TEST] Stage 2: Accelerating (ransomware warming up)...")

    # Stage 2: accelerating
    for i in range(20):
        f = test_dir / f"accelerating_{i}.tmp"
        f.write_bytes(bytes([random.randint(0, 255) for _ in range(512)]))
        time.sleep(0.15)

    print(f"[AEGIS TEST] Stage 3: RANSOMWARE BEHAVIOR (high entropy + velocity)...")

    # Stage 3: ransomware behavior
    # High entropy writes + file renames
    for i in range(50):
        # Write high-entropy (fake encrypted) content
        victim = test_dir / f"document_{i:03d}.docx"
        if victim.exists():
            # Overwrite with high-entropy data
            fake_encrypted = bytes([random.randint(0, 255) for _ in range(4096)])
            victim.write_bytes(fake_encrypted)
            # Rename with ransomware extension
            encrypted = test_dir / f"document_{i:03d}.docx.wncry"
            victim.rename(encrypted)
        time.sleep(0.02)  # 20 files/sec — above kill threshold

    print(f"[AEGIS TEST] Ransomware simulation complete.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global _interceptor, _args

    parser = argparse.ArgumentParser(
        description="AEGIS — Ransomware Behavioral Interception Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aegis.py                              # Watch C:\\Users, kill at 75
  python aegis.py --watch D:\\Documents        # Custom watch path
  python aegis.py --threshold 60              # More sensitive
  python aegis.py --demo                      # Verbose output mode
  python aegis.py --test                      # Run synthetic test (no real malware)
        """
    )

    default_watch = "C:\\Users" if platform.system() == "Windows" else str(Path.home())

    default_specter = os.getenv("SPECTER_API_URL", "http://localhost:8000")

    parser.add_argument("--watch",       default=default_watch,
                        help=f"Directory to monitor (default: {default_watch})")
    parser.add_argument("--threshold",   type=float, default=65.0,
                        help="Kill threshold 0-100 (default: 65)")
    parser.add_argument("--specter-url", default=default_specter,
                        help=f"SPECTER API endpoint (default: {default_specter})")
    parser.add_argument("--demo",        action="store_true",
                        help="Demo mode: verbose score display")
    parser.add_argument("--test",        action="store_true",
                        help="Run synthetic ransomware test")
    parser.add_argument("--no-api",      action="store_true",
                        help="Disable score API server on :8001")

    _args = parser.parse_args()

    # Banner
    print(f"""
\033[91m╔══════════════════════════════════════════════════════╗
║          AEGIS — RANSOMWARE BEHAVIORAL INTERCEPTOR   ║
║          Part of SPECTER Threat Intelligence Suite   ║
╚══════════════════════════════════════════════════════╝\033[0m
  Watch path : {_args.watch}
  Threshold  : {_args.threshold}/100
  Score API  : http://localhost:8001/aegis/score
  SPECTER    : {_args.specter_url}
""")

    # Start score API server in background thread
    if HAS_FASTAPI and not _args.no_api:
        api_thread = threading.Thread(target=_run_api, daemon=True)
        api_thread.start()
        print(f"[AEGIS] Score API running on :8001")

    # Start interceptor
    _interceptor = AEGISInterceptor(
        watch_path=_args.watch,
        kill_threshold=_args.threshold,
        on_kill=on_kill,
        on_score=on_score_update,
    )
    _interceptor.start()

    # Run synthetic test if requested
    if _args.test:
        print("\n[AEGIS] Starting synthetic ransomware test in 3 seconds...")
        print("[AEGIS] Watch the score climb in real time.\n")
        time.sleep(3)
        test_thread = threading.Thread(
            target=run_synthetic_test,
            args=(_args.watch,),
            daemon=True
        )
        test_thread.start()

    # Main loop
    print(f"[AEGIS] Monitoring active. Waiting for threats...\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[AEGIS] Shutting down...")
        _interceptor.stop()

        # Print session summary
        print(f"\n{'='*50}")
        print(f"  SESSION SUMMARY")
        print(f"{'='*50}")
        print(f"  Kill events: {len(_kill_events)}")
        for ke in _kill_events:
            print(f"  → {ke['family']} | {ke['latency_ms']:.0f}ms | "
                  f"{ke['files_encrypted']} encrypted | {ke['files_saved']} saved")

        if _interceptor.score_history:
            scores = [s for _, s in _interceptor.score_history]
            print(f"  Score peak:  {max(scores):.1f}/100")
            print(f"  Score mean:  {sum(scores)/len(scores):.1f}/100")
        print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
