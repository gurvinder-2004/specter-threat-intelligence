"""
AEGIS — Research Results Generator
=====================================
Runs AEGIS against multiple test scenarios and generates:
  1. ROC curve (TPR vs FPR at different thresholds)
  2. Results table (latency, files encrypted, false positives per family)
  3. Score distribution plot (normal vs ransomware)

This is your research output — the data you present to your professor.

Usage:
    python research/results_generator.py --mode roc
    python research/results_generator.py --mode table
    python research/results_generator.py --mode all

Requires:
    pip install matplotlib numpy scipy
"""

import os
import sys
import json
import time
import math
import random
import argparse
import threading
from pathlib import Path
from datetime import datetime

root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(root_dir) not in sys.path:
    sys.path.append(str(root_dir))

from aegis.interceptor import AEGISInterceptor, shannon_entropy

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MATPLOTLIB = True
except ImportError:
    print("Installing matplotlib and numpy...")
    os.system(f"{sys.executable} -m pip install matplotlib numpy")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MATPLOTLIB = True


# ── Synthetic test scenarios ──────────────────────────────────────────────────

def simulate_ransomware(watch_path: str, family: str = "WannaCry", speed: float = 1.0):
    """
    Simulate ransomware behavior by writing high-entropy files.
    speed: 1.0 = realistic, 2.0 = faster, 0.5 = slower
    """
    test_dir = Path(watch_path) / f"sim_{family.lower()}_{int(time.time())}"
    test_dir.mkdir(parents=True, exist_ok=True)

    # Create victim files
    for i in range(100):
        f = test_dir / f"doc_{i:03d}.docx"
        f.write_text(f"Document content {i} " * 50)

    time.sleep(1)

    # Simulate encryption
    extensions = {"WannaCry": ".wncry", "LockBit": ".lockbit", "Generic": ".encrypted"}
    ext = extensions.get(family, ".enc")

    for i in range(100):
        victim = test_dir / f"doc_{i:03d}.docx"
        if victim.exists():
            # Write high-entropy (encrypted) content
            encrypted_data = bytes([random.randint(0, 255) for _ in range(4096)])
            victim.write_bytes(encrypted_data)
            # Rename
            victim.rename(test_dir / f"doc_{i:03d}.docx{ext}")
        time.sleep(0.05 / speed)

    # Simulate VSS deletion (write to a temp file with the command, don't actually run it)
    vss_sim = test_dir / "vss_cmd.txt"
    vss_sim.write_text("vssadmin delete shadows /all /quiet")


def simulate_legitimate_highentropy(watch_path: str, tool: str = "7zip"):
    """
    Simulate legitimate high-entropy operations that should NOT trigger AEGIS.
    These form the false-positive test cases.
    """
    test_dir = Path(watch_path) / f"legit_{tool}_{int(time.time())}"
    test_dir.mkdir(parents=True, exist_ok=True)

    if tool == "7zip":
        # Compress/decompress — high entropy writes but not ransomware
        for i in range(30):
            f = test_dir / f"archive_{i}.zip"
            data = bytes([random.randint(0, 255) for _ in range(2048)])
            f.write_bytes(data)
            time.sleep(0.1)

    elif tool == "video_encode":
        # Video encoding — large high-entropy writes
        for i in range(10):
            f = test_dir / f"frame_{i:04d}.raw"
            data = bytes([random.randint(100, 200) for _ in range(8192)])
            f.write_bytes(data)
            time.sleep(0.3)

    elif tool == "git_pack":
        # Git pack objects — binary, high entropy
        for i in range(20):
            f = test_dir / f"pack_{i:04d}.pack"
            data = bytes([random.randint(0, 255) for _ in range(1024)])
            f.write_bytes(data)
            time.sleep(0.15)


# ── Single run measurement ────────────────────────────────────────────────────

def run_single_measurement(
    watch_path: str,
    scenario: str,
    family: str = "",
    threshold: float = 75.0,
    timeout: float = 60.0,
) -> dict:
    """
    Run one complete AEGIS test and return measurement results.
    """
    results = {
        "scenario":      scenario,
        "family":        family,
        "threshold":     threshold,
        "killed":        False,
        "latency_ms":    None,
        "files_encrypted": 0,
        "peak_score":    0.0,
        "score_at_kill": 0.0,
        "true_positive": False,
        "false_positive": False,
    }

    kill_event_received = threading.Event()

    def on_kill(kill_event):
        results["killed"]           = True
        results["latency_ms"]       = kill_event.detection_latency_ms
        results["files_encrypted"]  = kill_event.files_encrypted
        results["score_at_kill"]    = kill_event.behavioral_score
        if scenario == "ransomware":
            results["true_positive"] = True
        else:
            results["false_positive"] = True
        kill_event_received.set()

    scores = []
    def on_score(score):
        scores.append(score.total)
        if score.total > results["peak_score"]:
            results["peak_score"] = score.total

    interceptor = AEGISInterceptor(
        watch_path=watch_path,
        kill_threshold=threshold,
        on_kill=on_kill,
        on_score=on_score,
    )
    interceptor.start()

    # Run the simulation in a thread
    if scenario == "ransomware":
        sim_thread = threading.Thread(
            target=simulate_ransomware,
            args=(watch_path, family),
            daemon=True,
        )
    else:
        sim_thread = threading.Thread(
            target=simulate_legitimate_highentropy,
            args=(watch_path, family),
            daemon=True,
        )
    sim_thread.start()

    # Wait for kill or timeout
    kill_event_received.wait(timeout=timeout)
    interceptor.stop()

    results["score_history"] = scores
    return results


# ── ROC curve generator ───────────────────────────────────────────────────────

def generate_roc_curve(watch_path: str, runs_per_threshold: int = 3):
    """
    Generate ROC curve by running AEGIS at different thresholds
    against both ransomware and legitimate scenarios.
    """
    print("\n[ROC] Generating ROC curve data...")
    print(f"[ROC] {runs_per_threshold} runs × each threshold × both scenarios")

    thresholds = [30, 40, 50, 60, 70, 75, 80, 85, 90, 95]
    roc_points = []

    ransomware_families = ["WannaCry", "LockBit", "Generic"]
    legit_tools         = ["7zip", "video_encode", "git_pack"]

    for threshold in thresholds:
        print(f"\n[ROC] Threshold: {threshold}...")
        tp, fp, tn, fn = 0, 0, 0, 0

        # Ransomware runs
        for i in range(runs_per_threshold):
            family = ransomware_families[i % len(ransomware_families)]
            print(f"  Ransomware run {i+1}/{runs_per_threshold} ({family})...", end=" ")
            r = run_single_measurement(watch_path, "ransomware", family, threshold, timeout=30)
            if r["killed"] and r["true_positive"]:
                tp += 1
                print(f"TP (score={r['peak_score']:.0f})")
            else:
                fn += 1
                print(f"FN (score={r['peak_score']:.0f})")

        # Legitimate runs
        for i in range(runs_per_threshold):
            tool = legit_tools[i % len(legit_tools)]
            print(f"  Legit run {i+1}/{runs_per_threshold} ({tool})...", end=" ")
            r = run_single_measurement(watch_path, "legitimate", tool, threshold, timeout=30)
            if r["killed"] and r["false_positive"]:
                fp += 1
                print(f"FP (score={r['peak_score']:.0f})")
            else:
                tn += 1
                print(f"TN (score={r['peak_score']:.0f})")

        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        roc_points.append({"threshold": threshold, "tpr": tpr, "fpr": fpr, "tp": tp, "fp": fp, "tn": tn, "fn": fn})
        print(f"  TPR={tpr:.2f} FPR={fpr:.2f}")

    # Plot
    _plot_roc(roc_points)
    return roc_points


def _plot_roc(points: list):
    fig, ax = plt.subplots(1, 1, figsize=(8, 7))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#080c10")

    fprs = [p["fpr"] for p in points]
    tprs = [p["tpr"] for p in points]

    # Random classifier baseline
    ax.plot([0, 1], [0, 1], "--", color="#3d5166", linewidth=1, label="Random classifier")

    # AEGIS ROC curve
    ax.plot(fprs, tprs, "o-", color="#ff3333", linewidth=2.5, markersize=8,
            markerfacecolor="#ff3333", label="AEGIS behavioral detector")

    # Annotate threshold values
    for p in points:
        ax.annotate(
            f"  T={p['threshold']}",
            (p["fpr"], p["tpr"]),
            fontsize=8, color="#8b949e",
        )

    # Compute AUC (trapezoidal)
    sorted_pts = sorted(points, key=lambda x: x["fpr"])
    auc = np.trapz([p["tpr"] for p in sorted_pts], [p["fpr"] for p in sorted_pts])
    auc = max(0.0, min(1.0, abs(auc)))

    ax.set_xlabel("False Positive Rate", color="#8b949e", fontsize=12)
    ax.set_ylabel("True Positive Rate", color="#8b949e", fontsize=12)
    ax.set_title(f"AEGIS ROC Curve — AUC = {auc:.3f}", color="#e6edf3", fontsize=14, fontweight="bold")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.tick_params(colors="#8b949e")
    ax.spines["bottom"].set_color("#1a2332")
    ax.spines["left"].set_color("#1a2332")
    ax.spines["top"].set_color("#1a2332")
    ax.spines["right"].set_color("#1a2332")
    ax.grid(True, color="#1a2332", alpha=0.5)
    ax.legend(facecolor="#0d1117", edgecolor="#1a2332", labelcolor="#c9d1d9")

    plt.tight_layout()
    out_path = "aegis_roc_curve.png"
    plt.savefig(out_path, dpi=150, facecolor="#0d1117")
    print(f"\n[ROC] Curve saved: {out_path}")
    plt.show()


# ── Results table ─────────────────────────────────────────────────────────────

def generate_results_table(watch_path: str, runs_per_family: int = 5):
    """
    Generate the results table your professor will see:
    Family | Avg latency | Avg files encrypted | Detection rate | False positive rate
    """
    print("\n[TABLE] Generating results table...")
    families = ["WannaCry", "LockBit", "Generic"]
    legit    = ["7zip", "video_encode"]
    rows     = []

    for family in families:
        print(f"\n[TABLE] Testing {family} × {runs_per_family} runs...")
        latencies  = []
        encrypted  = []
        detections = 0

        for i in range(runs_per_family):
            print(f"  Run {i+1}/{runs_per_family}...", end=" ", flush=True)
            r = run_single_measurement(watch_path, "ransomware", family, 75.0, timeout=30)
            if r["true_positive"]:
                detections += 1
                latencies.append(r["latency_ms"])
                encrypted.append(r["files_encrypted"])
                print(f"DETECTED ({r['latency_ms']:.0f}ms, {r['files_encrypted']} files)")
            else:
                print(f"MISSED (peak score: {r['peak_score']:.0f})")

        rows.append({
            "family":         family,
            "detection_rate": f"{detections/runs_per_family*100:.0f}%",
            "avg_latency_ms": f"{sum(latencies)/len(latencies):.0f}" if latencies else "—",
            "avg_encrypted":  f"{sum(encrypted)/len(encrypted):.1f}" if encrypted else "—",
            "runs":           runs_per_family,
        })

    # False positive tests
    print("\n[TABLE] Testing false positive scenarios...")
    fp_results = []
    for tool in legit:
        fps = 0
        for i in range(runs_per_family):
            r = run_single_measurement(watch_path, "legitimate", tool, 75.0, timeout=30)
            if r["false_positive"]:
                fps += 1
        fp_results.append({"tool": tool, "fp_rate": f"{fps/runs_per_family*100:.0f}%"})

    # Print table
    _print_results_table(rows, fp_results)

    # Save as JSON
    results = {"ransomware_results": rows, "false_positive_results": fp_results}
    with open("aegis_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[TABLE] Results saved: aegis_results.json")

    return results


def _print_results_table(rows, fp_results):
    print(f"\n{'='*70}")
    print(f"  AEGIS DETECTION RESULTS")
    print(f"{'='*70}")
    print(f"  {'Family':<16} {'Detection':<12} {'Avg Latency':<14} {'Avg Files Enc.':<16}")
    print(f"  {'-'*60}")
    for r in rows:
        print(f"  {r['family']:<16} {r['detection_rate']:<12} {r['avg_latency_ms']} ms{'':<10} {r['avg_encrypted']}")

    print(f"\n  FALSE POSITIVE RATE (legitimate software)")
    print(f"  {'-'*40}")
    for fp in fp_results:
        print(f"  {fp['tool']:<20} {fp['fp_rate']}")
    print(f"{'='*70}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode",    choices=["roc","table","all"], default="table")
    parser.add_argument("--watch",   default=str(Path.home() / "aegis_test"))
    parser.add_argument("--runs",    type=int, default=3)
    args = parser.parse_args()

    Path(args.watch).mkdir(parents=True, exist_ok=True)

    if args.mode in ("table", "all"):
        generate_results_table(args.watch, runs_per_family=args.runs)

    if args.mode in ("roc", "all"):
        generate_roc_curve(args.watch, runs_per_threshold=args.runs)
