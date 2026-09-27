import { useState, useEffect, useRef } from "react";

const T = {
  bg:       "linear-gradient(135deg, #f3f6f9 0%, #e2e8f0 100%)",
  surface:  "#ffffff",
  raise:    "#f5f8fa",
  hover:    "#edf1f5",
  border:   "rgba(12, 7, 64, 0.08)",
  borderMd: "rgba(12, 7, 64, 0.14)",
  red:      "#d32f2f",
  blue:     "#1a73e8",
  green:    "#1b873f",
  purple:   "#6c4eb8",
  amber:    "#d97706",
  t1:       "#0c0740", // Deep navy
  t2:       "#4a5270", // Slate grey
  t3:       "#838da8", // Light slate
  orange:   "#f97316"
};

const DEFAULT_AEGIS_API = import.meta.env.VITE_AEGIS_API_URL || "http://localhost:8001";

const STATUS_CONFIG = {
  NORMAL:    { color: T.green,  label: "Monitoring Stable" },
  SUSPICIOUS:{ color: "#d97706",label: "Suspicious Activity" },
  WARNING:   { color: T.amber,  label: "Warning Risk" },
  CRITICAL:  { color: T.red,    label: "Critical Threat" },
  KILL_FIRED:{ color: T.red,    label: "Process Intercepted" },
};

const SIGNALS = [
  { key:"entropy_score",   label:"Shannon Entropy",  max:55, color:T.red    },
  { key:"velocity_score",  label:"Write Velocity",   max:30, color:T.amber  },
  { key:"vss_score",       label:"VSS Deletion Attempt", max:35, color:T.purple },
  { key:"extension_score", label:"Extension Churn Rate", max:40, color:T.blue },
];

// Circular score ring using SVG
function ScoreRing({ score, color, size = 120 }) {
  const r     = 46;
  const circ  = 2 * Math.PI * r;
  const dash  = circ - (score / 100) * circ;

  return (
    <svg width={size} height={size} viewBox="0 0 100 100" style={{ transform: "rotate(-90deg)" }}>
      <circle cx="50" cy="50" r={r} fill="none" stroke={T.raise} strokeWidth="8" />
      <circle cx="50" cy="50" r={r} fill="none"
        stroke={color} strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={circ}
        strokeDashoffset={dash}
        style={{ transition: "stroke-dashoffset 0.5s ease, stroke 0.3s ease" }}
      />
    </svg>
  );
}

// Mini bar chart for score history
function ScoreChart({ history }) {
  const max = 100;
  const pts = history.slice(-80);
  if (!pts.length) return null;

  const W = 600, H = 100;
  const xs = pts.map((_, i) => (i / Math.max(pts.length - 1, 1)) * W);
  const ys = pts.map(p => H - (p.score / max) * H);

  const pathD = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${xs[i].toFixed(1)} ${ys[i].toFixed(1)}`).join(" ");
  const fillD = pathD + ` L ${W} ${H} L 0 ${H} Z`;

  const lastScore = pts[pts.length - 1]?.score ?? 0;
  const lineColor = lastScore >= 75 ? T.red : lastScore >= 40 ? T.amber : T.green;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: 100, display: "block" }}>
      {/* Kill threshold line at 75% */}
      <line x1="0" y1={H * 0.25} x2={W} y2={H * 0.25}
        stroke={T.red} strokeWidth="1" strokeDasharray="4,4" opacity="0.4" />
      <text x="6" y={H * 0.25 - 4} fill={T.red} fontSize="8" fontWeight="700" opacity="0.6">75 THRESHOLD KILL</text>
      {/* Fill */}
      <path d={fillD} fill={lineColor} opacity="0.08" />
      {/* Line */}
      <path d={pathD} fill="none" stroke={lineColor} strokeWidth="2.0" strokeLinejoin="round" />
    </svg>
  );
}

export default function AEGISDashboard() {
  const [aegisHost, setAegisHost] = useState(() => localStorage.getItem("specter_aegis_host") || DEFAULT_AEGIS_API);
  const [editingHost, setEditingHost] = useState(false);
  const [hostInput, setHostInput] = useState(aegisHost);
  const [score,     setScore]     = useState(null);
  const [history,   setHistory]   = useState([]);
  const [kills,     setKills]     = useState([]);
  const [connected, setConnected] = useState(false);
  const [elapsed,   setElapsed]   = useState(0);
  const startRef = useRef(Date.now());

  useEffect(() => {
    let isMounted = true;
    const poll = async () => {
      try {
        const [s, h, k] = await Promise.all([
          fetch(`${aegisHost}/aegis/score`).then(r => r.json()),
          fetch(`${aegisHost}/aegis/history`).then(r => r.json()),
          fetch(`${aegisHost}/aegis/kills`).then(r => r.json()),
        ]);
        if (isMounted) {
          setScore(s); setConnected(true);
          const base = h.history?.[0]?.t || Date.now() / 1000;
          setHistory((h.history || []).map(p => ({ t: `${(p.t - base).toFixed(0)}s`, score: p.score })));
          setKills(k.kills || []);
        }
      } catch {
        if (isMounted) setConnected(false);
      }
    };
    poll();
    const t = setInterval(poll, 500);
    const e = setInterval(() => setElapsed(Math.floor((Date.now() - startRef.current) / 1000)), 1000);
    return () => { isMounted = false; clearInterval(t); clearInterval(e); };
  }, [aegisHost]);

  const saveHost = (newHost) => {
    const trimmed = (newHost || DEFAULT_AEGIS_API).trim().replace(/\/$/, "");
    setAegisHost(trimmed);
    localStorage.setItem("specter_aegis_host", trimmed);
    setEditingHost(false);
  };

  const total   = score?.total ?? 0;
  const status  = score?.status ?? "NORMAL";
  const sc      = STATUS_CONFIG[status] ?? STATUS_CONFIG.NORMAL;
  const elapsed_str = `${Math.floor(elapsed / 60).toString().padStart(2, "0")}:${(elapsed % 60).toString().padStart(2, "0")}`;

  return (
    <div style={{ padding: "32px 48px", maxWidth: 1280, margin: "0 auto", fontFamily: "'Outfit', 'Inter', sans-serif" }}>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: -0.5, color: T.t1, marginBottom: 4 }}>
            AEGIS — Ransomware Interceptor
          </h1>
          <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 2, textTransform: "uppercase", fontWeight: 600 }}>
            Behavioral Kill Switch · Live Entropy Analysis · Memory Forensics
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 11 }}>
          <div style={{ color: T.t3, letterSpacing: 0.5, fontWeight: 600 }}>
            Active Session: <span style={{ color: T.t1, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700 }}>{elapsed_str}</span>
          </div>

          {editingHost ? (
            <div style={{ display: "flex", alignItems: "center", gap: 6, background: T.surface, border: `1px solid ${T.borderMd}`, borderRadius: 8, padding: "3px 8px" }}>
              <input
                type="text"
                value={hostInput}
                onChange={e => setHostInput(e.target.value)}
                placeholder="http://192.168.x.x:8001"
                style={{ border: "none", outline: "none", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", width: 180, color: T.t1 }}
              />
              <button onClick={() => saveHost(hostInput)} style={{ background: T.blue, color: "#fff", border: "none", borderRadius: 4, padding: "2px 8px", cursor: "pointer", fontSize: 10, fontWeight: 700 }}>Save</button>
              <button onClick={() => setEditingHost(false)} style={{ background: "transparent", color: T.t3, border: "none", cursor: "pointer", fontSize: 10 }}>✕</button>
            </div>
          ) : (
            <div
              onClick={() => { setHostInput(aegisHost); setEditingHost(true); }}
              title="Click to change AEGIS agent host IP"
              style={{
                display: "flex", alignItems: "center", gap: 6, cursor: "pointer",
                background: T.surface, border: `1px solid ${T.borderMd}`,
                borderRadius: 99, padding: "4px 12px", fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: T.t2
              }}
            >
              <span>Host: {aegisHost.replace(/^https?:\/\//, "")}</span>
              <span style={{ fontSize: 9, color: T.blue }}>✏️</span>
            </div>
          )}

          <div style={{
            display: "flex", alignItems: "center", gap: 6,
            background: connected ? `${T.green}10` : `${T.red}10`,
            border: `1px solid ${connected ? T.green : T.red}25`,
            borderRadius: 99, padding: "5px 14px",
          }}>
            <div style={{
              width: 7, height: 7, borderRadius: "50%",
              background: connected ? T.green : T.red,
              animation: connected ? "pulse 2s infinite" : "none",
            }} />
            <span style={{ fontWeight: 750, letterSpacing: 0.5, color: connected ? T.green : T.red, fontSize: 10 }}>
              {connected ? "AEGIS ONLINE" : "AEGIS OFFLINE"}
            </span>
          </div>
        </div>
      </div>

      {/* Offline notice */}
      {!connected && (
        <div style={{
          background: `rgba(217,119,6,0.06)`, border: `1px solid rgba(217,119,6,0.18)`,
          borderLeft: `4px solid ${T.amber}`, borderRadius: 12,
          padding: "12px 18px", marginBottom: 20, fontSize: 12.5, color: T.amber,
          display: "flex", alignItems: "center", gap: 8, fontWeight: 600
        }}>
          ⚠️ AEGIS core API is offline. Deploy and initialize with:
          <code style={{
            marginLeft: 8, background: T.surface, padding: "3px 10px",
            borderRadius: 6, fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
            color: T.t1, border: `1px solid ${T.border}`
          }}>
            python aegis.py --demo
          </code>
        </div>
      )}

      {/* Main score section */}
      <div style={{
        border: `1px solid ${total >= 75 ? `${T.red}35` : total >= 40 ? `${T.amber}25` : T.border}`,
        borderRadius: 20, padding: 24, marginBottom: 20,
        boxShadow: "0 6px 24px rgba(12, 7, 64, 0.02)",
        background: total >= 75 ? `linear-gradient(135deg, ${T.surface}, rgba(211,47,47,0.04))`
          : total >= 40 ? `linear-gradient(135deg, ${T.surface}, rgba(217,119,6,0.03))` : T.surface,
        transition: "all 0.3s ease"
      }}>
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 32, alignItems: "center" }}>

          {/* Circular SVG Progress Ring */}
          <div style={{ position: "relative", width: 120, height: 120, flexShrink: 0 }}>
            <ScoreRing score={total} color={sc.color} size={120} />
            <div style={{
              position: "absolute", inset: 0,
              display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
            }}>
              <div style={{
                fontSize: 30, fontWeight: 900, letterSpacing: -1.5,
                color: sc.color, lineHeight: 1,
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                {total.toFixed(0)}
              </div>
              <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 0.5, marginTop: 2, fontWeight: 700 }}>RISK SCORE</div>
            </div>
          </div>

          {/* Middle details: status + sub-metrics */}
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
              <div style={{
                display: "inline-flex", alignItems: "center", gap: 6,
                background: `${sc.color}10`, border: `1px solid ${sc.color}20`,
                borderRadius: 99, padding: "5px 16px",
                fontSize: 11, fontWeight: 750, letterSpacing: 1, color: sc.color, textTransform: "uppercase",
              }}>
                <div style={{
                  width: 7, height: 7, borderRadius: "50%", background: sc.color,
                  animation: status !== "NORMAL" ? "pulse 1s infinite" : "none",
                }} />
                {sc.label}
              </div>
              {score?.files_per_sec !== undefined && (
                <div style={{ fontSize: 11, color: T.t2, fontWeight: 600 }}>
                  Active Write Velocity: <span style={{ color: T.t1, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700 }}>
                    {(score.files_per_sec || 0).toFixed(1)}
                  </span> files/s
                </div>
              )}
              {score?.vss_detected && (
                <div style={{
                  fontSize: 9.5, fontWeight: 700, padding: "3px 10px", borderRadius: 6,
                  background: `${T.purple}12`, color: T.purple, border: `1px solid ${T.purple}20`,
                  letterSpacing: 0.5, textTransform: "uppercase",
                }}>
                  VSS Deletion Detected
                </div>
              )}
            </div>

            {/* Sub-Signal Progress Bars */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
              {SIGNALS.map(sig => {
                const val = score?.[sig.key] ?? 0;
                const pct = Math.min(100, (val / sig.max) * 100);
                return (
                  <div key={sig.key}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                      <span style={{ fontSize: 9.5, color: T.t2, letterSpacing: 0.5, textTransform: "uppercase", fontWeight: 700 }}>{sig.label}</span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: val > sig.max * 0.6 ? sig.color : T.t1, fontFamily: "'JetBrains Mono', monospace" }}>
                        {val.toFixed(1)}
                      </span>
                    </div>
                    <div style={{ height: 5, background: T.raise, borderRadius: 3, overflow: "hidden" }}>
                      <div style={{
                        height: "100%", width: `${pct}%`,
                        background: sig.color, borderRadius: 3, transition: "width 0.3s ease",
                        boxShadow: pct > 60 ? `0 0 10px ${sig.color}66` : "none",
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right column: metrics boxes */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {[
              { l: "Host Kills",  v: kills.length,                          c: kills.length > 0 ? T.green : T.t3 },
              { l: "High Entropy",v: score?.high_entropy_count ?? 0,        c: T.red    },
              { l: "Renames",     v: score?.suspicious_renames ?? 0,        c: T.amber  },
              { l: "Total Writes",v: score?.total_writes ?? 0,              c: T.t1     },
            ].map(s => (
              <div key={s.l} style={{
                background: T.raise, borderRadius: 12, padding: "10px 14px", textAlign: "center",
                border: `1px solid ${T.border}`, minWidth: 90
              }}>
                <div style={{ fontSize: 20, fontWeight: 800, color: s.c, letterSpacing: -0.5, lineHeight: 1 }}>
                  {s.v}
                </div>
                <div style={{ fontSize: 8, color: T.t3, letterSpacing: 1, marginTop: 4, textTransform: "uppercase", fontWeight: 700 }}>
                  {s.l}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Live Timeline Chart Panel */}
      <div style={{
        background: T.surface, border: `1px solid ${T.border}`,
        borderRadius: 20, padding: 20, marginBottom: 20,
        boxShadow: "0 6px 24px rgba(12, 7, 64, 0.02)"
      }}>
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14,
        }}>
          <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, color: T.t1, textTransform: "uppercase" }}>
            Live Score Timeline
          </span>
          <span style={{ fontSize: 10, color: T.t3, fontWeight: 500 }}>Last 60 seconds · Kill threshold: 75</span>
        </div>
        {history.length > 1 ? (
          <ScoreChart history={history} />
        ) : (
          <div style={{ height: 100, display: "flex", alignItems: "center", justifyContent: "center", color: T.t3, fontSize: 12, fontWeight: 600 }}>
            Waiting for AEGIS telemetry metrics...
          </div>
        )}
      </div>

      {/* Kill Events Logs */}
      <div style={{
        background: T.surface, border: `1px solid ${T.border}`,
        borderRadius: 20, overflow: "hidden", boxShadow: "0 6px 24px rgba(12, 7, 64, 0.02)"
      }}>
        <div style={{
          padding: "14px 20px", borderBottom: `1px solid ${T.border}`,
          display: "flex", justifyContent: "space-between", alignItems: "center",
        }}>
          <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, color: T.t1, textTransform: "uppercase" }}>
            Kill Events History — {kills.length} neutralizations
          </span>
          {kills.length > 0 && (
            <span style={{ fontSize: 10.5, color: T.green, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
              {kills.length} Ransomware threat{kills.length !== 1 ? "s" : ""} blocked
            </span>
          )}
        </div>

        {kills.length === 0 ? (
          <div style={{ padding: 48, textAlign: "center" }}>
            <div style={{ fontSize: 24, color: T.t3, marginBottom: 10, opacity: 0.3 }}>🛡️</div>
            <div style={{ fontSize: 13, color: T.t3, marginBottom: 6, fontWeight: 600 }}>No ransomware attacks intercepted yet</div>
            {connected && (
              <div style={{ fontSize: 11.5, color: T.t2 }}>
                Simulate a file encryption threat: <code style={{
                  background: T.raise, padding: "3px 10px", borderRadius: 6,
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: T.blue,
                  border: `1px solid ${T.border}`, marginLeft: 6
                }}>python aegis.py --test</code>
              </div>
            )}
          </div>
        ) : (
          kills.map((k, i) => (
            <div key={i} style={{
              padding: "18px 20px", borderBottom: i === kills.length - 1 ? "none" : `1px solid ${T.border}`,
              background: i === 0 ? `rgba(211,47,47,0.03)` : "transparent",
              transition: "background 0.15s ease"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: T.red, marginBottom: 4, display: "flex", alignItems: "center", gap: 8 }}>
                    <span>⚠️</span> {k.family} ransomware neutralized
                  </div>
                  <div style={{ fontSize: 11, color: T.t3, fontWeight: 500 }}>
                    {new Date(k.timestamp).toLocaleTimeString()} · PID {k.pid} ({k.process_name})
                  </div>
                </div>
                <div style={{ display: "flex", gap: 18 }}>
                  {[
                    { l: "Response Time",v: `${k.latency_ms?.toFixed(0)}ms`, c: T.green },
                    { l: "Encrypted Files",v: k.files_encrypted,                 c: T.red   },
                    { l: "Restored Files", v: k.files_saved,                     c: T.green },
                    { l: "Decision Score",v: `${k.score?.toFixed(0)}/100`,       c: T.amber },
                  ].map(s => (
                    <div key={s.l} style={{ textAlign: "center" }}>
                      <div style={{ fontSize: 18, fontWeight: 900, color: s.c, letterSpacing: -0.5, lineHeight: 1 }}>
                        {s.v}
                      </div>
                      <div style={{ fontSize: 8, color: T.t3, letterSpacing: 1, marginTop: 4, textTransform: "uppercase", fontWeight: 700 }}>
                        {s.l}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              {k.triggers?.length > 0 && (
                <div style={{ marginTop: 12, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {k.triggers.map(t => (
                    <span key={t} style={{
                      fontSize: 9.5, fontWeight: 700, padding: "3px 9px", borderRadius: 6,
                      background: `${T.red}10`, color: T.red,
                      border: `1px solid ${T.red}20`, letterSpacing: 0.5, textTransform: "uppercase"
                    }}>{t}</span>
                  ))}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* How it works panel (shown when system is quiet) */}
      {total < 15 && kills.length === 0 && (
        <div style={{
          marginTop: 20, background: `rgba(26,115,232,0.03)`,
          border: `1px solid rgba(26,115,232,0.1)`, borderRadius: 16, padding: 20,
        }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 2, color: T.blue, marginBottom: 14, textTransform: "uppercase" }}>
            How AEGIS Shield Works
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14 }}>
            {[
              { t: "Shannon Entropy Analyzer", d: "Normal file writes measure 3.5–6.0 bits/byte. Fully encrypted high-entropy packets cluster strictly at 7.9–8.0. This mathematical delta is completely bypass-proof.", c: T.red },
              { t: "Write Velocity Monitor",  d: "Users read/write at 2–5 files/s. Ransomware algorithms encrypt at 50–500 files/s. AEGIS tracks these spikes inside a 2-second moving window.", c: T.amber },
              { t: "Automated Kill Switch",   d: "If the composite threat index hits the 75/100 threshold, AEGIS triggers an instant process freeze and saves memory states for analysis.", c: T.green },
            ].map(s => (
              <div key={s.t} style={{
                background: T.surface, borderTop: `3px solid ${s.c}`, borderRadius: 12, padding: "14px 16px",
                borderLeft: `1px solid ${T.border}`, borderRight: `1px solid ${T.border}`, borderBottom: `1px solid ${T.border}`,
                boxShadow: "0 4px 12px rgba(12, 7, 64, 0.01)"
              }}>
                <div style={{ fontSize: 11.5, fontWeight: 750, color: s.c, marginBottom: 6 }}>{s.t}</div>
                <div style={{ fontSize: 11, color: T.t2, lineHeight: 1.6 }}>{s.d}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

