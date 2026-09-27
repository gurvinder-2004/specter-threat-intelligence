import { useState, useEffect, useCallback } from "react";
import { api } from "../api";

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

const TYPE_COLOR  = { ip: T.red, domain: T.blue, sha256: T.purple, md5: T.purple, url: T.amber, email: T.green };
const SCORE_COLOR = s => s >= 90 ? T.red : s >= 70 ? T.amber : s >= 50 ? "#ffd700" : T.green;
const SEV_LABEL   = s => s >= 90 ? "CRITICAL" : s >= 70 ? "HIGH" : s >= 50 ? "MEDIUM" : "LOW";

function StatCard({ val, label, color, sub }) {
  return (
    <div style={{
      background: T.surface, border: `1px solid ${T.border}`,
      borderTop: `3px solid ${color}`, borderRadius: 16, padding: "18px 20px",
      position: "relative", overflow: "hidden",
      boxShadow: "0 4px 20px rgba(12, 7, 64, 0.02)",
      transition: "all 0.2s ease",
      cursor: "default"
    }}
    onMouseEnter={(e) => {
      e.currentTarget.style.transform = "translateY(-2px)";
      e.currentTarget.style.boxShadow = "0 8px 30px rgba(12, 7, 64, 0.06)";
    }}
    onMouseLeave={(e) => {
      e.currentTarget.style.transform = "translateY(0)";
      e.currentTarget.style.boxShadow = "0 4px 20px rgba(12, 7, 64, 0.02)";
    }}
    >
      <div style={{ fontSize: 30, fontWeight: 900, letterSpacing: -1.2, color, lineHeight: 1, marginBottom: 6 }}>
        {typeof val === "number" ? val.toLocaleString() : val ?? "—"}
      </div>
      <div style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: 1.5, color: T.t3, textTransform: "uppercase" }}>
        {label}
      </div>
      {sub && <div style={{ fontSize: 10.5, color: T.t2, marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function TypeBadge({ type }) {
  const c = TYPE_COLOR[type] || T.t2;
  return (
    <span style={{
      fontSize: 8.5, fontWeight: 700, letterSpacing: 0.5, padding: "3px 8px",
      borderRadius: 6, background: `${c}10`, color: c,
      border: `1px solid ${c}25`, minWidth: 54, textAlign: "center",
      textTransform: "uppercase", display: "inline-block",
    }}>
      {type}
    </span>
  );
}

function ScoreBar({ score, width = 56 }) {
  const c = SCORE_COLOR(score);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
      <div style={{ width, height: 4, background: T.raise, borderRadius: 2, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${score}%`, background: c, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color: c, minWidth: 26, fontFamily: "'JetBrains Mono', monospace" }}>
        {score.toFixed(0)}
      </span>
    </div>
  );
}

function SevBadge({ score }) {
  const c = SCORE_COLOR(score);
  return (
    <span style={{
      fontSize: 8, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
      background: `${c}15`, color: c, border: `1px solid ${c}25`,
      letterSpacing: 0.5, textTransform: "uppercase",
    }}>
      {SEV_LABEL(score)}
    </span>
  );
}

export default function Dashboard({ stats, onRefresh }) {
  const [iocs,    setIocs]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter,  setFilter]  = useState("all");
  const [selected,setSelected]= useState(null);
  const [xai,     setXai]     = useState("");
  const [xaiLoad, setXaiLoad] = useState(false);
  const [vtData,  setVtData]  = useState(null);
  const [vtLoad,  setVtLoad]  = useState(false);

  const fetchIocs = useCallback((type) => {
    setLoading(true);
    const url = type === "all" ? "/api/iocs?limit=500" : `/api/iocs?limit=500&ioc_type=${type}`;
    api.get(url).then(d => setIocs(d.iocs || [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchIocs(filter); }, [filter, fetchIocs]);

  const explain = async (ioc) => {
    setSelected(ioc); setXai(""); setVtData(null); setXaiLoad(true);
    try {
      const d = await api.get(`/api/llm/explain/${encodeURIComponent(ioc.value)}`);
      setXai(d.explanation || "");
    } catch { setXai("LLM unavailable — check GROQ_API_KEY in .env"); }
    finally { setXaiLoad(false); }
  };

  const enrichVT = async (ioc) => {
    setVtLoad(true); setVtData(null);
    try {
      const d = await api.get(`/api/enrich/virustotal/${encodeURIComponent(ioc.value)}`);
      setVtData(d);
    } catch { setVtData({ error: "VT request failed" }); }
    finally { setVtLoad(false); }
  };

  const allTypes = stats?.type_breakdown ? Object.keys(stats.type_breakdown) : [];
  const FILTERS  = ["all", ...allTypes];

  return (
    <div style={{ padding: "32px 48px", maxWidth: 1280, margin: "0 auto", fontFamily: "'Outfit', 'Inter', sans-serif" }}>

      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: -0.5, color: T.t1, marginBottom: 4 }}>
            Threat Dashboard
          </h1>
          <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 2, textTransform: "uppercase", fontWeight: 600 }}>
            Real-Time Indicator Monitoring
          </div>
        </div>
        <button onClick={() => { onRefresh?.(); fetchIocs(filter); }} 
          style={{
            background: T.surface, border: `1px solid ${T.border}`, borderRadius: 10,
            color: T.t2, padding: "8px 18px", cursor: "pointer",
            fontSize: 10.5, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase",
            boxShadow: "0 2px 8px rgba(12, 7, 64, 0.02)", transition: "all 0.15s ease"
          }}
          onMouseEnter={(e) => { e.target.style.borderColor = T.borderMd; e.target.style.background = T.raise; }}
          onMouseLeave={(e) => { e.target.style.borderColor = T.border; e.target.style.background = T.surface; }}
        >
          Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        <StatCard val={stats?.total_iocs}    label="Total IOCs"  color={T.blue}   sub="All ingested indicators" />
        <StatCard val={stats?.active_iocs}   label="Active"      color={T.green}  sub="Currently tracked" />
        <StatCard val={stats?.critical_iocs} label="Critical"    color={T.red}    sub="Confidence >= 80" />
        <StatCard val={stats?.ttps}          label="TTPs Mapped" color={T.purple} sub="ATT&CK techniques" />
      </div>

      {/* IOC breakdown strip */}
      {stats?.type_breakdown && Object.keys(stats.type_breakdown).length > 0 && (
        <div style={{
          background: T.surface, border: `1px solid ${T.border}`,
          borderRadius: 14, padding: "14px 20px", marginBottom: 20,
          display: "flex", gap: 28, alignItems: "center", flexWrap: "wrap",
          boxShadow: "0 4px 16px rgba(12, 7, 64, 0.01)"
        }}>
          <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: 2, color: T.t3, textTransform: "uppercase" }}>
            Breakdown
          </span>
          {Object.entries(stats.type_breakdown).map(([t, c]) => (
            <div key={t} style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 800, color: TYPE_COLOR[t] || T.t2 }}>
                {c.toLocaleString()}
              </span>
              <span style={{ fontSize: 10.5, color: T.t3, textTransform: "uppercase", fontWeight: 600 }}>{t}</span>
            </div>
          ))}
        </div>
      )}

      {/* Critical banner */}
      {(stats?.critical_iocs || 0) > 0 && (
        <div style={{
          background: `linear-gradient(90deg, rgba(211,47,47,0.06), rgba(211,47,47,0.01))`,
          border: `1px solid rgba(211,47,47,0.18)`,
          borderLeft: `4px solid ${T.red}`,
          borderRadius: 12, padding: "12px 18px", marginBottom: 20,
          display: "flex", alignItems: "center", gap: 12,
        }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: T.red, animation: "pulse 1.5s infinite", flexShrink: 0 }} />
          <span style={{ fontSize: 13, fontWeight: 700, color: T.red }}>
            {stats.critical_iocs.toLocaleString()} critical indicators detected
          </span>
          <span style={{ fontSize: 11, color: T.t2, marginLeft: 4 }}>
            {"Confidence >= 80 — Immediate response required"}
          </span>
        </div>
      )}

      {/* Main grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 20 }}>

        {/* IOC table */}
        <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 20, overflow: "hidden", boxShadow: "0 6px 24px rgba(12, 7, 64, 0.02)" }}>
          {/* Table header */}
          <div style={{
            padding: "16px 20px", borderBottom: `1px solid ${T.border}`,
            display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12,
          }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, color: T.t1, textTransform: "uppercase" }}>
              Active Indicators ({iocs.length})
            </span>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {FILTERS.map(f => (
                <button key={f} onClick={() => setFilter(f)} 
                  style={{
                    padding: "4px 11px", borderRadius: 8,
                    background: filter === f ? T.t1 : "transparent",
                    border: `1px solid ${filter === f ? T.t1 : T.border}`,
                    color: filter === f ? "#ffffff" : T.t2,
                    cursor: "pointer", fontSize: 9.5, fontFamily: "inherit",
                    letterSpacing: 0.5, textTransform: "uppercase", fontWeight: 700,
                    transition: "all 0.15s ease",
                  }}
                  onMouseEnter={(e) => {
                    if (filter !== f) {
                      e.target.style.background = T.hover;
                      e.target.style.color = T.t1;
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (filter !== f) {
                      e.target.style.background = "transparent";
                      e.target.style.color = T.t2;
                    }
                  }}
                >
                  {f}
                  {f !== "all" && stats?.type_breakdown?.[f] !== undefined && (
                    <span style={{ marginLeft: 4, fontSize: 8.5, opacity: filter === f ? 0.9 : 0.6 }}>
                      ({stats.type_breakdown[f]})
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Table body */}
          {loading ? (
            <div style={{ padding: 60, textAlign: "center", color: T.t3, fontSize: 13, fontWeight: 600 }}>
              Loading indicators...
            </div>
          ) : iocs.length === 0 ? (
            <div style={{ padding: 60, textAlign: "center" }}>
              <div style={{ fontSize: 32, color: T.t3, marginBottom: 12, opacity: 0.3 }}>◈</div>
              <div style={{ fontSize: 13, color: T.t3, letterSpacing: 0.5, fontWeight: 600 }}>
                No indicators — use Ingest page to import threat telemetry
              </div>
            </div>
          ) : (
            <div style={{ maxHeight: 540, overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead style={{ position: "sticky", top: 0, background: T.surface, zIndex: 1 }}>
                  <tr>
                    {["Type", "Indicator", "Score", "Severity", "Source", ""].map(h => (
                      <th key={h} style={{
                        padding: "10px 16px", textAlign: "left",
                        fontSize: 8.5, fontWeight: 700, letterSpacing: 1.5,
                        color: T.t3, borderBottom: `1px solid ${T.border}`,
                        textTransform: "uppercase",
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((ioc, i) => {
                    const sc = ioc.confidence_score ?? 0;
                    const active = selected?.value === ioc.value;
                    return (
                      <tr key={i} style={{
                        borderBottom: `1px solid ${T.border}`,
                        background: active ? `rgba(26,115,232,0.06)` : "transparent",
                        transition: "background 0.15s ease",
                      }}
                      onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = T.raise; }}
                      onMouseLeave={(e) => { if (!active) e.currentTarget.style.background = "transparent"; }}
                      >
                        <td style={{ padding: "10px 16px" }}>
                          <TypeBadge type={ioc.ioc_type} />
                        </td>
                        <td style={{ padding: "10px 16px", maxWidth: 220 }}>
                          <span style={{
                            fontSize: 12, fontFamily: "'JetBrains Mono', monospace",
                            color: T.t1, overflow: "hidden", textOverflow: "ellipsis",
                            whiteSpace: "nowrap", display: "block", fontWeight: 500,
                          }} title={ioc.value}>
                            {ioc.value?.length > 32 ? ioc.value.slice(0, 32) + "…" : ioc.value}
                          </span>
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          <ScoreBar score={sc} />
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          <SevBadge score={sc} />
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          <span style={{ fontSize: 10, color: T.t3, maxWidth: 100, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>
                            {(ioc.source || "").replace(/^(pdf:|rss:|otx:)/, "").slice(0, 22)}
                          </span>
                        </td>
                        <td style={{ padding: "10px 16px" }}>
                          <button onClick={() => explain(ioc)} 
                            style={{
                              background: T.surface, border: `1px solid ${T.border}`,
                              borderRadius: 6, color: T.t2, padding: "4px 10px",
                              cursor: "pointer", fontSize: 9.5, fontFamily: "inherit",
                              letterSpacing: 0.5, textTransform: "uppercase", fontWeight: 700,
                              boxShadow: "0 2px 6px rgba(12, 7, 64, 0.01)", transition: "all 0.15sEase"
                            }}
                            onMouseEnter={(e) => { e.target.style.borderColor = T.t2; e.target.style.background = T.raise; }}
                            onMouseLeave={(e) => { e.target.style.borderColor = T.border; e.target.style.background = T.surface; }}
                          >
                            Explain
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right panel: XAI + VT enrichment */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

          {/* XAI Panel */}
          <div style={{
            background: T.surface, border: `1px solid ${T.border}`,
            borderRadius: 20, overflow: "hidden", boxShadow: "0 6px 24px rgba(12, 7, 64, 0.02)"
          }}>
            <div style={{ padding: "14px 20px", borderBottom: `1px solid ${T.border}` }}>
              <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, color: T.t1, textTransform: "uppercase" }}>
                AI Analysis & Enrichment
              </span>
            </div>

            {!selected ? (
              <div style={{ padding: "36px 20px", textAlign: "center" }}>
                <div style={{ fontSize: 28, color: T.t3, marginBottom: 8, opacity: 0.3 }}>◉</div>
                <div style={{ fontSize: 12, color: T.t3, lineHeight: 1.6, fontWeight: 500 }}>
                  Select an indicator<br />to generate AI analysis
                </div>
              </div>
            ) : (
              <div style={{ padding: 20 }}>
                <div style={{
                  background: T.raise, border: `1px solid ${T.border}`, borderRadius: 10,
                  padding: "10px 12px", marginBottom: 16,
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 10.5, color: T.blue,
                  wordBreak: "break-all", fontWeight: 600,
                }}>
                  {selected.value}
                </div>

                {/* Score */}
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <span style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, textTransform: "uppercase", fontWeight: 700 }}>
                      Confidence
                    </span>
                    <span style={{
                      fontSize: 22, fontWeight: 900, letterSpacing: -0.5,
                      color: SCORE_COLOR(selected.confidence_score ?? 0),
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      {(selected.confidence_score ?? 0).toFixed(0)}
                    </span>
                  </div>
                  <div style={{ height: 6, background: T.raise, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{
                      height: "100%", width: `${selected.confidence_score ?? 0}%`,
                      background: `linear-gradient(90deg, ${T.amber}, ${SCORE_COLOR(selected.confidence_score ?? 0)})`,
                      borderRadius: 3, transition: "width 0.5s",
                    }} />
                  </div>
                  <div style={{ marginTop: 6, display: "flex", justifyContent: "flex-end" }}>
                    <SevBadge score={selected.confidence_score ?? 0} />
                  </div>
                </div>

                {/* AI explanation */}
                <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 6, fontWeight: 700 }}>
                  AI Analysis
                </div>
                <div style={{
                  background: T.raise, border: `1px solid ${T.border}`, borderRadius: 10,
                  padding: "12px 14px", fontSize: 11.5, color: T.t2, lineHeight: 1.7, minHeight: 80,
                  whiteSpace: "pre-wrap",
                }}>
                  {xaiLoad ? (
                    <span style={{ color: T.t3, fontWeight: 500 }}>Analyzing telemetry...</span>
                  ) : xai || (
                    <span style={{ color: T.t3 }}>Click Explain on any row to generate analysis</span>
                  )}
                </div>

                {/* TTPs */}
                {(selected.ttp_tags || []).length > 0 && (
                  <div style={{ marginTop: 14 }}>
                    <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 6, fontWeight: 700 }}>
                      ATT&CK Techniques
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {selected.ttp_tags.map(t => (
                        <span key={t} style={{
                          fontSize: 9.5, fontWeight: 700, padding: "3px 8px", borderRadius: 6,
                          background: `${T.purple}10`, color: T.purple,
                          border: `1px solid ${T.purple}20`,
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Context */}
                {selected.raw_context && (
                  <div style={{ marginTop: 14 }}>
                    <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 4, fontWeight: 700 }}>
                      Context
                    </div>
                    <div style={{ fontSize: 10.5, color: T.t2, lineHeight: 1.6, fontStyle: "italic", background: T.raise, padding: 10, borderRadius: 8, border: `1px solid ${T.border}` }}>
                      "{selected.raw_context.slice(0, 180)}
                      {selected.raw_context.length > 180 ? "…" : ""}"
                    </div>
                  </div>
                )}

                {/* VT enrich button */}
                <button onClick={() => enrichVT(selected)} disabled={vtLoad} 
                  style={{
                    marginTop: 16, width: "100%",
                    background: T.t1, border: "none",
                    borderRadius: 99, color: "#ffffff", padding: "10px 0",
                    cursor: vtLoad ? "default" : "pointer", fontSize: 11,
                    fontWeight: 700, letterSpacing: 1, textTransform: "uppercase",
                    boxShadow: "0 4px 12px rgba(12, 7, 64, 0.1)",
                    transition: "all 0.2s ease"
                  }}
                  onMouseEnter={(e) => { if (!vtLoad) e.target.style.background = "#1c1273"; }}
                  onMouseLeave={(e) => { if (!vtLoad) e.target.style.background = T.t1; }}
                >
                  {vtLoad ? "Loading VirusTotal..." : "VirusTotal Enrich"}
                </button>

                {/* VT result */}
                {vtData && !vtData.error && vtData.found && (
                  <div style={{
                    marginTop: 14, background: T.raise, border: `1px solid ${T.border}`,
                    borderRadius: 10, padding: "12px 14px",
                  }}>
                    <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, textTransform: "uppercase", marginBottom: 8, fontWeight: 700 }}>
                      VirusTotal Results
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                      {[
                        { l: "Malicious", v: vtData.malicious ?? 0, c: T.red },
                        { l: "Total Engines", v: vtData.total_engines ?? 0, c: T.t2 },
                      ].map(s => (
                        <div key={s.l} style={{ textAlign: "center", background: T.surface, borderRadius: 8, padding: "8px", border: `1px solid ${T.border}` }}>
                          <div style={{ fontSize: 18, fontWeight: 900, color: s.c }}>{s.v}</div>
                          <div style={{ fontSize: 8.5, color: T.t3, letterSpacing: 0.5, fontWeight: 700, textTransform: "uppercase", marginTop: 2 }}>{s.l}</div>
                        </div>
                      ))}
                    </div>
                    {vtData.flagging_vendors?.length > 0 && (
                      <div style={{ marginTop: 10, fontSize: 10, color: T.amber, fontWeight: 600 }}>
                        Flagged by: {vtData.flagging_vendors.slice(0, 3).join(", ")}
                      </div>
                    )}
                  </div>
                )}
                {vtData?.error && (
                  <div style={{ marginTop: 10, fontSize: 10.5, color: T.amber, fontWeight: 600 }}>{vtData.error}</div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

