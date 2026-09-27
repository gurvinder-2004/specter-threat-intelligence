import { useState } from "react";
import { api, apiFetch } from "../api";

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

const TACTIC_COLOR = {
  "Initial Access": T.red, "Execution": T.orange, "Persistence": T.amber,
  "Privilege Escalation": T.purple, "Defense Evasion": T.blue,
  "Credential Access": "#ff5722", "Discovery": T.green,
  "Lateral Movement": T.orange, "Collection": T.blue,
  "Command and Control": T.red, "Exfiltration": T.orange, "Impact": "#e91e63",
};

const TYPE_COLOR = { ip: T.red, domain: T.blue, sha256: T.purple, md5: T.purple, url: T.amber };

function Tab({ id, label, icon, active, onClick }) {
  return (
    <button onClick={() => onClick(id)} style={{
      padding: "8px 18px", borderRadius: 8,
      background: active ? T.t1 : "transparent",
      border: "none",
      color: active ? "#ffffff" : T.t2,
      cursor: "pointer", fontSize: 10.5, fontFamily: "inherit",
      letterSpacing: 1, fontWeight: 700, textTransform: "uppercase",
      display: "flex", alignItems: "center", gap: 8, transition: "all 0.2s ease",
    }}>
      <span style={{ fontSize: 14 }}>{icon}</span>{label}
    </button>
  );
}

function PrimaryBtn({ children, onClick, loading, disabled }) {
  return (
    <button onClick={onClick} disabled={loading || disabled} style={{
      background: disabled || loading ? T.raise : T.t1,
      border: `1px solid ${disabled || loading ? T.border : T.t1}`,
      borderRadius: 99, color: disabled || loading ? T.t3 : "#fff",
      padding: "10px 22px", cursor: disabled || loading ? "not-allowed" : "pointer",
      fontSize: 10.5, fontFamily: "inherit", letterSpacing: 1,
      fontWeight: 700, textTransform: "uppercase", transition: "all 0.2s ease",
      boxShadow: disabled || loading ? "none" : "0 4px 12px rgba(12, 7, 64, 0.12)"
    }}
    onMouseEnter={(e) => { if (!disabled && !loading) e.target.style.background = "#1c1273"; }}
    onMouseLeave={(e) => { if (!disabled && !loading) e.target.style.background = T.t1; }}
    >
      {loading ? "Processing..." : children}
    </button>
  );
}

function FeedCard({ title, badge, badgeColor, desc, note, onFetch, loading }) {
  return (
    <div style={{
      background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16,
      padding: 20, display: "flex", alignItems: "center", gap: 20,
      boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)",
      transition: "all 0.2s ease"
    }}
    onMouseEnter={(e) => e.currentTarget.style.borderColor = T.borderMd}
    onMouseLeave={(e) => e.currentTarget.style.borderColor = T.border}
    >
      <div style={{ flex: 1 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <span style={{ fontSize: 14, fontWeight: 800, color: T.t1 }}>{title}</span>
          <span style={{
            fontSize: 8.5, fontWeight: 700, padding: "2px 8px", borderRadius: 6,
            background: `${badgeColor}10`, color: badgeColor,
            border: `1px solid ${badgeColor}20`, letterSpacing: 0.5, textTransform: "uppercase",
          }}>{badge}</span>
        </div>
        <div style={{ fontSize: 11.5, color: T.t2, lineHeight: 1.7, marginBottom: 4 }}>{desc}</div>
        <div style={{ fontSize: 10, color: T.t3, fontWeight: 500 }}>{note}</div>
      </div>
      <PrimaryBtn onClick={onFetch} loading={loading}>Pull Now</PrimaryBtn>
    </div>
  );
}

function IngestResult({ result }) {
  const iocs = result.iocs_extracted ?? result.total_iocs ?? 0;
  const ttps = result.ttps_detected ?? 0;
  const crit = result.critical_alerts_fired ?? 0;

  return (
    <div style={{
      marginTop: 24, background: T.surface,
      border: `1px solid rgba(27,135,63,0.18)`,
      borderLeft: `4px solid ${T.green}`, borderRadius: 16, padding: 24,
      boxShadow: "0 6px 20px rgba(12, 7, 64, 0.02)"
    }}>
      <div style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: 2, color: T.green, marginBottom: 16, textTransform: "uppercase" }}>
        Ingestion Complete
      </div>

      {/* AI summary */}
      {result.ai_summary && !result.ai_summary.startsWith("[LLM") && (
        <div style={{
          background: `rgba(26,115,232,0.03)`, border: `1px solid rgba(26,115,232,0.1)`,
          borderLeft: `3px solid ${T.blue}`, borderRadius: 10,
          padding: "14px 16px", marginBottom: 20, fontSize: 12.5,
          color: T.t2, lineHeight: 1.8,
        }}>
          <div style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 1.5, color: T.blue, marginBottom: 6, textTransform: "uppercase" }}>
            AI Threat Summary
          </div>
          {result.ai_summary}
        </div>
      )}

      {/* Numbers */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 20 }}>
        {[
          { v: iocs, l: "IOCs Extracted",  c: T.green  },
          { v: ttps, l: "TTPs Detected",   c: T.purple },
          { v: crit, l: "Critical Alerts", c: T.red    },
        ].map(s => (
          <div key={s.l} style={{
            background: T.raise, borderRadius: 12, padding: "14px 16px", border: `1px solid ${T.border}`
          }}>
            <div style={{ fontSize: 28, fontWeight: 900, letterSpacing: -1.2, color: s.c, lineHeight: 1, marginBottom: 4 }}>
              {s.v}
            </div>
            <div style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 1, color: T.t3, textTransform: "uppercase" }}>
              {s.l}
            </div>
          </div>
        ))}
      </div>

      {/* IOC type breakdown */}
      {result.ioc_types && Object.keys(result.ioc_types).length > 0 && (
        <div style={{ marginBottom: 18 }}>
          <div style={{ fontSize: 9, color: T.t3, letterSpacing: 1.5, marginBottom: 8, textTransform: "uppercase", fontWeight: 700 }}>
            IOC Breakdown
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(result.ioc_types).map(([t, c]) => (
              <div key={t} style={{
                padding: "5px 14px", borderRadius: 8,
                background: `${TYPE_COLOR[t] || T.blue}10`,
                border: `1px solid ${TYPE_COLOR[t] || T.blue}20`,
              }}>
                <span style={{ fontSize: 13, fontWeight: 800, color: TYPE_COLOR[t] || T.blue }}>{c}</span>
                <span style={{ fontSize: 10, color: T.t3, marginLeft: 6, textTransform: "uppercase", fontWeight: 600 }}>{t}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TTP tags */}
      {result.ttps?.length > 0 && (
        <div>
          <div style={{ fontSize: 9, color: T.t3, letterSpacing: 1.5, marginBottom: 8, textTransform: "uppercase", fontWeight: 700 }}>
            MITRE ATT&CK Techniques Detected
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {result.ttps.map(t => {
              const tc = TACTIC_COLOR[t.tactic] || T.purple;
              return (
                <div key={t.id} title={`${t.id} — ${t.name}\nTactic: ${t.tactic}`}
                  style={{
                    background: `${tc}10`, border: `1px solid ${tc}20`,
                    padding: "4px 12px", borderRadius: 8, cursor: "default",
                  }}>
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: tc }}>{t.id}</span>
                  <span style={{ fontSize: 9.5, color: T.t2, marginLeft: 6, fontWeight: 500 }}>{t.name}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Ingest({ onIngested }) {
  const [tab,      setTab]      = useState("pdf");
  const [result,   setResult]   = useState(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [file,     setFile]     = useState(null);
  const [text,     setText]     = useState("");
  const [srcLabel, setSrcLabel] = useState("manual_paste");
  const [dragOver, setDragOver] = useState(false);

  const run = async (fn) => {
    setLoading(true); setError(""); setResult(null);
    try { setResult(await fn()); onIngested?.(); }
    catch (e) { setError(e.message || "Request failed"); }
    finally { setLoading(false); }
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f?.name.endsWith(".pdf")) setFile(f);
  };

  return (
    <div style={{ padding: "32px 48px", maxWidth: 900, margin: "0 auto", fontFamily: "'Outfit', 'Inter', sans-serif" }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: -0.5, color: T.t1, marginBottom: 4 }}>
          Ingest Intelligence
        </h1>
        <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 2, textTransform: "uppercase", fontWeight: 600 }}>
          Upload PDF Reports · Paste Raw Text · Pull Live Feeds
        </div>
      </div>

      {/* Tab Selectors */}
      <div style={{
        display: "flex", gap: 4, marginBottom: 24,
        background: "rgba(255, 255, 255, 0.8)", border: `1px solid ${T.border}`,
        borderRadius: 12, padding: 4, width: "fit-content",
        boxShadow: "0 2px 10px rgba(12,7,64,0.01)"
      }}>
        <Tab id="pdf"  label="PDF Report" icon="◧" active={tab==="pdf"}  onClick={setTab} />
        <Tab id="text" label="Raw Text"   icon="≡"  active={tab==="text"} onClick={setTab} />
        <Tab id="api"  label="Live Feeds" icon="⬡"  active={tab==="api"}  onClick={setTab} />
      </div>

      <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 20, padding: 24, boxShadow: "0 6px 24px rgba(12, 7, 64, 0.02)" }}>

        {/* PDF Ingestion Area */}
        {tab === "pdf" && (
          <div>
            <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, marginBottom: 16, textTransform: "uppercase", fontWeight: 700 }}>
              Supported: Mandiant · CrowdStrike · CISA Advisories · Threat PDFs
            </div>
            <div
              onDrop={handleDrop}
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              style={{
                border: `2px dashed ${dragOver ? T.t1 : file ? T.green : T.borderMd}`,
                borderRadius: 14, padding: "48px 24px", textAlign: "center",
                marginBottom: 20, background: dragOver ? T.raise : "transparent",
                transition: "all 0.2s ease",
              }}>
              <input type="file" accept=".pdf" id="pdf-in"
                onChange={e => setFile(e.target.files[0])} style={{ display: "none" }} />
              <label htmlFor="pdf-in" style={{ cursor: "pointer" }}>
                {file ? (
                  <>
                    <div style={{ fontSize: 36, marginBottom: 10, color: T.green }}>📄</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: T.green }}>{file.name}</div>
                    <div style={{ fontSize: 10.5, color: T.t3, marginTop: 6, fontWeight: 500 }}>
                      {(file.size / 1024).toFixed(0)} KB · Click to change file
                    </div>
                  </>
                ) : (
                  <>
                    <div style={{ fontSize: 36, marginBottom: 10, opacity: 0.35 }}>📄</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: T.t2 }}>Drop intelligence PDF here or click to select</div>
                    <div style={{ fontSize: 10.5, color: T.t3, marginTop: 6, fontWeight: 500 }}>Threat advisories, briefings, and incident files</div>
                  </>
                )}
              </label>
            </div>
            <PrimaryBtn loading={loading} disabled={!file}
              onClick={() => run(async () => {
                const f = new FormData();
                f.append("file", file);
                return apiFetch("/api/ingest/pdf", { method: "POST", body: f });
              })}>
              Extract IOCs from PDF
            </PrimaryBtn>
          </div>
        )}

        {/* Raw Text Input */}
        {tab === "text" && (
          <div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, marginBottom: 8, textTransform: "uppercase", fontWeight: 700 }}>
                Source Label / Reference Name
              </div>
              <input value={srcLabel} onChange={e => setSrcLabel(e.target.value)}
                placeholder="e.g. pastebin · threatpost · blackhat_forum"
                style={{
                  background: T.raise, border: `1px solid ${T.border}`, borderRadius: 10,
                  padding: "10px 14px", color: T.t1, fontSize: 13,
                  fontFamily: "inherit", width: "100%", outline: "none",
                  fontWeight: 500, transition: "border-color 0.2s"
                }}
                onFocus={(e)=>e.target.style.borderColor = T.t3}
                onBlur={(e)=>e.target.style.borderColor = T.border}
              />
            </div>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 1.5, marginBottom: 8, textTransform: "uppercase", fontWeight: 700 }}>
                Raw Threat Report Context
              </div>
              <textarea value={text} onChange={e => setText(e.target.value)} rows={9}
                placeholder={"Paste blog posts, raw cyber analysis dumps, or raw security text here...\n\nSPECTER engine will:\n· Parse IPs, domains, cryptographic hashes, and URLs\n· Map MITRE ATT&CK techniques with local context\n· Evaluate confidence and severity indexes\n· Automatically drop whitelist domains (github, microsoft, apple, google...)"}
                style={{
                  background: T.raise, border: `1px solid ${T.border}`, borderRadius: 10,
                  padding: "12px 14px", color: T.t1, fontSize: 12,
                  fontFamily: "'JetBrains Mono', monospace", width: "100%",
                  outline: "none", resize: "vertical", lineHeight: 1.6,
                  transition: "border-color 0.2s"
                }}
                onFocus={(e)=>e.target.style.borderColor = T.t3}
                onBlur={(e)=>e.target.style.borderColor = T.border}
              />
            </div>
            <PrimaryBtn loading={loading} disabled={!text.trim()}
              onClick={() => run(() => api.post("/api/ingest/text", { text, source_label: srcLabel }))}>
              Extract IOCs from Text
            </PrimaryBtn>
          </div>
        )}

        {/* Live Feeds Tab */}
        {tab === "api" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{
              background: `rgba(26,115,232,0.03)`, border: `1px solid rgba(26,115,232,0.1)`,
              borderRadius: 10, padding: "14px 16px", fontSize: 12, color: T.t2, lineHeight: 1.8,
              fontWeight: 500
            }}>
              <div style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 1.5, color: T.blue, marginBottom: 6, textTransform: "uppercase" }}>
                What are Live Threat Feeds?
              </div>
              Live feeds query global telemetry brokers to fetch active indicators.
              OTX feeds harvest crowdsourced IOC records validated by global security cells. RSS feeds scrape modern news sites and extract IOC sets instantly.
            </div>

            <FeedCard
              title="AlienVault OTX" badge="Structured Graph" badgeColor={T.blue}
              desc="Pull verified indicators of compromise from AlienVault Open Threat Exchange. High validity indicators mapped directly into the database."
              note="Requires OTX_API_KEY in server environment settings (.env file)"
              loading={loading}
              onFetch={() => run(() => api.post("/api/ingest/otx", {}))}
            />
            <FeedCard
              title="Global Security RSS Feeds" badge="Heuristic Scraping" badgeColor={T.green}
              desc="Parse current articles from BleepingComputer, Threatpost, Krebs, and SANS ISC. Raw texts are scraped and automatically cataloged."
              note="No authentication keys required · Scoring engine filters safe entities"
              loading={loading}
              onFetch={() => run(() => api.post("/api/ingest/rss", {}))}
            />
          </div>
        )}
      </div>

      {/* Error Output */}
      {error && (
        <div style={{
          marginTop: 20, background: `rgba(211,47,47,0.06)`,
          border: `1px solid rgba(211,47,47,0.18)`, borderLeft: `4px solid ${T.red}`,
          borderRadius: 12, padding: "14px 18px",
        }}>
          <div style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: 2, color: T.red, marginBottom: 6, textTransform: "uppercase" }}>
            Ingestion Error
          </div>
          <div style={{ fontSize: 12, color: T.red, fontWeight: 600 }}>{error}</div>
        </div>
      )}

      {result && <IngestResult result={result} />}
    </div>
  );
}

