import { useState, useEffect } from "react";
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

const TABS = [
  { id:"briefs",   label:"Briefs"      },
  { id:"enrich",   label:"Enrichment"  },
  { id:"hunt",     label:"Hunt Queries"},
  { id:"clusters", label:"Clusters"    },
  { id:"export",   label:"Export"      },
];

function Btn({ children, onClick, loading, color = T.t1, disabled }) {
  const isAltColor = color === T.raise;
  return (
    <button onClick={onClick} disabled={loading || disabled} 
      style={{
        background: disabled || loading ? T.raise : color,
        border: isAltColor ? `1px solid ${T.borderMd}` : "none",
        borderRadius: 99, 
        color: disabled || loading ? T.t3 : isAltColor ? T.t1 : "#fff",
        padding: "8px 20px", 
        cursor: disabled || loading ? "not-allowed" : "pointer",
        fontSize: 11, fontFamily: "inherit", letterSpacing: 0.5,
        fontWeight: 700, textTransform: "uppercase", whiteSpace: "nowrap",
        boxShadow: disabled || loading || isAltColor ? "none" : "0 4px 12px rgba(12, 7, 64, 0.12)",
        transition: "all 0.2s ease"
      }}
      onMouseEnter={(e) => {
        if (!disabled && !loading && !isAltColor) {
          e.target.style.background = "#1c1273";
        } else if (isAltColor) {
          e.target.style.background = T.hover;
        }
      }}
      onMouseLeave={(e) => {
        if (!disabled && !loading && !isAltColor) {
          e.target.style.background = color;
        } else if (isAltColor) {
          e.target.style.background = T.raise;
        }
      }}
    >
      {loading ? "Generating..." : children}
    </button>
  );
}

function Section({ title, badge, badgeColor, desc, action, children }) {
  return (
    <div style={{
      background: T.surface, border: `1px solid ${T.border}`,
      borderRadius: 16, padding: 22, marginBottom: 16,
      boxShadow: "0 4px 20px rgba(12, 7, 64, 0.02)"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap", marginBottom: children ? 16 : 0 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
            <span style={{ fontSize: 14, fontWeight: 800, color: T.t1 }}>{title}</span>
            {badge && (
              <span style={{
                fontSize: 8.5, fontWeight: 700, padding: "2px 8px", borderRadius: 6,
                background: `${badgeColor}10`, color: badgeColor,
                border: `1px solid ${badgeColor}20`, letterSpacing: 0.5, textTransform: "uppercase",
              }}>{badge}</span>
            )}
          </div>
          <div style={{ fontSize: 11.5, color: T.t2, lineHeight: 1.6 }}>{desc}</div>
        </div>
        {action && <div style={{ flexShrink: 0 }}>{action}</div>}
      </div>
      {children}
    </div>
  );
}

function Output({ text, color, onDl, onCopy }) {
  const [copied, setCopied] = useState(false);
  const isErr = text?.startsWith("[LLM") || text?.startsWith("[");
  return (
    <div>
      <div style={{
        background: T.raise, border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${isErr ? T.amber : color}`,
        borderRadius: 10, padding: "14px 16px", fontSize: 12.5,
        color: isErr ? T.amber : T.t1, lineHeight: 1.8, marginBottom: 10,
        whiteSpace: "pre-wrap"
      }}>{text}</div>
      {!isErr && (
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={onDl} style={{
            background: T.surface, border: `1px solid ${T.border}`,
            borderRadius: 8, color: T.t2, padding: "6px 14px",
            cursor: "pointer", fontSize: 10, fontFamily: "inherit", letterSpacing: 0.5,
            fontWeight: 700, transition: "all 0.15s ease"
          }}
          onMouseEnter={(e)=>e.target.style.borderColor = T.borderMd}
          onMouseLeave={(e)=>e.target.style.borderColor = T.border}
          >Download</button>
          <button onClick={() => { onCopy(); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
            style={{
              background: "transparent", border: `1px solid ${T.border}`,
              borderRadius: 8, color: copied ? T.green : T.t3, padding: "6px 14px",
              cursor: "pointer", fontSize: 10, fontFamily: "inherit", letterSpacing: 0.5,
              fontWeight: 700, transition: "all 0.15s ease"
            }}
            onMouseEnter={(e)=>e.target.style.borderColor = T.borderMd}
            onMouseLeave={(e)=>e.target.style.borderColor = T.border}
            >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      )}
    </div>
  );
}

function CodeOut({ code, color, filename }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <pre style={{
        background: T.raise, border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${color}`, borderRadius: 10, padding: "14px 16px",
        fontSize: 11, color: T.t1, overflowX: "auto", maxHeight: 300,
        fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.7, marginBottom: 10,
        whiteSpace: "pre-wrap",
      }}>{code}</pre>
      <div style={{ display: "flex", gap: 8 }}>
        <button onClick={() => dl(code, filename)} style={{
          background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8,
          color: T.t2, padding: "6px 14px", cursor: "pointer",
          fontSize: 10, fontFamily: "inherit", letterSpacing: 0.5, fontWeight: 700,
          transition: "all 0.15s ease"
        }}
        onMouseEnter={(e)=>e.target.style.borderColor = T.borderMd}
        onMouseLeave={(e)=>e.target.style.borderColor = T.border}
        >Download {filename}</button>
        <button onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
          style={{
            background: "transparent", border: `1px solid ${T.border}`, borderRadius: 8,
            color: copied ? T.green : T.t3, padding: "6px 14px", cursor: "pointer",
            fontSize: 10, fontFamily: "inherit", letterSpacing: 0.5, fontWeight: 700,
            transition: "all 0.15s ease"
          }}
          onMouseEnter={(e)=>e.target.style.borderColor = T.borderMd}
          onMouseLeave={(e)=>e.target.style.borderColor = T.border}
          >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

function dl(content, filename) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
  a.download = filename; a.click();
}

// ── Enrichment tab ─────────────────────────────────────────────────────────────
function EnrichTab({ iocs }) {
  const [sel,      setSel]      = useState(null);
  const [vtData,   setVtData]   = useState(null);
  const [sdData,   setSdData]   = useState(null);
  const [loading,  setLoading]  = useState({ vt: false, sd: false });
  const [search,   setSearch]   = useState("");

  const setL = (k, v) => setLoading(l => ({ ...l, [k]: v }));
  const TYPE_COLOR = { ip: T.red, domain: T.blue, sha256: T.purple, md5: T.purple, url: T.amber };

  const fetchVT = async (ioc) => {
    setL("vt", true); setVtData(null);
    try { setVtData(await api.get(`/api/enrich/virustotal/${encodeURIComponent(ioc.value)}`)); }
    catch(e) { setVtData({ error: e.message }); } finally { setL("vt", false); }
  };
  const fetchSD = async (ioc) => {
    setL("sd", true); setSdData(null);
    try { setSdData(await api.get(`/api/enrich/shodan/${encodeURIComponent(ioc.value)}`)); }
    catch(e) { setSdData({ error: e.message }); } finally { setL("sd", false); }
  };

  const filtered = iocs.filter(i => !search || i.value.toLowerCase().includes(search.toLowerCase())).slice(0, 100);
  const scoreColor = s => s >= 90 ? T.red : s >= 70 ? T.amber : "#ffd700";

  return (
    <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 16, fontFamily: "'Outfit', 'Inter', sans-serif" }}>
      <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 20, overflow: "hidden", boxShadow: "0 4px 20px rgba(12, 7, 64, 0.02)" }}>
        <div style={{ padding: "12px 14px", borderBottom: `1px solid ${T.border}` }}>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IOC list..."
            style={{
              background: T.raise, border: `1px solid ${T.border}`, borderRadius: 10,
              padding: "7px 12px", color: T.t1, fontSize: 12, fontFamily: "inherit",
              width: "100%", outline: "none", fontWeight: 500
            }} />
        </div>
        <div style={{ maxHeight: 540, overflowY: "auto" }}>
          {filtered.map((ioc, i) => {
            const sc = ioc.confidence_score || 0;
            const c  = scoreColor(sc);
            const isActive = sel?.value === ioc.value;
            return (
              <div key={i} onClick={() => { setSel(ioc); setVtData(null); setSdData(null); }}
                style={{
                  padding: "10px 16px", cursor: "pointer",
                  borderBottom: `1px solid ${T.border}`,
                  background: isActive ? T.hover : "transparent",
                  display: "flex", alignItems: "center", gap: 10, transition: "background 0.15s ease",
                }}
                onMouseEnter={(e)=>{ if(!isActive) e.currentTarget.style.background=T.raise; }}
                onMouseLeave={(e)=>{ if(!isActive) e.currentTarget.style.background="transparent"; }}
                >
                <div style={{ width: 7, height: 7, borderRadius: "50%", background: c, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                    color: TYPE_COLOR[ioc.ioc_type] || T.t1,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    fontWeight: 600
                  }}>{ioc.value}</div>
                  <div style={{ fontSize: 9, color: T.t3, marginTop: 2, fontWeight: 700, textTransform: "uppercase" }}>
                    {ioc.ioc_type} · Score: {sc.toFixed(0)}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        {!sel ? (
          <div style={{
            background: T.surface, border: `1px solid ${T.border}`,
            borderRadius: 20, padding: 60, textAlign: "center", color: T.t3,
            boxShadow: "0 4px 20px rgba(12, 7, 64, 0.02)", fontWeight: 600
          }}>
            <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.3 }}>◈</div>
            Select an active indicator to request threat intelligence
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{
              background: T.surface, border: `1px solid ${T.border}`,
              borderRadius: 16, padding: 18,
              display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap",
              boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)"
            }}>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: 13,
                color: T.blue, flex: 1, wordBreak: "break-all", fontWeight: 700
              }}>{sel.value}</span>
              <Btn onClick={() => fetchVT(sel)} loading={loading.vt} color={T.blue}>VirusTotal</Btn>
              {sel.ioc_type === "ip" && (
                <Btn onClick={() => fetchSD(sel)} loading={loading.sd} color={T.amber}>Shodan</Btn>
              )}
            </div>

            {vtData && (
              <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16, padding: 20, boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)" }}>
                <div style={{ fontSize: 10, fontWeight: 750, letterSpacing: 1.5, color: T.blue, marginBottom: 14, textTransform: "uppercase" }}>
                  VirusTotal Reports & Verdict
                </div>
                {vtData.error ? (
                  <div style={{ color: T.amber, fontSize: 12, fontWeight: 600 }}>{vtData.error}</div>
                ) : !vtData.found ? (
                  <div style={{ color: T.t3, fontSize: 12, fontWeight: 500 }}>Not cataloged inside VirusTotal databases.</div>
                ) : (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 16 }}>
                      {[
                        { l: "Malicious Engines", v: vtData.malicious ?? 0,       c: T.red   },
                        { l: "Total Scanned",    v: vtData.total_engines ?? 0,   c: T.t2    },
                        { l: "Trust Rating",     v: vtData.reputation ?? "N/A",  c: T.t2    },
                      ].map(s => (
                        <div key={s.l} style={{ background: T.raise, borderRadius: 10, padding: "12px", textAlign: "center", border: `1px solid ${T.border}` }}>
                          <div style={{ fontSize: 22, fontWeight: 900, color: s.c }}>{s.v}</div>
                          <div style={{ fontSize: 8.5, color: T.t3, letterSpacing: 0.5, marginTop: 4, textTransform: "uppercase", fontWeight: 700 }}>{s.l}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ height: 6, background: T.raise, borderRadius: 3, marginBottom: 12, overflow: "hidden" }}>
                      <div style={{
                        height: "100%", borderRadius: 3,
                        width: `${Math.min(100, ((vtData.malicious || 0) / Math.max(1, vtData.total_engines || 1)) * 100)}%`,
                        background: T.red,
                      }} />
                    </div>
                    {vtData.flagging_vendors?.length > 0 && (
                      <div style={{ fontSize: 11, color: T.t1, fontWeight: 500, background: T.raise, padding: 12, borderRadius: 8, border: `1px solid ${T.border}`, marginBottom: 10 }}>
                        <span style={{ color: T.t3, fontWeight: 700 }}>Flagged Vendors: </span>
                        {vtData.flagging_vendors.slice(0, 5).join(", ")}
                        {vtData.flagging_vendors.length > 5 && ` +${vtData.flagging_vendors.length - 5} others`}
                      </div>
                    )}
                    {vtData.country && (
                      <div style={{ fontSize: 11, color: T.t2, fontWeight: 550 }}>
                        <span style={{ color: T.t3, fontWeight: 700 }}>Target Geolocation: </span>{vtData.country}
                        {vtData.as_owner && <span> · <span style={{ color: T.t3, fontWeight: 700 }}>Provider ASN: </span>{vtData.as_owner}</span>}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {sdData && (
              <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16, padding: 20, boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)" }}>
                <div style={{ fontSize: 10, fontWeight: 750, letterSpacing: 1.5, color: T.amber, marginBottom: 14, textTransform: "uppercase" }}>
                  Shodan Port Intelligence
                </div>
                {sdData.error ? (
                  <div style={{ color: T.amber, fontSize: 12, fontWeight: 600 }}>{sdData.error}</div>
                ) : !sdData.found ? (
                  <div style={{ color: T.t3, fontSize: 12, fontWeight: 500 }}>No host endpoints cataloged in Shodan.</div>
                ) : (
                  <>
                    {sdData.verdict && (
                      <div style={{
                        background: `rgba(217,119,6,0.06)`, border: `1px solid rgba(217,119,6,0.18)`,
                        borderLeft: `3px solid ${T.amber}`, borderRadius: 8,
                        padding: "10px 14px", marginBottom: 14, fontSize: 12, color: T.amber,
                        fontWeight: 600
                      }}>{sdData.verdict}</div>
                    )}
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
                      {[
                        ["Registrar Country", sdData.country_name],
                        ["ISP Carrier",       sdData.isp],
                        ["Organization",      sdData.org],
                        ["Host Tagging",      sdData.ip_classification],
                      ].map(([l, v]) => v && (
                        <div key={l} style={{ background: T.raise, padding: 10, borderRadius: 8, border: `1px solid ${T.border}` }}>
                          <div style={{ fontSize: 8.5, color: T.t3, letterSpacing: 0.5, marginBottom: 3, textTransform: "uppercase", fontWeight: 700 }}>{l}</div>
                          <div style={{ fontSize: 11.5, color: T.t1, fontWeight: 600 }}>{v}</div>
                        </div>
                      ))}
                    </div>
                    {sdData.ports?.length > 0 && (
                      <div>
                        <div style={{ fontSize: 9, color: T.t3, letterSpacing: 1, marginBottom: 8, textTransform: "uppercase", fontWeight: 700 }}>Open Telemetry Ports</div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                          {sdData.ports.map(p => {
                            const sus = [4444, 50050, 31337, 8888].includes(p);
                            return (
                              <span key={p} style={{
                                fontSize: 10, fontWeight: 800, padding: "3px 9px", borderRadius: 6,
                                background: sus ? `${T.red}12` : `${T.blue}10`,
                                color: sus ? T.red : T.blue,
                                border: `1px solid ${sus ? T.red : T.blue}20`,
                              }}>{p}</span>
                            );
                          })}
                        </div>
                        {sdData.suspicious_ports?.length > 0 && (
                          <div style={{ marginTop: 10, fontSize: 11, color: T.red, fontWeight: 700 }}>
                            ⚠️ Critical service ports open: {sdData.suspicious_ports.join(", ")}
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Hunt queries tab ───────────────────────────────────────────────────────────
function HuntTab({ iocs, ttps }) {
  const [lang,  setLang]  = useState("kql");
  const [query, setQuery] = useState("");

  const gen = () => {
    const hashes = iocs.filter(i => i.ioc_type === "sha256").slice(0, 30);
    const ips    = iocs.filter(i => i.ioc_type === "ip").slice(0, 20);
    const doms   = iocs.filter(i => i.ioc_type === "domain").slice(0, 20);
    const now    = new Date().toISOString();

    if (lang === "kql") {
      let q = `// SPECTER Auto-generated KQL Hunt Queries\n// ${now}\n\n`;
      if (hashes.length) q += `// Malicious File Hashes\nDeviceFileEvents\n| where SHA256 in (\n${hashes.map(i => `    "${i.value}"`).join(",\n")}\n)\n| project Timestamp, DeviceName, FileName, SHA256\n| order by Timestamp desc\n\n`;
      if (ips.length)    q += `// Malicious IP Connections\nDeviceNetworkEvents\n| where RemoteIP in (\n${ips.map(i => `    "${i.value}"`).join(",\n")}\n)\n| project Timestamp, DeviceName, RemoteIP, RemotePort\n| order by Timestamp desc\n\n`;
      if (doms.length)   q += `// Malicious DNS Queries\nDnsEvents\n| where Name in (\n${doms.map(i => `    "${i.value}"`).join(",\n")}\n)\n| project TimeGenerated, Computer, Name\n| order by TimeGenerated desc\n`;
      setQuery(q.trim());
    } else {
      let q = `| Splunk Auto-generated Hunt Queries\n| Generated: ${now}\n\n`;
      if (ips.length)  q += `index=network dest_ip IN (${ips.map(i => `"${i.value}"`).join(", ")})\n| stats count by src_ip, dest_ip, dest_port, action\n\n`;
      if (doms.length) q += `index=dns query IN (${doms.map(i => `"${i.value}"`).join(", ")})\n| table _time src_ip query\n`;
      setQuery(q.trim());
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, fontFamily: "'Outfit', 'Inter', sans-serif" }}>
      <div style={{
        background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16, padding: 18,
        display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap",
        boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)"
      }}>
        <div style={{ display: "flex", gap: 4, background: T.raise, border: `1px solid ${T.border}`, borderRadius: 8, padding: 3 }}>
          {[["kql", "KQL — Sentinel / Defender"], ["spl", "SPL — Splunk"]].map(([id, lbl]) => (
            <button key={id} onClick={() => setLang(id)} style={{
              padding: "6px 14px", borderRadius: 6,
              background: lang === id ? T.surface : "transparent",
              border: "none", cursor: "pointer", fontSize: 10.5,
              fontFamily: "inherit", color: lang === id ? T.t1 : T.t2,
              fontWeight: 700, letterSpacing: 0.5, transition: "all 0.15s"
            }}>{lbl}</button>
          ))}
        </div>
        <Btn onClick={gen} color={T.blue}>Generate {lang.toUpperCase()}</Btn>
        <span style={{ fontSize: 11, color: T.t3, fontWeight: 500 }}>
          {iocs.length} critical IOCs · {ttps.length} ATT&CK vectors available
        </span>
      </div>
      {query ? (
        <CodeOut code={query} color={T.blue} filename={`specter_hunt.${lang}`} />
      ) : (
        <div style={{
          background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16,
          padding: 24, fontSize: 12, color: T.t2, lineHeight: 1.8,
          boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)", fontWeight: 500
        }}>
          KQL formats target Microsoft Sentinel, Defender endpoints, or Log Analytics workspaces.<br />
          SPL formats target Splunk indexing schemas.<br /><br />
          Select a format to compile custom hunting syntaxes from critical dataset inputs.
        </div>
      )}
    </div>
  );
}

// ── Clusters tab ───────────────────────────────────────────────────────────────
function ClustersTab({ iocs }) {
  const [clusters, setClusters] = useState([]);
  const [loading,  setLoading]  = useState(false);

  const run = async () => {
    setLoading(true); setClusters([]);
    try { const d = await api.get("/api/enrich/clusters"); setClusters(d.clusters || []); }
    catch { } finally { setLoading(false); }
  };

  const TYPE_COLORS = {
    "IP Infrastructure Block": T.red,
    "Domain Generation Pattern": T.blue,
    "Shared TTP Signature": T.purple,
    "Common Source": T.amber,
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16, fontFamily: "'Outfit', 'Inter', sans-serif" }}>
      <div style={{
        background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16, padding: 18,
        display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap",
        boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)"
      }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: T.t1, marginBottom: 4 }}>AI Indicator Clustering</div>
          <div style={{ fontSize: 11.5, color: T.t3, fontWeight: 500 }}>
            Clusters indicators by subnet proximity, domain character patterns, and TTP similarities.
            Deduces threat actor intent per classification group.
          </div>
        </div>
        <Btn onClick={run} loading={loading} color={T.purple}>Run Clustering</Btn>
      </div>

      {clusters.length === 0 && !loading && (
        <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16, padding: 24, color: T.t3, fontSize: 12, fontWeight: 500, boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)" }}>
          {"Run AI parsing to align threat telemetry into logical campaigns. Best results with >50 ingested assets."}
        </div>
      )}

      {clusters.map((c, i) => {
        const tc = TYPE_COLORS[c.cluster_type] || T.blue;
        return (
          <div key={i} style={{
            background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16, padding: 20,
            boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)"
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 12, flexWrap: "wrap" }}>
              <div>
                <span style={{
                  fontSize: 8.5, fontWeight: 700, padding: "2px 8px", borderRadius: 6, letterSpacing: 0.5,
                  background: `${tc}10`, color: tc, border: `1px solid ${tc}20`, textTransform: "uppercase",
                }}>{c.cluster_type}</span>
                <div style={{ fontSize: 12, color: T.t1, marginTop: 6, fontWeight: 700 }}>{c.cluster_label} · {c.member_count} members</div>
              </div>
              <div style={{ fontSize: 24, fontWeight: 900, color: c.avg_score >= 80 ? T.red : T.amber, letterSpacing: -1 }}>
                {c.avg_score?.toFixed(0)}
              </div>
            </div>
            {c.ai_hypothesis && (
              <div style={{
                background: "rgba(26,115,232,0.03)", border: `1px solid rgba(26,115,232,0.1)`,
                borderLeft: `3px solid ${T.blue}`, borderRadius: 8,
                padding: "10px 14px", marginBottom: 12, fontSize: 12, color: T.t2, lineHeight: 1.8,
                fontWeight: 500
              }}>
                {c.ai_hypothesis}
              </div>
            )}
            {c.shared_ttps?.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 8.5, color: T.t3, letterSpacing: 1, marginBottom: 6, textTransform: "uppercase", fontWeight: 700 }}>Shared ATT&CK Tactics</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {c.shared_ttps.map(t => (
                    <span key={t} style={{
                      fontSize: 9.5, fontWeight: 700, padding: "3px 8px", borderRadius: 6,
                      background: `${T.purple}10`, color: T.purple, border: `1px solid ${T.purple}20`,
                    }}>{t}</span>
                  ))}
                </div>
              </div>
            )}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {(c.members || []).slice(0, 8).map(v => (
                <span key={v} style={{
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                  background: T.raise, border: `1px solid ${T.border}`,
                  padding: "4px 10px", borderRadius: 6, color: T.t1,
                  maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  fontWeight: 500
                }}>{v}</span>
              ))}
              {c.member_count > 8 && (
                <span style={{ fontSize: 10, color: T.t3, fontWeight: 600, alignSelf: "center", marginLeft: 4 }}>+{c.member_count - 8} more</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main Reports ────────────────────────────────────────────────────────────────
export default function Reports() {
  const [stats,     setStats]     = useState(null);
  const [iocs,      setIocs]      = useState([]);
  const [ttps,      setTtps]      = useState([]);
  const [activeTab, setActiveTab] = useState("briefs");
  const [brief,     setBrief]     = useState("");
  const [narrative, setNarrative] = useState("");
  const [fwScript,  setFwScript]  = useState("");
  const [fwFormat,  setFwFormat]  = useState("iptables");
  const [sigma,     setSigma]     = useState("");
  const [loading,   setLoading]   = useState({});

  useEffect(() => {
    Promise.all([api.get("/api/stats"), api.get("/api/iocs/critical")])
      .then(([s, c]) => {
        setStats(s);
        const list = c.iocs || [];
        setIocs(list);
        const tm = new Map();
        list.forEach(ioc => (ioc.ttp_tags || []).forEach(id => !tm.has(id) && tm.set(id, { technique_id: id, name: id, tactic: "" })));
        setTtps(Array.from(tm.values()));
      }).catch(() => {});
  }, []);

  const setL = (k, v) => setLoading(l => ({ ...l, [k]: v }));

  const iocSummary = () => {
    const bd = stats?.type_breakdown || {};
    return `${stats?.total_iocs || 0} IOCs (${Object.entries(bd).map(([t, c]) => `${c} ${t}`).join(", ")}). Top: ${iocs.slice(0, 5).map(i => `${i.ioc_type}:${i.value}`).join(", ")}`;
  };
  const ttpSummary = () => !ttps.length ? "none" : `${ttps.length} techniques: ${ttps.slice(0, 10).map(t => t.technique_id).join(", ")}`;

  const genBrief = async () => {
    setL("brief", true); setBrief("");
    try { const d = await api.post("/api/llm/brief", { ioc_summary: iocSummary(), ttp_summary: ttpSummary(), source: "SPECTER" }); setBrief(d.brief); }
    catch { setBrief("[LLM unavailable]"); } finally { setL("brief", false); }
  };

  const genNarrative = async () => {
    setL("narrative", true); setNarrative("");
    try { const d = await api.post("/api/llm/narrative", ttps.length ? ttps : [{ technique_id: "unknown", name: "None" }]); setNarrative(d.narrative); }
    catch { setNarrative("[LLM unavailable]"); } finally { setL("narrative", false); }
  };

  const genFW = async () => {
    setL("fw", true); setFwScript("");
    try {
      const vals = iocs.filter(i => (i.ioc_type === "ip" || i.ioc_type === "domain") && (i.confidence_score || 0) >= 70).slice(0, 200).map(i => i.value);
      if (!vals.length) { setFwScript("# No high-confidence IP/domain IOCs found."); setL("fw", false); return; }
      const d = await api.post("/api/soar/firewall", { ioc_values: vals, format: fwFormat });
      setFwScript(d.script);
    } catch (e) { setFwScript("# Error: " + e.message); } finally { setL("fw", false); }
  };

  const genSigma = () => {
    const hashes = iocs.filter(i => ["sha256", "md5"].includes(i.ioc_type)).slice(0, 50);
    const ips    = iocs.filter(i => i.ioc_type === "ip").slice(0, 30);
    const doms   = iocs.filter(i => i.ioc_type === "domain").slice(0, 30);
    const now    = new Date().toISOString().split("T")[0];
    let rule = `# SPECTER Auto-generated Sigma Rules — ${now}\n\n`;
    if (hashes.length) rule += `title: SPECTER - Malicious File Hash\ndetection:\n  selection:\n    Hashes|contains:\n${hashes.map(i => `      - '${i.value}'`).join("\n")}\n  condition: selection\nlevel: critical\n\n---\n\n`;
    if (ips.length)    rule += `title: SPECTER - Malicious IP\ndetection:\n  selection:\n    DestinationIp|contains:\n${ips.map(i => `      - '${i.value}'`).join("\n")}\n  condition: selection\nlevel: critical\n\n---\n\n`;
    if (doms.length)   rule += `title: SPECTER - Malicious Domain\ndetection:\n  selection:\n    QueryName|contains:\n${doms.map(i => `      - '${i.value}'`).join("\n")}\n  condition: selection\nlevel: high\n`;
    setSigma(rule.trim());
  };

  const exportCSV = () => dl(
    ["type,value,score,source,ttps", ...iocs.map(i => `${i.ioc_type},"${i.value}",${(i.confidence_score || 0).toFixed(1)},"${i.source}","${(i.ttp_tags || []).join("|")}"`)].join("\n"),
    "specter_iocs.csv"
  );

  const exportSTIX = () => {
    const now = new Date().toISOString();
    const bundle = {
      type: "bundle", id: `bundle--specter-${Date.now()}`, spec_version: "2.1", created: now,
      objects: iocs.slice(0, 500).map((ioc, i) => ({
        type: "indicator", spec_version: "2.1", id: `indicator--specter-${i}`, created: now, modified: now,
        name: `SPECTER IOC: ${ioc.value}`, pattern: `[ipv4-addr:value = '${ioc.value}']`,
        pattern_type: "stix", valid_from: now, confidence: Math.round(ioc.confidence_score || 50),
        labels: ["malicious-activity"],
      })),
    };
    dl(JSON.stringify(bundle, null, 2), "specter_stix2.json");
  };

  return (
    <div style={{ padding: "32px 48px", maxWidth: 1000, margin: "0 auto", fontFamily: "'Outfit', 'Inter', sans-serif" }}>
      <div style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: -0.5, color: T.t1, marginBottom: 4 }}>
          Reports & Response
        </h1>
        <div style={{ fontSize: 9.5, color: T.t3, letterSpacing: 2, textTransform: "uppercase", fontWeight: 600 }}>
          LLM Briefs · Enrichment · Hunt Queries · IOC Clusters · STIX Export
        </div>
      </div>

      {/* Stats bar */}
      {stats && (
        <div style={{
          background: T.surface, border: `1px solid ${T.border}`, borderRadius: 16,
          padding: "16px 20px", marginBottom: 24, display: "flex", gap: 0,
          boxShadow: "0 4px 20px rgba(12, 7, 64, 0.02)"
        }}>
          {[
            { l: "Total IOCs",  v: stats.total_iocs,    c: T.blue   },
            { l: "Active",      v: stats.active_iocs,   c: T.green  },
            { l: "Critical",    v: stats.critical_iocs, c: T.red    },
            { l: "Actors",      v: stats.actors ?? 0,   c: T.t1     },
            { l: "TTP Vectors", v: stats.ttps ?? 0,     c: T.purple },
          ].map((s, i, arr) => (
            <div key={s.l} style={{
              flex: 1, textAlign: "center",
              borderRight: i < arr.length - 1 ? `1px solid ${T.border}` : "none",
              padding: "0 14px",
            }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: s.c, letterSpacing: -0.5 }}>{s.v ?? 0}</div>
              <div style={{ fontSize: 8.5, color: T.t3, letterSpacing: 1.5, marginTop: 4, textTransform: "uppercase", fontWeight: 700 }}>{s.l}</div>
            </div>
          ))}
        </div>
      )}

      {/* Tab bar */}
      <div style={{
        display: "flex", gap: 4, marginBottom: 24,
        background: "rgba(255, 255, 255, 0.8)", border: `1px solid ${T.border}`,
        borderRadius: 12, padding: 4, width: "fit-content",
        boxShadow: "0 2px 10px rgba(12,7,64,0.01)"
      }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} 
            style={{
              padding: "8px 18px", borderRadius: 8,
              background: activeTab === t.id ? T.t1 : "transparent",
              border: "none",
              color: activeTab === t.id ? "#ffffff" : T.t2,
              cursor: "pointer", fontSize: 10.5, fontFamily: "inherit",
              letterSpacing: 1, fontWeight: 700, transition: "all 0.2s ease", textTransform: "uppercase",
            }}>{t.label}</button>
        ))}
      </div>

      {/* Briefs tab */}
      {activeTab === "briefs" && (
        <div>
          <Section title="Executive Brief" badge="CISO Summary" badgeColor={T.blue}
            desc="Plain-English threat summary for stakeholders. Synthesized via Groq Llama 3.3."
            action={<Btn onClick={genBrief} loading={loading.brief}>Generate Brief</Btn>}>
            {brief && <Output text={brief} color={T.blue}
              onDl={() => dl(brief, "specter_brief.txt")} onCopy={() => navigator.clipboard.writeText(brief)} />}
          </Section>

          <Section title="Attack Campaign Narrative" badge="AI Hypothesis" badgeColor={T.purple}
            desc="Constructs chronological kill-chain stories based on ATT&CK techniques mapped to indicators."
            action={<Btn onClick={genNarrative} loading={loading.narrative} color={T.purple}>Generate Narrative</Btn>}>
            {narrative && <Output text={narrative} color={T.purple}
              onDl={() => dl(narrative, "specter_narrative.txt")} onCopy={() => navigator.clipboard.writeText(narrative)} />}
          </Section>

          <Section title="Sigma Detection Rules" badge="SIEM Format" badgeColor={T.amber}
            desc="Compiles threat indicators into standardized Sigma YAML definitions. Drop directly into Splunk, Elastic, or Chronicle."
            action={<Btn onClick={genSigma} color={T.amber}>Generate Sigma</Btn>}>
            {sigma && <CodeOut code={sigma} color={T.amber} filename="specter_sigma.yml" />}
          </Section>

          <Section title="Active Firewall Scripting" badge="SOAR block list" badgeColor={T.green}
            desc="Assembles script files to drop active IPs and domains at borders. Filters clean references automatically."
            action={
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <select value={fwFormat} onChange={e => setFwFormat(e.target.value)} 
                  style={{
                    background: T.raise, border: `1px solid ${T.border}`, borderRadius: 10,
                    padding: "8px 14px", color: T.t1, fontSize: 11, fontFamily: "inherit", outline: "none",
                    fontWeight: 700, cursor: "pointer", transition: "border-color 0.2s"
                  }}
                  onFocus={(e)=>e.target.style.borderColor = T.t3}
                  onBlur={(e)=>e.target.style.borderColor = T.border}
                >
                  <option value="iptables">iptables (Linux)</option>
                  <option value="pfsense">pfSense XML</option>
                </select>
                <Btn onClick={genFW} loading={loading.fw} color={T.green}>Generate Script</Btn>
              </div>
            }>
            {fwScript && <CodeOut code={fwScript} color={T.green} filename={fwFormat === "iptables" ? "block_specter.sh" : "specter_pfsense.xml"} />}
          </Section>
        </div>
      )}

      {activeTab === "enrich"   && <EnrichTab iocs={iocs} />}
      {activeTab === "hunt"     && <HuntTab iocs={iocs} ttps={ttps} />}
      {activeTab === "clusters" && <ClustersTab iocs={iocs} />}

      {activeTab === "export" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <Section title={`IOC Export — ${iocs.length} Indicators`} badge="TELEMETRY" badgeColor={T.t3}
            desc="Export active threat data bundles for secure network sharing or SIEM storage."
            action={<div style={{ display: "flex", gap: 10 }}><Btn onClick={exportCSV} color={T.blue}>Export CSV</Btn><Btn onClick={exportSTIX} color={T.purple}>STIX 2.1</Btn></div>}>
            <div style={{ maxHeight: 320, overflowY: "auto", marginTop: 16, border: `1px solid ${T.border}`, borderRadius: 12, padding: "4px 16px", background: T.raise }}>
              {iocs.map((ioc, i) => {
                const sc = ioc.confidence_score || 0;
                const c  = sc >= 90 ? T.red : sc >= 70 ? T.amber : "#ffd700";
                return (
                  <div key={i} style={{
                    display: "flex", alignItems: "center", gap: 12, padding: "10px 0",
                    borderBottom: i === iocs.length - 1 ? "none" : `1px solid ${T.border}`, fontSize: 11.5,
                  }}>
                    <span style={{ fontSize: 8.5, color: c, width: 60, letterSpacing: 0.5, textTransform: "uppercase", fontWeight: 800 }}>
                      {ioc.ioc_type}
                    </span>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace", color: T.blue, flex: 1,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 420,
                      fontWeight: 600
                    }}>{ioc.value}</span>
                    <span style={{ fontSize: 12.5, fontWeight: 800, color: c, minWidth: 32, textAlign: "right", fontFamily: "'JetBrains Mono', monospace" }}>
                      {sc.toFixed(0)}
                    </span>
                  </div>
                );
              })}
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}
