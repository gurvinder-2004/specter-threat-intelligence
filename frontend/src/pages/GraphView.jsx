import { useEffect, useRef, useState, useCallback } from "react";
import * as d3 from "d3";
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
  t1:       "#0c0740",
  t2:       "#4a5270",
  t3:       "#838da8",
  orange:   "#f97316"
};

const IOC_COLORS = {
  ip: T.red, domain: T.blue, sha256: T.purple,
  md5: T.purple, url: T.amber, email: T.green,
};

function nodeColor(n) {
  if (n.labels?.[0] === "IOC")      return IOC_COLORS[n.props?.ioc_type] || T.blue;
  if (n.labels?.[0] === "TTP")      return T.purple;
  if (n.labels?.[0] === "Actor")    return T.red;
  if (n.labels?.[0] === "Campaign") return T.amber;
  return T.t3;
}
function nodeSize(n) {
  if (n.labels?.[0] === "Actor")    return 14;
  if (n.labels?.[0] === "Campaign") return 12;
  if (n.labels?.[0] === "TTP")      return 9;
  return 7;
}

const LEGEND = [
  { c: T.red,    l: "Critical IP" }, 
  { c: T.blue,   l: "Domain" },
  { c: T.amber,  l: "URL" }, 
  { c: T.purple, l: "Hash / TTP" },
  { c: T.red,    l: "Threat Actor" },
];

const NEO4J_QUERIES = [
  { label: "IOC → TTP",     q: "MATCH p=(i:IOC)-[:USES_TECHNIQUE]->(t:TTP) RETURN p LIMIT 80" },
  { label: "Actor → IOC",   q: "MATCH p=(a:Actor)-[r]->(i:IOC) RETURN p LIMIT 50" },
  { label: "All edges",     q: "MATCH p=(a)-[r]->(b) RETURN p LIMIT 100" },
  { label: "Critical only", q: "MATCH (n:IOC) WHERE n.confidence_score >= 80 RETURN n LIMIT 60" },
];

export default function GraphView() {
  const svgRef   = useRef(null);
  const simRef   = useRef(null);
  const [loading, setLoading]   = useState(true);
  const [counts,  setCounts]    = useState({ nodes: 0, edges: 0 });
  const [selected,setSelected]  = useState(null);
  const [search,  setSearch]    = useState("");
  const [hits,    setHits]      = useState([]);
  const [rawData, setRawData]   = useState(null);
  const [filter,  setFilter]    = useState("ALL");
  const [neo4jMode,setNeo4jMode]= useState(false);
  const [qIdx,    setQIdx]      = useState(0);

  const buildGraph = useCallback((rawNodes, rawEdges, hlId = null) => {
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    const W = svgRef.current.clientWidth || 900;
    const H = svgRef.current.clientHeight || 640;

    const nodes = rawNodes.map(n => ({ ...n }));
    const ids   = new Set(nodes.map(n => n.id));
    const edges = rawEdges.filter(e => ids.has(e.source) && ids.has(e.target)).map(e => ({ ...e }));
    setCounts({ nodes: nodes.length, edges: edges.length });

    // Subtle grid background (Light theme)
    const defs = svg.append("defs");
    const pat  = defs.append("pattern").attr("id","g").attr("width",40).attr("height",40).attr("patternUnits","userSpaceOnUse");
    pat.append("path").attr("d","M 40 0 L 0 0 0 40").attr("fill","none").attr("stroke","rgba(12,7,64,0.025)").attr("stroke-width",.5);
    svg.append("rect").attr("width",W).attr("height",H).attr("fill","url(#g)");

    defs.append("marker").attr("id","arr").attr("viewBox","0 -4 8 8")
      .attr("refX",18).attr("refY",0).attr("markerWidth",5).attr("markerHeight",5)
      .attr("orient","auto").append("path").attr("d","M0,-4L8,0L0,4")
      .attr("fill","rgba(12,7,64,0.15)");

    const root = svg.append("g");
    const zoom = d3.zoom().scaleExtent([0.05, 6])
      .on("zoom", e => root.attr("transform", e.transform));
    svg.call(zoom);
    svg.on("wheel.zoom", e => { e.preventDefault(); e.stopPropagation(); }, { passive: false });

    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(edges).id(d => d.id)
        .distance(d => {
          const st = d.source?.labels?.[0], tt = d.target?.labels?.[0];
          if (st === "Actor" || tt === "Actor") return 180;
          if (tt === "TTP") return 110;
          return 72;
        }).strength(0.45))
      .force("charge", d3.forceManyBody().strength(d =>
        d.labels?.[0] === "Actor" ? -600 : d.labels?.[0] === "TTP" ? -130 : -180))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("collide", d3.forceCollide(d => nodeSize(d) + 7))
      .force("x", d3.forceX(d => {
        if (d.labels?.[0] === "Actor") return W * 0.15;
        if (d.labels?.[0] === "TTP")   return W * 0.78;
        return W / 2;
      }).strength(0.04))
      .alphaDecay(0.022).velocityDecay(0.38);
    simRef.current = sim;

    const linkG = root.append("g");
    const link  = linkG.selectAll("line").data(edges).join("line")
      .attr("stroke", d => {
        const rt = d.rel_type || "";
        return rt === "USES_TECHNIQUE" ? `${T.purple}40` : rt === "USES" ? `${T.red}40` : "rgba(12,7,64,0.08)";
      })
      .attr("stroke-width", 1.2)
      .attr("marker-end", "url(#arr)");

    const nodeG = root.append("g");
    const node  = nodeG.selectAll("g").data(nodes).join("g").style("cursor","pointer");

    node.append("circle")
      .attr("r", d => nodeSize(d) * 2.8)
      .attr("fill", d => nodeColor(d) + "12")
      .attr("stroke","none");
    node.append("circle")
      .attr("r", d => nodeSize(d))
      .attr("fill", d => nodeColor(d))
      .attr("stroke", d => d.id === hlId ? T.t1 : "rgba(255,255,255,0.85)")
      .attr("stroke-width", d => d.id === hlId ? 2.5 : 1.2);
    node.append("text")
      .attr("dy", d => nodeSize(d) + 12).attr("text-anchor","middle")
      .attr("font-size", d => d.labels?.[0] === "IOC" ? 8 : 10)
      .attr("font-weight", d => d.labels?.[0] === "IOC" ? 500 : 700)
      .attr("font-family","'JetBrains Mono', 'Outfit', monospace")
      .attr("fill", d => d.labels?.[0] === "IOC" ? "rgba(12,7,64,0.4)" : T.t1)
      .attr("pointer-events","none")
      .text(d => {
        const v = d.props?.value || d.props?.name || d.props?.technique_id || "";
        return v.length > 18 ? v.slice(0,18)+"…" : v;
      });

    node.on("click", (e,d) => { e.stopPropagation(); setSelected(d); });
    svg.on("click", () => setSelected(null));
    node.call(d3.drag()
      .on("start", (e,d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on("drag",  (e,d) => { d.fx=e.x; d.fy=e.y; })
      .on("end",   (e,d) => { if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));

    sim.on("tick", () => {
      link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
      node.attr("transform",d=>`translate(${d.x},${d.y})`);
    });
    sim.on("end", () => {
      const b = root.node().getBBox();
      if (!b.width) return;
      const sc = Math.min(0.88, 0.88 * Math.min(W / b.width, H / b.height));
      svg.transition().duration(600)
        .call(zoom.transform, d3.zoomIdentity.translate(W/2 - sc*(b.x+b.width/2), H/2 - sc*(b.y+b.height/2)).scale(sc));
    });
  }, []);

  useEffect(() => {
    api.get("/api/graph").then(d => {
      setRawData(d); buildGraph(d.nodes||[], d.edges||[]);
    }).catch(() => setRawData({nodes:[],edges:[]})).finally(() => setLoading(false));
  }, [buildGraph]);

  useEffect(() => {
    if (!rawData) return;
    let n = rawData.nodes || [];
    if (filter !== "ALL") {
      if (["IP","DOMAIN","SHA256","URL","MD5"].includes(filter))
        n = n.filter(nd => nd.labels?.[0]==="IOC" && nd.props?.ioc_type===filter.toLowerCase());
      else if (filter==="TTP")   n = n.filter(nd => nd.labels?.[0]==="TTP");
      else if (filter==="ACTOR") n = n.filter(nd => nd.labels?.[0]==="Actor");
    }
    buildGraph(n, rawData.edges||[]);
  }, [filter, rawData, buildGraph]);

  const doSearch = q => {
    setSearch(q);
    if (!q || !rawData) { setHits([]); return; }
    setHits((rawData.nodes||[]).filter(n =>
      (n.props?.value||n.props?.name||n.props?.technique_id||"").toLowerCase().includes(q.toLowerCase())
    ).slice(0,8));
  };

  const jumpTo = n => {
    setSearch(""); setHits([]); setSelected(n);
    if (rawData) buildGraph(rawData.nodes||[], rawData.edges||[], n.id);
  };

  const FILTERS = ["ALL","IP","DOMAIN","SHA256","URL","TTP","ACTOR"];

  if (neo4jMode) {
    const q = encodeURIComponent(NEO4J_QUERIES[qIdx].q);
    const url = `http://localhost:7474/browser/?cmd=edit&arg=${q}`;
    return (
      <div style={{ height: "100vh", display: "flex", flexDirection: "column", background: "#eef2f7", fontFamily: "'Outfit', 'Inter', sans-serif" }}>
        <div style={{
          padding: "16px 24px", background: T.surface, borderBottom: `1px solid ${T.border}`,
          display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap",
        }}>
          <button onClick={() => setNeo4jMode(false)} style={{
            background: T.surface, border: `1px solid ${T.border}`, borderRadius: 8,
            color: T.t1, padding: "6px 14px", cursor: "pointer", fontSize: 11, fontWeight: 700,
            boxShadow: "0 2px 8px rgba(12,7,64,0.02)"
          }}>← Back to Graph Map</button>
          <span style={{ fontSize: 13, color: T.t1, fontWeight: 800 }}>Neo4j Graph Database direct Link</span>
          <span style={{ fontSize: 10, color: T.t3, fontWeight: 500 }}>bolt://localhost:7687 · neo4j / specter_pass</span>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {NEO4J_QUERIES.map((q, i) => (
              <button key={i} onClick={() => setQIdx(i)} style={{
                padding: "4px 12px", borderRadius: 8, border: `1px solid ${qIdx===i ? T.t1 : T.border}`,
                background: qIdx===i ? T.t1 : "transparent",
                color: qIdx===i ? "#ffffff" : T.t2, cursor: "pointer",
                fontSize: 10, fontWeight: 700, letterSpacing: 0.5,
                transition: "all 0.2s"
              }}>{q.label}</button>
            ))}
          </div>
          <a href={url} target="_blank" rel="noopener noreferrer" style={{
            marginLeft: "auto", background: T.t1, borderRadius: 99, color: "#fff",
            padding: "8px 18px", textDecoration: "none", fontSize: 11, fontWeight: 700, letterSpacing: 0.5,
            boxShadow: "0 4px 12px rgba(12,7,64,0.15)"
          }}>Open Browser Tab</a>
        </div>

        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 24, padding: 40 }}>
          <div style={{ fontSize: 36, color: T.t3, opacity: 0.3 }}>⬡</div>
          <div style={{ fontSize: 14, color: T.t1, textAlign: "center", lineHeight: 1.8, maxWidth: 520, fontWeight: 600 }}>
            Neo4j Console operates directly on <span style={{ color: T.blue }}>localhost:7474</span>.<br />
            Launch the standalone browser window to execute cyber query graphs.
          </div>
          <div style={{
            background: T.surface, border: `1px solid ${T.border}`, borderRadius: 14,
            padding: "16px 24px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: T.blue,
            textAlign: "center", boxShadow: "0 4px 16px rgba(12,7,64,0.02)", maxWidth: "90%", wordBreak: "break-all"
          }}>
            <div style={{ fontSize: 9, color: T.t3, letterSpacing: 1.5, marginBottom: 6, textTransform: "uppercase", fontWeight: 700 }}>Active Cipher Command</div>
            {NEO4J_QUERIES[qIdx].q}
          </div>
          <div style={{ display: "flex", gap: 12 }}>
            <a href="http://localhost:7474/browser/" target="_blank" rel="noopener noreferrer" style={{
              background: T.t1, borderRadius: 99, color: "#fff", padding: "12px 28px",
              fontSize: 13, fontWeight: 700, textDecoration: "none", letterSpacing: 0.5,
              boxShadow: "0 4px 16px rgba(12,7,64,0.15)"
            }}>Open standalone Console</a>
            <button onClick={() => setNeo4jMode(false)} style={{
              background: T.surface, border: `1px solid ${T.border}`, borderRadius: 99, color: T.t2,
              padding: "12px 24px", cursor: "pointer", fontSize: 13, fontWeight: 700,
            }}>Return to Graph Map</button>
          </div>
          <div style={{
            background: "rgba(26,115,232,0.04)", border: `1px solid rgba(26,115,232,0.1)`,
            borderRadius: 10, padding: "14px 20px", fontSize: 11, color: T.t2, lineHeight: 1.8,
            fontWeight: 500
          }}>
            🔐 Target Creds: Bolt: <span style={{ color: T.t1, fontWeight: 700 }}>bolt://localhost:7687</span>
            · User: <span style={{ color: T.t1, fontWeight: 700 }}>neo4j</span>
            · Password: <span style={{ color: T.t1, fontWeight: 700 }}>specter_pass</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100vh", background:"#eef2f7", fontFamily: "'Outfit', 'Inter', sans-serif" }}>
      <div style={{
        padding:"12px 24px", background:T.surface, borderBottom:`1px solid ${T.border}`,
        display:"flex", gap:14, alignItems:"center", flexWrap:"wrap",
        boxShadow: "0 2px 10px rgba(12, 7, 64, 0.01)"
      }}>
        <span style={{ fontSize:15, fontWeight:800, color:T.t1 }}>Threat Map</span>

        <div style={{ position:"relative" }}>
          <input value={search} onChange={e=>doSearch(e.target.value)} placeholder="Search IOC or Threat Actor..."
            style={{
              background:T.raise, border:`1px solid ${T.border}`, borderRadius:10,
              padding:"6px 14px 6px 32px", color:T.t1, fontSize:12, fontFamily:"inherit",
              width:220, outline:"none", transition: "border-color 0.2s",
              fontWeight: 500
            }}
            onFocus={(e) => e.target.style.borderColor = T.t3}
            onBlur={(e) => e.target.style.borderColor = T.border}
          />
          <span style={{ position: "absolute", left: 10, top: 7, fontSize: 13, color: T.t3 }}>🔍</span>
          {hits.length > 0 && (
            <div style={{
              position:"absolute", top:"100%", left:0, background:T.surface,
              border:`1px solid ${T.border}`, borderRadius:12, zIndex:99,
              width:320, maxHeight:240, overflowY:"auto", marginTop:6,
              boxShadow: "0 8px 30px rgba(12,7,64,0.08)"
            }}>
              {hits.map(n => (
                <div key={n.id} onClick={()=>jumpTo(n)} style={{
                  padding:"9px 14px", cursor:"pointer", borderBottom:`1px solid ${T.border}`,
                  display:"flex", alignItems:"center", gap:10, fontSize:11.5,
                  color:T.t2, fontFamily:"'JetBrains Mono', monospace",
                  transition: "background 0.15s ease"
                }}
                onMouseEnter={(e)=>e.currentTarget.style.background=T.raise}
                onMouseLeave={(e)=>e.currentTarget.style.background="transparent"}
                >
                  <div style={{ width:6,height:6,borderRadius:"50%",background:nodeColor(n),flexShrink:0 }} />
                  <span style={{ flex:1, overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",fontWeight: 500 }}>
                    {(n.props?.value||n.props?.name||"").slice(0,36)}
                  </span>
                  <span style={{ color:T.t3, fontSize:9.5, fontWeight: 700, textTransform: "uppercase" }}>{n.labels?.[0]}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div style={{ display:"flex", gap:4 }}>
          {FILTERS.map(f => (
            <button key={f} onClick={()=>setFilter(f)} 
              style={{
                padding:"5px 12px", borderRadius:8,
                background:filter===f ? T.t1 : "transparent",
                border:`1px solid ${filter===f ? T.t1 : T.border}`,
                color:filter===f ? "#ffffff" : T.t2, cursor:"pointer",
                fontSize:10, fontWeight:700, letterSpacing:0.5, textTransform:"uppercase",
                transition: "all 0.15s ease"
              }}
              onMouseEnter={(e) => { if(filter!==f) { e.target.style.background = T.hover; e.target.style.color = T.t1; } }}
              onMouseLeave={(e) => { if(filter!==f) { e.target.style.background = "transparent"; e.target.style.color = T.t2; } }}
            >{f}</button>
          ))}
        </div>

        <div style={{ display:"flex", gap:12, fontSize:10.5, color:T.t3, letterSpacing:0.5, fontWeight: 600 }}>
          <span>Node count: <span style={{ color:T.t1, fontWeight:750 }}>{counts.nodes}</span></span>
          <span>Edge links: <span style={{ color:T.t1, fontWeight:750 }}>{counts.edges}</span></span>
          {counts.edges === 0 && (
            <span style={{ color:T.amber, fontWeight:700 }}>⚠️ Ingest data to build edge relationships</span>
          )}
        </div>

        <div style={{ display:"flex", gap:12, flexWrap:"wrap" }}>
          {LEGEND.map(l => (
            <div key={l.l} style={{ display:"flex", alignItems:"center", gap:6, fontSize:10, color:T.t2, fontWeight: 600 }}>
              <div style={{ width:7,height:7,borderRadius:"50%",background:l.c }} />
              {l.l}
            </div>
          ))}
        </div>

        <button onClick={()=>setNeo4jMode(true)} 
          style={{
            marginLeft:"auto", background: T.surface, border:`1px solid ${T.border}`,
            borderRadius:8, color: T.t1, padding:"6px 14px", cursor:"pointer",
            fontSize:10, fontWeight:750, letterSpacing:0.5, textTransform: "uppercase",
            boxShadow: "0 2px 6px rgba(12,7,64,0.02)", transition: "all 0.15s ease"
          }}
          onMouseEnter={(e) => { e.target.style.borderColor = T.borderMd; e.target.style.background = T.raise; }}
          onMouseLeave={(e) => { e.target.style.borderColor = T.border; e.target.style.background = T.surface; }}
        >
          Neo4j Browser
        </button>
      </div>

      <div style={{ flex:1, display:"flex", position:"relative", overflow:"hidden" }}>
        {loading && (
          <div style={{
            position:"absolute", inset:0, display:"flex", alignItems:"center",
            justifyContent:"center", color:T.t3, fontSize:12, letterSpacing:2, zIndex:10, background:"#eef2f7",
            fontWeight: 700
          }}>Building Force Layout Sim...</div>
        )}

        <svg ref={svgRef} style={{ flex:1, display:"block", overflow:"hidden" }} />

        <div style={{ position:"absolute", bottom:24, right: selected ? 320 : 24, display:"flex", flexDirection:"column", gap:6, zIndex:10 }}>
          {[
            { l:"+", a:()=>d3.select(svgRef.current).transition().call(d3.zoom().scaleBy,1.5) },
            { l:"⟲", a:()=>d3.select(svgRef.current).transition().duration(500).call(d3.zoom().transform,d3.zoomIdentity) },
            { l:"−", a:()=>d3.select(svgRef.current).transition().call(d3.zoom().scaleBy,0.67) },
          ].map(b => (
            <button key={b.l} onClick={b.a} style={{
              width:34,height:34,background:T.surface,
              border:`1px solid ${T.border}`,borderRadius:8,
              color:T.t1,cursor:"pointer",fontSize:16,fontWeight:800,
              boxShadow: "0 4px 12px rgba(12,7,64,0.03)", transition: "all 0.15s"
            }}
            onMouseEnter={(e)=>e.target.style.background=T.raise}
            onMouseLeave={(e)=>e.target.style.background=T.surface}
            >{b.l}</button>
          ))}
        </div>

        {selected && (
          <div style={{
            width:300, background:T.surface, borderLeft:`1px solid ${T.border}`,
            padding:20, overflowY:"auto", flexShrink:0,
            boxShadow: "-4px 0 24px rgba(12,7,64,0.02)",
            animation: "fadeIn 0.2s ease"
          }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:18, alignItems:"center" }}>
              <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                <div style={{ width:10,height:10,borderRadius:"50%",background:nodeColor(selected) }} />
                <span style={{ fontSize:10.5, color:T.t1, letterSpacing:1.5, textTransform:"uppercase", fontWeight: 800 }}>
                  {selected.labels?.[0]} Node
                </span>
              </div>
              <button onClick={()=>setSelected(null)} style={{ background:"none",border:"none",color:T.t3,cursor:"pointer",fontSize:22, lineHeight: 1 }}>×</button>
            </div>

            {selected.props?.confidence_score !== undefined && (
              <div style={{ marginBottom:18 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
                  <span style={{ fontSize:9.5, color:T.t3, letterSpacing:1.5, textTransform:"uppercase", fontWeight: 700 }}>Confidence</span>
                  <span style={{ fontSize:18, fontWeight:800, color:nodeColor(selected), fontFamily:"'JetBrains Mono', monospace" }}>
                    {selected.props.confidence_score?.toFixed(0)}
                  </span>
                </div>
                <div style={{ height:5, background:T.raise, borderRadius:2 }}>
                  <div style={{ height:"100%", width:`${selected.props.confidence_score}%`, background:nodeColor(selected), borderRadius:2 }} />
                </div>
              </div>
            )}

            {Object.entries(selected.props || {}).filter(([k]) => k !== "confidence_score").map(([k,v]) => (
              <div key={k} style={{ marginBottom:12 }}>
                <div style={{ fontSize:9, color:T.t3, letterSpacing:1, marginBottom:4, textTransform:"uppercase", fontWeight: 700 }}>
                  {k.replace(/_/g," ")}
                </div>
                <div style={{
                  fontSize:11.5, wordBreak:"break-all",
                  color:k==="value"||k==="name"?T.blue:T.t2,
                  fontFamily:k==="value"||k==="technique_id"?"'JetBrains Mono', monospace":"inherit",
                  background:T.raise, padding:"8px 10px", borderRadius:8, border:`1px solid ${T.border}`,
                  lineHeight: 1.6, fontWeight: 500
                }}>
                  {Array.isArray(v) ? v.join(", ") : String(v).slice(0,180)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
