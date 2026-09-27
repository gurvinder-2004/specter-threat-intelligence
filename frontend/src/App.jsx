import { useState, useEffect, useRef } from "react";
import * as THREE     from "three";
import Dashboard      from "./pages/Dashboard";
import GraphView      from "./pages/GraphView";
import Ingest         from "./pages/Ingest";
import Reports        from "./pages/Reports";
import AEGISDashboard from "./pages/AEGISDashboard";
import { api }        from "./api";

// ── Design tokens (Light Mode Aesthetic) ──────────────────────────────────────
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
  orange:   "#f97316", // Accent orange
};

// ── Global styles injected once ───────────────────────────────────────────────
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500;600&display=swap');
  
  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }
  
  :root {
    --red: #d32f2f;
    --blue: #1a73e8;
    --green: #1b873f;
    --purple: #6c4eb8;
    --amber: #d97706;
    --bg: #ebf0f5;
    --surface: #ffffff;
    --raise: #f5f8fa;
    --hover: #edf1f5;
    --border: rgba(12, 7, 64, 0.08);
    --border-md: rgba(12, 7, 64, 0.14);
    --brand: #0c0740;
    --brand-hover: #161159;
    --t1: #0c0740;
    --t2: #4a5270;
    --t3: #838da8;
  }
  
  html, body, #root {
    height: 100%;
    font-family: 'Outfit', 'Inter', system-ui, sans-serif;
    background: #eef2f7;
    color: var(--t1);
    overflow-x: hidden;
  }
  
  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  ::-webkit-scrollbar-track {
    background: transparent;
  }
  ::-webkit-scrollbar-thumb {
    background: rgba(12, 7, 64, 0.12);
    border-radius: 4px;
  }
  ::-webkit-scrollbar-thumb:hover {
    background: rgba(12, 7, 64, 0.24);
  }
  
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(24px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
  
  .nav-link {
    transition: color 0.15s, background 0.15s, border-color 0.15s;
  }
  .nav-link:hover {
    color: var(--brand) !important;
    background: var(--hover) !important;
  }
  
  .btn-primary {
    transition: all 0.2s ease;
    box-shadow: 0 4px 12px rgba(12, 7, 64, 0.15);
  }
  .btn-primary:hover {
    background: var(--brand-hover) !important;
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(12, 7, 64, 0.25);
  }
  .btn-primary:active {
    transform: translateY(1px);
  }
  
  .card-hover {
    transition: all 0.2s ease;
    box-shadow: 0 4px 20px rgba(12, 7, 64, 0.03);
  }
  .card-hover:hover {
    border-color: var(--border-md) !important;
    transform: translateY(-2px);
    box-shadow: 0 8px 30px rgba(12, 7, 64, 0.08);
  }
`;

// ── Three.js Brain Hero (Detailed Mathematical Model) ─────────────────────────
function BrainHero() {
  const mountRef = useRef(null);
  const mouseRef = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const el = mountRef.current;
    if (!el) return;

    const W = el.clientWidth || window.innerWidth || 800;
    const H = el.clientHeight || window.innerHeight || 600;
    const renderer = new THREE.WebGLRenderer({ 
      antialias: false, 
      alpha: true,
      powerPreference: "high-performance" 
    });
    renderer.setPixelRatio(1);
    renderer.setSize(W, H);
    renderer.setClearColor(0x000000, 0);

    const canvas = renderer.domElement;
    canvas.style.position = "absolute";
    canvas.style.top = "0";
    canvas.style.left = "0";
    canvas.style.width = "100%";
    canvas.style.height = "100%";
    canvas.style.pointerEvents = "none";
    el.appendChild(canvas);

    const scene  = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, W / H, 0.1, 100);
    camera.position.set(0, 0, 5.2);

    const createDotTexture = () => {
      const cv = document.createElement("canvas");
      cv.width = 16;
      cv.height = 16;
      const ctx = cv.getContext("2d");
      const grad = ctx.createRadialGradient(8, 8, 0, 8, 8, 8);
      grad.addColorStop(0, "rgba(255,255,255,1)");
      grad.addColorStop(0.3, "rgba(255,255,255,0.8)");
      grad.addColorStop(1, "rgba(255,255,255,0)");
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 16, 16);
      return new THREE.CanvasTexture(cv);
    };

    const dotTexture = createDotTexture();

    const COUNT = 1200;
    const positions = new Float32Array(COUNT * 3);
    const colors    = new Float32Array(COUNT * 3);
    const c1 = new THREE.Color("#e2e8f0");
    const c2 = new THREE.Color("#38bdf8");
    const c3 = new THREE.Color("#0c0740");
    const c4 = new THREE.Color("#f97316");

    for (let i = 0; i < COUNT; i++) {
      let x = 0, y = 0, z = 0;
      const region = Math.random();

      if (region < 0.72) {
        const theta = Math.random() * Math.PI * 2;
        const phi   = Math.acos(2 * Math.random() - 1);
        const rx = 0.95; const ry = 0.90; const rz = 1.35;
        let bx = rx * Math.sin(phi) * Math.cos(theta);
        let by = ry * Math.cos(phi);
        let bz = rz * Math.sin(phi) * Math.sin(theta);
        const offset = 0.05;
        if (bx > 0) bx += offset; else bx -= offset;
        const pinch = 1.0 - 0.35 * Math.exp(-20.0 * bx * bx);
        bx *= pinch; by *= pinch; bz *= pinch;
        const wrinkle = 0.08 * Math.sin(8 * bx) * Math.cos(8 * by) * Math.sin(8 * bz)
                      + 0.04 * Math.sin(16 * bx) * Math.cos(16 * bz);
        x = bx + wrinkle * Math.sin(phi) * Math.cos(theta);
        y = by + wrinkle * Math.cos(phi);
        z = bz + wrinkle * Math.sin(phi) * Math.sin(theta);
      } else if (region < 0.90) {
        const theta = Math.random() * Math.PI * 2;
        const phi   = Math.acos(2 * Math.random() - 1);
        const cx = 0.55 * Math.sin(phi) * Math.cos(theta);
        const cy = 0.28 * Math.cos(phi);
        const cz = 0.45 * Math.sin(phi) * Math.sin(theta);
        const ox = 0; const oy = -0.45; const oz = -0.7;
        const wrinkle = 0.02 * Math.sin(38.0 * (cy + oy));
        x = cx + ox + wrinkle * Math.sin(phi) * Math.cos(theta);
        y = cy + oy + wrinkle * Math.cos(phi);
        z = cz + oz + wrinkle * Math.sin(phi) * Math.sin(theta);
      } else {
        const t = Math.random(); const theta = Math.random() * Math.PI * 2;
        const yStart = -0.4; const yEnd = -1.15;
        const stemY = yStart + t * (yEnd - yStart);
        const rad = 0.16 * (1.0 - 0.55 * t);
        const nx = 0.02 * Math.sin(12.0 * stemY);
        const nz = 0.02 * Math.cos(12.0 * stemY);
        x = rad * Math.cos(theta) + nx;
        y = stemY;
        z = rad * Math.sin(theta) - 0.25 + nz;
      }

      positions[i*3] = x; positions[i*3+1] = y; positions[i*3+2] = z;
      const rollColor = Math.random();
      let col = c1;
      if (rollColor < 0.45) col = c1.clone().lerp(c2, rollColor * 2.2);
      else if (rollColor < 0.85) col = c2.clone().lerp(c3, (rollColor - 0.45) * 2.5);
      else col = Math.random() > 0.65 ? c4.clone() : c2.clone();
      colors[i*3] = col.r; colors[i*3+1] = col.g; colors[i*3+2] = col.b;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setAttribute("color",    new THREE.BufferAttribute(colors, 3));
    const particles = new THREE.Points(geo, new THREE.PointsMaterial({
      size: 0.045, vertexColors: true, transparent: true, opacity: 0.9,
      map: dotTexture, depthWrite: false, blending: THREE.NormalBlending,
    }));
    scene.add(particles);

    const cubes = [];
    const cubesGroup = new THREE.Group();
    scene.add(cubesGroup);
    const cubeCount = 5;
    for (let i = 0; i < cubeCount; i++) {
      const size = 0.06 + Math.random() * 0.14;
      const isWire = Math.random() > 0.4;
      const mat = new THREE.MeshBasicMaterial({
        color: Math.random() > 0.75 ? 0xf97316 : (Math.random() > 0.45 ? 0x38bdf8 : 0x0c0740),
        wireframe: isWire, transparent: true, opacity: isWire ? 0.25 : 0.65,
      });
      const mesh = new THREE.Mesh(new THREE.BoxGeometry(size, size, size), mat);
      const angle = Math.random() * Math.PI * 2;
      const radius = 1.35 + Math.random() * 1.5;
      const height = (Math.random() - 0.5) * 2.2;
      const speed = (0.003 + Math.random() * 0.012) * (Math.random() > 0.5 ? 1 : -1);
      const rotSpeed = { x: Math.random() * 0.02, y: Math.random() * 0.02, z: Math.random() * 0.02 };
      mesh.position.set(radius * Math.cos(angle), height, radius * Math.sin(angle));
      cubesGroup.add(mesh);
      cubes.push({ mesh, angle, radius, height, speed, rotSpeed });
    }

    const onMove = (e) => {
      mouseRef.current.x = (e.clientX / window.innerWidth - 0.5) * 1.2;
      mouseRef.current.y = (e.clientY / window.innerHeight - 0.5) * 0.8;
    };
    window.addEventListener("pointermove", onMove);

    let frame;
    const animate = (t) => {
      frame = requestAnimationFrame(animate);
      const time = t * 0.001;
      particles.rotation.y = time * 0.08 + mouseRef.current.x;
      particles.rotation.x = Math.sin(time * 0.2) * 0.06 + mouseRef.current.y;
      cubes.forEach((c) => {
        c.angle += c.speed;
        c.mesh.position.x = c.radius * Math.cos(c.angle);
        c.mesh.position.z = c.radius * Math.sin(c.angle);
        c.mesh.position.y = c.height + Math.sin(time * 0.8 + c.angle) * 0.12;
        c.mesh.rotation.x += c.rotSpeed.x; c.mesh.rotation.y += c.rotSpeed.y; c.mesh.rotation.z += c.rotSpeed.z;
      });
      renderer.render(scene, camera);
    };
    animate(0);

    const onResize = () => {
      const nW = el.clientWidth || window.innerWidth;
      const nH = el.clientHeight || window.innerHeight;
      renderer.setSize(nW, nH);
      camera.aspect = nW / nH;
      camera.updateProjectionMatrix();
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("resize", onResize);
      renderer.dispose();
      if (canvas.parentNode === el) el.removeChild(canvas);
    };
  }, []);

  return (
    <div ref={mountRef} style={{
      position: "absolute", inset: 0, pointerEvents: "none", zIndex: 1
    }} />
  );
}

function HomeScreen({ onSelect, stats, online }) {
  const [selectedModule, setSelectedModule] = useState("specter");
  const [username, setUsername] = useState("");
  const [token, setToken] = useState("");

  const handleAccessSubmit = (e) => {
    e.preventDefault();
    onSelect(selectedModule);
  };

  return (
    <div style={{
      minHeight: "100vh", display: "flex", flexDirection: "column",
      background: "#eef2f7", position: "relative", overflow: "hidden",
      fontFamily: "'Outfit', 'Inter', sans-serif"
    }}>
      <BrainHero />
      <header style={{
        position: "absolute", top: 0, left: 0, right: 0,
        padding: "20px 48px", display: "flex",
        alignItems: "center", justifyContent: "space-between",
        borderBottom: `1px solid ${T.border}`,
        background: "rgba(238, 242, 247, 0.75)", backdropFilter: "blur(20px)",
        zIndex: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 28, height: 28, borderRadius: "50%",
            background: T.orange,
            display: "flex", alignItems: "center", justifyContent: "center",
            position: "relative",
          }}>
            <div style={{
              width: 14, height: 14, borderRadius: "3px",
              background: T.t1, transform: "rotate(45deg)"
            }} />
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, letterSpacing: "1px", color: T.t1 }}>
            SPECTER<span style={{ color: T.orange, fontWeight: 400 }}>.INTEL</span>
          </div>
        </div>

        <nav style={{ display: "flex", gap: 32, alignItems: "center" }}>
          {["Home", "Dashboard", "Threat Map", "AEGIS Monitor", "Reports"].map((link) => (
            <button key={link}
              onClick={() => {
                if (link === "AEGIS Monitor") onSelect("aegis");
                else if (link !== "Home") onSelect("specter");
              }}
              style={{
                background: "none", border: "none", cursor: "pointer",
                fontSize: 13, fontWeight: 500, color: T.t2,
                transition: "color 0.15s ease",
              }}
              onMouseEnter={(e) => e.target.style.color = T.orange}
              onMouseLeave={(e) => e.target.style.color = T.t2}
            >
              {link}
            </button>
          ))}
        </nav>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
            width: 7, height: 7, borderRadius: "50%",
            background: online ? T.green : T.red,
            animation: online ? "pulse 2s infinite" : "none",
          }} />
          <span style={{ fontSize: 11, fontWeight: 700, color: online ? T.green : T.red, letterSpacing: 1 }}>
            {online ? "SYS ONLINE" : "SYS OFFLINE"}
          </span>
        </div>
      </header>

      <div style={{
        display: "grid", gridTemplateColumns: "1.1fr 0.9fr",
        gap: 48, width: "100%", maxWidth: 1280,
        margin: "0 auto", padding: "120px 48px 48px",
        minHeight: "100vh", alignItems: "center",
        zIndex: 2, position: "relative"
      }}>
        <div style={{ animation: "fadeUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) both" }}>
          <h1 style={{
            fontSize: 54, fontWeight: 800, lineHeight: 1.1,
            color: T.t1, marginBottom: 28, letterSpacing: "-1.5px"
          }}>
            Threats Evolve.<br />
            So Do We.
          </h1>

          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 32, maxWidth: 360 }}>
            {[
              { text: "Automated Defensive Response", icon: "🛡️" },
              { text: "Real-Time AI Sensor Fusion", icon: "📡" },
              { text: "Cognitive Threat Graph Intelligence", icon: "🧬" }
            ].map((p, idx) => (
              <div key={idx} style={{
                background: "rgba(255, 255, 255, 0.75)",
                backdropFilter: "blur(10px)",
                border: `1px solid ${T.border}`,
                boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)",
                borderRadius: 99, padding: "11px 22px",
                fontSize: 13, fontWeight: 600, color: T.t2,
                display: "flex", alignItems: "center", gap: 12,
                transition: "transform 0.2s ease, border-color 0.2s ease",
                cursor: "default"
              }}
              onMouseEnter={(e) => { e.currentTarget.style.transform = "translateX(5px)"; e.currentTarget.style.borderColor = T.borderMd; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = "translateX(0)"; e.currentTarget.style.borderColor = T.border; }}
              >
                <span style={{ fontSize: 16 }}>{p.icon}</span>
                {p.text}
              </div>
            ))}
          </div>

          <p style={{
            fontSize: 14.5, color: T.t2, lineHeight: 1.7,
            maxWidth: 480, marginBottom: 36
          }}>
            SPECTER.INTEL is the first agentic Counter-AI (cAI) platform, designed to sense, analyze, and respond to AI-driven cyber threats in real time. Deploy models, orchestrate defensive maneuvers, and neutralize threats before containment is compromised.
          </p>

          <div style={{ display: "flex", gap: 16 }}>
            {[
              { v: stats?.total_iocs ? stats.total_iocs.toLocaleString() : "1,842", l: "Indicators", c: T.blue },
              { v: stats?.ttps ?? "48", l: "Active TTPs", c: T.purple },
              { v: "0.985", l: "Decision Area", c: T.green },
            ].map((stat, idx) => (
              <div key={idx} style={{
                background: T.surface, border: `1px solid ${T.border}`,
                boxShadow: "0 4px 16px rgba(12, 7, 64, 0.02)",
                borderRadius: 14, padding: "14px 22px", minWidth: 120,
              }}>
                <div style={{ fontSize: 22, fontWeight: 800, color: stat.c, letterSpacing: "-0.5px" }}>{stat.v}</div>
                <div style={{ fontSize: 8.5, fontWeight: 700, color: T.t3, letterSpacing: 1.5, textTransform: "uppercase", marginTop: 4 }}>{stat.l}</div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ 
          display: "flex", flexDirection: "column", gap: 24,
          animation: "fadeUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) 0.15s both"
        }}>
          <div style={{
            background: T.surface,
            border: `1px solid ${T.border}`,
            borderRadius: 24,
            boxShadow: "0 10px 40px rgba(12, 7, 64, 0.04)",
            padding: "32px 36px",
            position: "relative"
          }}>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: T.t1, marginBottom: 6 }}>Platform Access</h2>
            <p style={{ fontSize: 13, color: T.t3, marginBottom: 24 }}>Enter credentials and choose the target node to deploy.</p>

            <form onSubmit={handleAccessSubmit} style={{ display: "flex", flexDirection: "column", gap: 18 }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 700, color: T.t2, textTransform: "uppercase", letterSpacing: 0.5 }}>Access Module</label>
                <div style={{
                  display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8,
                  background: T.raise, borderRadius: 12, padding: 4,
                  border: `1px solid ${T.border}`
                }}>
                  <button type="button"
                    onClick={() => setSelectedModule("specter")}
                    style={{
                      padding: "8px 12px", border: "none", borderRadius: 9,
                      cursor: "pointer", fontSize: 12, fontWeight: 700,
                      background: selectedModule === "specter" ? T.t1 : "transparent",
                      color: selectedModule === "specter" ? "#ffffff" : T.t2,
                      transition: "all 0.2s ease"
                    }}
                  >
                    SPECTER Intel
                  </button>
                  <button type="button"
                    onClick={() => setSelectedModule("aegis")}
                    style={{
                      padding: "8px 12px", border: "none", borderRadius: 9,
                      cursor: "pointer", fontSize: 12, fontWeight: 700,
                      background: selectedModule === "aegis" ? T.t1 : "transparent",
                      color: selectedModule === "aegis" ? "#ffffff" : T.t2,
                      transition: "all 0.2s ease"
                    }}
                  >
                    AEGIS Monitor
                  </button>
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 700, color: T.t2, textTransform: "uppercase", letterSpacing: 0.5 }}>Operator Name</label>
                <div style={{ position: "relative" }}>
                  <input type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Operator Code / Username"
                    style={{
                      width: "100%", padding: "12px 16px 12px 36px",
                      borderRadius: 12, border: `1px solid ${T.border}`,
                      fontSize: 13, background: T.raise, color: T.t1,
                      outline: "none", transition: "border-color 0.2s ease"
                    }}
                    onFocus={(e) => e.target.style.borderColor = T.t3}
                    onBlur={(e) => e.target.style.borderColor = T.border}
                  />
                  <span style={{ position: "absolute", left: 14, top: 12, fontSize: 14, color: T.t3 }}>👤</span>
                </div>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label style={{ fontSize: 11, fontWeight: 700, color: T.t2, textTransform: "uppercase", letterSpacing: 0.5 }}>Access Token</label>
                <div style={{ position: "relative" }}>
                  <input type="password"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="Enter security key"
                    style={{
                      width: "100%", padding: "12px 16px 12px 36px",
                      borderRadius: 12, border: `1px solid ${T.border}`,
                      fontSize: 13, background: T.raise, color: T.t1,
                      outline: "none", transition: "border-color 0.2s ease"
                    }}
                    onFocus={(e) => e.target.style.borderColor = T.t3}
                    onBlur={(e) => e.target.style.borderColor = T.border}
                  />
                  <span style={{ position: "absolute", left: 14, top: 12, fontSize: 14, color: T.t3 }}>🔑</span>
                </div>
              </div>

              <button type="submit"
                className="btn-primary"
                style={{
                  background: T.t1, color: "#ffffff",
                  border: "none", borderRadius: 99,
                  padding: "13px 20px", fontWeight: 700, fontSize: 13,
                  cursor: "pointer", display: "flex", alignItems: "center",
                  justifyContent: "center", gap: 6, marginTop: 8
                }}
              >
                Access Cyber battlespace <span>→</span>
              </button>
            </form>
          </div>

          <div style={{
            background: "rgba(255, 255, 255, 0.65)",
            backdropFilter: "blur(16px)",
            border: `1px solid ${T.border}`,
            borderRadius: 20,
            padding: "12px 24px",
            display: "flex", alignItems: "center", gap: 16,
            boxShadow: "0 6px 20px rgba(12, 7, 64, 0.02)"
          }}>
            <button
              onClick={() => onSelect(selectedModule)}
              style={{
                width: 38, height: 38, borderRadius: "50%",
                background: T.t1, border: "none", display: "flex",
                alignItems: "center", justifyContent: "center", cursor: "pointer",
                boxShadow: "0 4px 10px rgba(12,7,64,0.15)",
                transition: "transform 0.2s"
              }}
              onMouseEnter={(e) => e.currentTarget.style.transform = "scale(1.08)"}
              onMouseLeave={(e) => e.currentTarget.style.transform = "scale(1.00)"}
            >
              <div style={{
                width: 0, height: 0,
                borderTop: "5px solid transparent",
                borderBottom: "5px solid transparent",
                borderLeft: "8px solid #ffffff",
                marginLeft: 3
              }} />
            </button>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: T.t1 }}>Sense. Analyze and Respond.</div>
              <div style={{ fontSize: 10, color: T.t3 }}>SPECTER Real-Time Node Ingestion Control</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Sidebar({ mode, page, onPage, onHome, stats, aegisScore, aegisStatus }) {
  const isAegis = mode === "aegis";
  const accent  = isAegis ? T.green : T.blue;

  const NAV = isAegis
    ? [{ id: "aegis", label: "Live Monitor", icon: "◉" }]
    : [
        { id: "dashboard", label: "Dashboard",  icon: "◈" },
        { id: "graph",     label: "Threat Map", icon: "⬡" },
        { id: "ingest",    label: "Ingest",     icon: "⊕" },
        { id: "reports",   label: "Reports",    icon: "◫" },
      ];

  const scoreColor = aegisScore >= 75 ? T.red
    : aegisScore >= 50 ? T.amber
    : aegisScore >= 20 ? "#ffd700"
    : T.green;

  return (
    <div style={{
      width: 220, 
      background: "rgba(255, 255, 255, 0.75)",
      backdropFilter: "blur(18px)",
      borderRight: `1px solid ${T.border}`,
      display: "flex", flexDirection: "column", flexShrink: 0,
      fontFamily: "'Outfit', 'Inter', sans-serif"
    }}>
      <div style={{ padding: "24px 20px 20px", borderBottom: `1px solid ${T.border}` }}>
        <button onClick={onHome} style={{
          background: "none", border: "none", cursor: "pointer",
          display: "flex", alignItems: "center", gap: 10, padding: 0, marginBottom: 14,
        }}>
          <div style={{
            width: 26, height: 26, borderRadius: "50%",
            background: T.orange,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <div style={{
              width: 12, height: 12, borderRadius: "2px",
              background: "#ffffff", transform: "rotate(45deg)"
            }} />
          </div>
          <div style={{ textAlign: "left" }}>
            <div style={{ fontSize: 13, fontWeight: 800, letterSpacing: 0.5, color: T.t1 }}>SPECTER</div>
            <div style={{ fontSize: 8.5, color: T.t3, letterSpacing: 0.5, textTransform: "uppercase" }}>
              {isAegis ? "Active Defense" : "Threat Intel"}
            </div>
          </div>
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 5, height: 5, borderRadius: "50%", background: T.green, animation: "pulse 2s infinite" }} />
          <span style={{ fontSize: 9, fontWeight: 700, color: T.green, letterSpacing: 1 }}>SYS ACTIVE</span>
        </div>
      </div>

      {!isAegis && stats && (
        <div style={{ padding: "16px 20px", borderBottom: `1px solid ${T.border}` }}>
          <div style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 1.5, color: T.t3, marginBottom: 10, textTransform: "uppercase" }}>
            Live Telemetry
          </div>
          {[
            { k: "Active IOCs",  v: stats.active_iocs,    c: T.red    },
            { k: "Critical",     v: stats.critical_iocs,  c: T.amber  },
            { k: "TTPs Mapped",  v: stats.ttps,           c: T.purple },
            { k: "Threat Actors",v: stats.actors ?? 0,    c: T.t2     },
          ].map(s => (
            <div key={s.k} style={{
              display: "flex", justifyContent: "space-between",
              alignItems: "center", marginBottom: 6,
            }}>
              <span style={{ fontSize: 10.5, color: T.t2 }}>{s.k}</span>
              <span style={{ fontSize: 12.5, fontWeight: 700, color: s.c }}>{(s.v ?? 0).toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}

      {isAegis && (
        <div style={{ padding: "16px 20px", borderBottom: `1px solid ${T.border}` }}>
          <div style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 1.5, color: T.t3, marginBottom: 8, textTransform: "uppercase" }}>
            Host Risk Score
          </div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 8 }}>
            <span style={{ fontSize: 32, fontWeight: 950, letterSpacing: -1, color: scoreColor, lineHeight: 1 }}>
              {aegisScore.toFixed(0)}
            </span>
            <span style={{ fontSize: 13, color: T.t3 }}>/100</span>
          </div>
          <div style={{ height: 4, background: T.raise, borderRadius: 2, marginBottom: 8, overflow: "hidden" }}>
            <div style={{
              height: "100%", width: `${aegisScore}%`,
              background: `linear-gradient(90deg, ${T.green}, ${T.amber}, ${T.red})`,
              transition: "width 0.4s ease",
            }} />
          </div>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 5,
            background: `${scoreColor}12`, border: `1px solid ${scoreColor}25`,
            borderRadius: 6, padding: "3px 8px",
            fontSize: 9, fontWeight: 700, color: scoreColor, letterSpacing: 1,
          }}>
            {aegisStatus === "KILL_FIRED" ? "PROCESS KILLED"
             : aegisStatus === "CRITICAL"  ? "CRITICAL ALERT"
             : aegisStatus === "WARNING"   ? "RISK WARNING"
             : "STABLE SECURITY"}
          </div>
        </div>
      )}

      <div style={{ padding: "12px 0", flex: 1, display: "flex", flexDirection: "column", justifySelf: "stretch" }}>
        {NAV.map(n => (
          <button key={n.id}
            className="nav-link"
            onClick={() => onPage(n.id)}
            style={{
              display: "flex", alignItems: "center", gap: 10,
              width: "100%", padding: "10px 20px",
              background: page === n.id ? `${accent}10` : "transparent",
              borderLeft: `3px solid ${page === n.id ? accent : "transparent"}`,
              borderTop: "none", borderBottom: "none", borderRight: "none",
              cursor: "pointer", fontSize: 12, fontWeight: 700,
              color: page === n.id ? accent : T.t2,
              textAlign: "left", transition: "all 0.15s ease"
            }}>
            <span style={{ fontSize: 14, color: page === n.id ? accent : T.t3 }}>{n.icon}</span>
            {n.label}
          </button>
        ))}

        <div style={{ margin: "auto 14px 14px" }}>
          <button
            onClick={() => onPage(isAegis ? "specter" : "aegis")}
            style={{
              width: "100%", background: T.surface,
              border: `1px solid ${T.border}`, borderRadius: 12,
              padding: "10px 12px", cursor: "pointer",
              display: "flex", alignItems: "center", gap: 10,
              boxShadow: "0 2px 8px rgba(12,7,64,0.02)",
              transition: "border-color 0.2s"
            }}
            onMouseEnter={(e) => e.currentTarget.style.borderColor = T.borderMd}
            onMouseLeave={(e) => e.currentTarget.style.borderColor = T.border}
          >
            <span style={{ fontSize: 14, color: isAegis ? T.blue : T.green }}>
              {isAegis ? "◈" : "◉"}
            </span>
            <div style={{ textAlign: "left" }}>
              <div style={{ fontSize: 8, color: T.t3, letterSpacing: 1.5, marginBottom: 1 }}>SWITCH ACTIVE NODE</div>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: isAegis ? T.blue : T.green }}>
                {isAegis ? "SPECTER Intel" : "AEGIS Intercept"}
              </div>
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [mode,       setMode]       = useState("home");
  const [page,       setPage]       = useState("dashboard");
  const [stats,      setStats]      = useState(null);
  const [online,     setOnline]     = useState(null);
  const [aegisScore, setAegisScore] = useState(0);
  const [aegisStatus,setAegisStatus]= useState("NORMAL");

  const fetchStats = () =>
    api.get("/api/stats").then(setStats).catch(() => {});

  useEffect(() => {
    fetch("http://localhost:8000/health")
      .then(r => { if (r.ok) { setOnline(true); fetchStats(); } else setOnline(false); })
      .catch(() => setOnline(false));
    const t = setInterval(fetchStats, 15000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (mode !== "aegis") return;
    const t = setInterval(async () => {
      try {
        const d = await fetch("http://localhost:8001/aegis/score").then(r => r.json());
        setAegisScore(d.total || 0);
        setAegisStatus(d.status || "NORMAL");
      } catch { }
    }, 800);
    return () => clearInterval(t);
  }, [mode]);

  const enterMode = (m) => {
    setMode(m);
    setPage(m === "specter" ? "dashboard" : "aegis");
  };

  const handlePageSwitch = (p) => {
    if (p === "specter") { setMode("specter"); setPage("dashboard"); return; }
    if (p === "aegis")   { setMode("aegis");   setPage("aegis");     return; }
    setPage(p);
  };

  useEffect(() => {
    const el = document.createElement("style");
    el.textContent = GLOBAL_CSS;
    document.head.appendChild(el);
    return () => el.remove();
  }, []);

  if (mode === "home") {
    return <HomeScreen onSelect={enterMode} stats={stats} online={online === true} />;
  }

  const isAegis = mode === "aegis";

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden", background: "#eef2f7" }}>
      <Sidebar
        mode={mode} page={page}
        onPage={handlePageSwitch}
        onHome={() => setMode("home")}
        stats={stats}
        aegisScore={aegisScore}
        aegisStatus={aegisStatus}
      />
      <main style={{ flex: 1, overflow: "auto", background: T.bg, animation: "fadeIn 0.2s ease" }}>
        {!isAegis && page === "dashboard" && <Dashboard stats={stats} onRefresh={fetchStats} />}
        {!isAegis && page === "graph"     && <GraphView />}
        {!isAegis && page === "ingest"    && <Ingest onIngested={fetchStats} />}
        {!isAegis && page === "reports"   && <Reports />}
        {isAegis  && page === "aegis"     && <AEGISDashboard />}
      </main>
    </div>
  );
}
