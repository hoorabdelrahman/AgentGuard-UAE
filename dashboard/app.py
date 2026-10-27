"""AgentGuard UAE — Edgy Tactical AI Defense Dashboard (Streamlit).
Run: streamlit run dashboard/app.py
"""
import json
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402
import streamlit.components.v1 as components  # noqa: E402

import config  # noqa: E402
from gateway import audit, report  # noqa: E402

st.set_page_config(
    page_title="AGENT//GUARD UAE — Tactical HUD",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

GW = config.GATEWAY_URL
ADMIN = {"X-Admin-Key": config.ADMIN_KEY}
BACKUP = config.DATA_DIR / "tamper_backup.json"

# ---------------------------------------------------------------- tactical styling
TACTICAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&family=Inter:wght@400;600;700;900&display=swap');

:root {
  --neon-cyan: #00f0ff;
  --neon-emerald: #10b981;
  --neon-rose: #ff0055;
  --neon-amber: #f59e0b;
}

/* Global Dark HUD Theme */
.stApp {
    background-color: #05070a !important;
    background-image: 
        linear-gradient(to right, rgba(0, 240, 255, 0.035) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(0, 240, 255, 0.035) 1px, transparent 1px) !important;
    background-size: 30px 30px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* Sidebar Styling */
[data-testid="stSidebar"] {
    background-color: #070a10 !important;
    border-right: 1px solid rgba(0, 240, 255, 0.2) !important;
}
[data-testid="stSidebar"] * {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Tactical Corner Brackets for Metric Cards */
[data-testid="stMetric"] {
    background: rgba(10, 14, 23, 0.85) !important;
    border: 1px solid rgba(0, 240, 255, 0.22) !important;
    padding: 12px 14px !important;
    border-radius: 1px !important;
    box-shadow: 0 0 15px rgba(0, 240, 255, 0.06) !important;
    position: relative !important;
    transition: all 0.2s ease !important;
}
[data-testid="stMetric"]:hover {
    border-color: rgba(0, 240, 255, 0.5) !important;
    box-shadow: 0 0 20px rgba(0, 240, 255, 0.15) !important;
}
[data-testid="stMetric"]::before {
    content: '';
    position: absolute;
    top: -1px; left: -1px; width: 6px; height: 6px;
    border-top: 2px solid #00f0ff;
    border-left: 2px solid #00f0ff;
}
[data-testid="stMetric"]::after {
    content: '';
    position: absolute;
    bottom: -1px; right: -1px; width: 6px; height: 6px;
    border-bottom: 2px solid #00f0ff;
    border-right: 2px solid #00f0ff;
}
[data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace !important;
    color: #00f0ff !important;
    font-weight: 800 !important;
    letter-spacing: -0.02em !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'JetBrains Mono', monospace !important;
    color: #94a3b8 !important;
    font-size: 0.72rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
}

/* Tactical Buttons */
.stButton > button {
    background: rgba(15, 23, 42, 0.8) !important;
    color: #00f0ff !important;
    border: 1px solid rgba(0, 240, 255, 0.4) !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
    border-radius: 1px !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background: rgba(0, 240, 255, 0.18) !important;
    border-color: #00f0ff !important;
    box-shadow: 0 0 18px rgba(0, 240, 255, 0.5) !important;
    color: #ffffff !important;
}

/* Tactical Tabs */
.stTabs [data-baseweb="tab-list"] {
    background-color: transparent !important;
    border-bottom: 1px solid rgba(0, 240, 255, 0.2) !important;
    gap: 6px !important;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    font-size: 0.82rem !important;
    color: #94a3b8 !important;
    background: rgba(10, 14, 23, 0.6) !important;
    border: 1px solid rgba(56, 189, 248, 0.15) !important;
    border-bottom: none !important;
    border-radius: 1px 1px 0 0 !important;
    padding: 8px 16px !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
}
.stTabs [aria-selected="true"] {
    color: #00f0ff !important;
    background: rgba(0, 240, 255, 0.12) !important;
    border-color: #00f0ff !important;
    border-bottom: 2px solid #00f0ff !important;
    box-shadow: 0 -2px 12px rgba(0, 240, 255, 0.25) !important;
}

/* Dataframe & Tables */
[data-testid="stDataFrame"], [data-testid="stTable"] {
    border: 1px solid rgba(0, 240, 255, 0.2) !important;
    background: rgba(10, 14, 23, 0.8) !important;
    border-radius: 1px !important;
}

/* Expander Containers */
[data-testid="stExpander"] {
    border: 1px solid rgba(0, 240, 255, 0.2) !important;
    background: rgba(10, 14, 23, 0.7) !important;
}

/* Custom Scrollbars */
::-webkit-scrollbar {
    width: 5px;
    height: 5px;
}
::-webkit-scrollbar-track {
    background: #05070a;
}
::-webkit-scrollbar-thumb {
    background: #1e293b;
    border-radius: 1px;
}
::-webkit-scrollbar-thumb:hover {
    background: #00f0ff;
}
</style>
"""
st.markdown(TACTICAL_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------- data helpers
def conn():
    if not config.DB_PATH.exists():
        return None
    c = sqlite3.connect(f"file:{config.DB_PATH}?mode=ro", uri=True, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def gw_get(path, **kw):
    try:
        return httpx.get(GW + path, timeout=15, **kw).json()
    except Exception:
        return None


def gw_post(path, body=None):
    try:
        return httpx.post(GW + path, json=body, headers=ADMIN, timeout=60).json()
    except Exception as e:
        return {"error": str(e)}


def load_events(limit=2000):
    c = conn()
    if not c:
        return pd.DataFrame()
    evs = audit.events(c, limit=limit)
    c.close()
    return pd.DataFrame(evs)


def chips(e):
    """Compact pipeline strip with tactical formatting."""
    if e.get("final_decision") == "rejected":
        return f"🔒 Credential ✗ ({e.get('policy_code')})"
    s = "ID ✓ → Task ✓ → "
    s += "Policy ✓" if e.get("policy_decision") == "allowed" else f"⛔ Policy ✗ ({e.get('policy_code')})"
    ml = e.get("ml_decision")
    if e.get("policy_decision") == "allowed":
        s += " → ML ✓" if ml in ("normal", "disabled", "unavailable") else f" → ⚠ ML ✗ ({ml})"
    fd = e.get("final_decision")
    if e.get("parent_event_id") and fd == "allowed":
        s += " → ⚡ Revalidated ✓ → Executed"
    elif fd == "allowed":
        s += " → ⚡ Executed"
    elif fd in ("denied", "held"):
        s += " → " + ("⏳ Held for review" if fd == "held" else "🛑 Blocked") + " → 🛠️ Corrected"
    return s


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("""
    <div style="padding: 10px 0; border-bottom: 1px solid rgba(0, 240, 255, 0.2); margin-bottom: 12px;">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 1.4rem;">🛡️</span>
        <div>
          <div style="font-size: 1rem; font-weight: 900; color: #00f0ff; letter-spacing: 0.08em;">AGENT//GUARD</div>
          <div style="font-size: 0.68rem; color: #64748b; letter-spacing: 0.05em;">AUTONOMOUS SWARM DEFENSE</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    health = gw_get("/health")
    if health:
        st.markdown("""
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); padding: 8px 12px; font-size: 0.75rem; margin-bottom: 10px;">
          <div style="color: #10b981; font-weight: 700; display: flex; align-items: center; gap: 6px;">
            <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10b981;"></span>
            GATEWAY ONLINE [NODE-ALPHA]
          </div>
          <div style="color: #94a3b8; font-size: 0.7rem; margin-top: 4px;">
            ML: <span style="color: #00f0ff;">""" + ('LOADED' if health['ml_model_loaded'] else 'MISSING') + """</span> · 
            LLM: <span style="color: #00f0ff;">""" + (str(health['llm_provider']).upper() if health['llm_enabled'] else 'OFF (RULES)') + """</span>
          </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="background: rgba(255, 0, 85, 0.15); border: 1px solid rgba(255, 0, 85, 0.5); padding: 8px 12px; font-size: 0.75rem; color: #ff0055; font-weight: bold; margin-bottom: 10px;">
          ⚠ GATEWAY DISCONNECTED ({GW})
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='font-size: 0.75rem; font-weight: 700; color: #00f0ff; margin-top: 15px; margin-bottom: 5px;'>DEMO CONTROLS</div>", unsafe_allow_html=True)
    scen = st.selectbox("Scenario", ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10"], index=5,
                        format_func=lambda x: {"S1": "S1 normal work", "S2": "S2 forged identity", "S3": "S3 credential abuse",
                                               "S4": "S4 prohibited tool", "S5": "S5 wrong case", "S6": "S6 injection → corrected",
                                               "S7": "S7 stubborn → quarantine", "S8": "S8 data harvesting (ML)",
                                               "S9": "S9 PII in report", "S10": "S10 audit tampering"}[x])

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        if st.button("▶ EXECUTE"):
            with st.spinner(f"Running {scen} ..."):
                p = subprocess.run([sys.executable, "-m", "scenarios.run_all", "--only", scen, "--no-reset"],
                                   cwd=ROOT, capture_output=True, text=True, timeout=300)
            st.session_state["last_run"] = (p.stdout + p.stderr)[-3000:]
            st.rerun()

    with col_s2:
        if st.button("⟲ RESET"):
            st.session_state["reset"] = gw_post("/admin/reset")
            st.rerun()

    if "reset" in st.session_state:
        st.caption(f"reset: {st.session_state['reset']}")

    st.markdown("<hr style='border: none; border-top: 1px solid rgba(0, 240, 255, 0.15); margin: 15px 0;'>", unsafe_allow_html=True)

    # Tactical Emergency Kill Switch
    st.markdown("""
    <div style="font-size: 0.72rem; font-weight: 700; color: #ff0055; margin-bottom: 4px;">EMERGENCY AIR-GAP</div>
    """, unsafe_allow_html=True)
    if st.button("🚨 EMERGENCY KILL-SWITCH", help="Instantly revokes tokens, halts swarms, and resets demo state."):
        gw_post("/admin/reset")
        st.error("🚨 EMERGENCY KILL-SWITCH ACTIVATED: Swarm tokens revoked, gateway reset.")
        st.rerun()

    if "last_run" in st.session_state:
        with st.expander("TERMINAL LOG OUTPUT", expanded=True):
            st.code(st.session_state["last_run"])


# ---------------------------------------------------------------- top tactical header
utc_str = datetime.utcnow().strftime("%H:%M:%S UTC")
st.markdown(f"""
<div style="background: rgba(10, 14, 23, 0.9); border: 1px solid rgba(0, 240, 255, 0.28); border-left: 4px solid #00f0ff; padding: 12px 18px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
  <div>
    <div style="display: flex; align-items: center; gap: 10px;">
      <span style="font-size: 1.25rem; font-weight: 900; color: #00f0ff; letter-spacing: 0.12em;">AGENT<span style="color: #ff0055;">//</span>GUARD TACTICAL HUD</span>
      <span style="background: rgba(0, 240, 255, 0.12); border: 1px solid rgba(0, 240, 255, 0.4); padding: 2px 6px; font-size: 0.65rem; color: #00f0ff; font-weight: bold;">UAE-ALPHA</span>
      <span style="background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.4); padding: 2px 6px; font-size: 0.65rem; color: #f59e0b; font-weight: bold;">DEFCON 2</span>
    </div>
    <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 4px; letter-spacing: 0.05em;">
      ED25519 ZERO-TRUST GATEWAY &bull; ML DRIFT MONITORING &bull; CORRECTIVE INTERCEPTION &bull; TAMPER-PROOF WAL
    </div>
  </div>
  <div style="display: flex; align-items: center; gap: 14px; font-size: 0.72rem; color: #94a3b8;">
    <span>TIME: <strong style="color: #00f0ff;">{utc_str}</strong></span>
    <span>STATUS: <strong style="color: #10b981;">ENFORCING</strong></span>
  </div>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------- radar canvas helper
def render_tactical_radar():
    radar_html = """
    <div style="background: #05070a; border: 1px solid rgba(0,240,255,0.25); position: relative; width: 100%; height: 180px; overflow: hidden; margin-bottom: 12px;">
      <canvas id="rCanvas" width="400" height="180" style="width: 100%; height: 100%;"></canvas>
      <div style="position: absolute; top: 6px; left: 8px; font-family: monospace; font-size: 10px; color: #00f0ff; pointer-events: none;">
        RADAR: VECTOR DRIFT [60 FPS]
      </div>
      <div style="position: absolute; bottom: 6px; right: 8px; font-family: monospace; font-size: 10px; color: #64748b; pointer-events: none;">
        ISOLATION-FOREST: ACTIVE
      </div>
    </div>
    <script>
      const c = document.getElementById('rCanvas');
      const ctx = c.getContext('2d');
      let angle = 0;
      const blips = [
        { a: 0.7, d: 35, col: '#10b981', lbl: 'AG-01' },
        { a: 2.3, d: 50, col: '#10b981', lbl: 'AG-04' },
        { a: 3.8, d: 65, col: '#f59e0b', lbl: 'AG-09' },
        { a: 5.1, d: 78, col: '#ff0055', lbl: 'AG-07 [ALERT]' }
      ];
      function draw() {
        ctx.clearRect(0, 0, c.width, c.height);
        const cx = c.width / 2;
        const cy = c.height / 2;
        const maxR = 80;

        // rings
        ctx.strokeStyle = 'rgba(0, 240, 255, 0.15)';
        ctx.lineWidth = 1;
        for (let r = 25; r <= maxR; r += 25) {
          ctx.beginPath();
          ctx.arc(cx, cy, r, 0, Math.PI * 2);
          ctx.stroke();
        }

        // safe ring
        ctx.strokeStyle = 'rgba(16, 185, 129, 0.3)';
        ctx.beginPath();
        ctx.arc(cx, cy, 60, 0, Math.PI * 2);
        ctx.stroke();

        // crosshairs
        ctx.beginPath();
        ctx.moveTo(cx - maxR, cy); ctx.lineTo(cx + maxR, cy);
        ctx.moveTo(cx, cy - maxR); ctx.lineTo(cx, cy + maxR);
        ctx.stroke();

        // sweep
        ctx.save();
        ctx.translate(cx, cy);
        ctx.rotate(angle);
        const g = ctx.createLinearGradient(0, 0, maxR, 0);
        g.addColorStop(0, 'rgba(0, 240, 255, 0.6)');
        g.addColorStop(1, 'rgba(0, 240, 255, 0.0)');
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.arc(0, 0, maxR, -0.3, 0);
        ctx.fillStyle = 'rgba(0, 240, 255, 0.08)';
        ctx.fill();
        ctx.strokeStyle = 'rgba(0, 240, 255, 0.8)';
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(maxR, 0);
        ctx.stroke();
        ctx.restore();

        // blips
        blips.forEach(b => {
          const bx = cx + Math.cos(b.a) * b.d;
          const by = cy + Math.sin(b.a) * b.d;
          ctx.beginPath();
          ctx.arc(bx, by, 3, 0, Math.PI * 2);
          ctx.fillStyle = b.col;
          ctx.shadowColor = b.col;
          ctx.shadowBlur = 6;
          ctx.fill();
          ctx.shadowBlur = 0;
          ctx.font = '8px monospace';
          ctx.fillStyle = b.col;
          ctx.fillText(b.lbl, bx + 5, by - 2);
        });

        angle += 0.03;
        requestAnimationFrame(draw);
      }
      draw();
    </script>
    """
    components.html(radar_html, height=195)


# ---------------------------------------------------------------- header + live KPIs
@st.fragment(run_every=3)
def live():
    c = conn()
    if not c:
        st.warning("No database yet. Run: python -m scripts.init_db")
        return
    stats = report.compute_stats(c)
    agents = pd.DataFrame([dict(r) for r in c.execute("SELECT agent_id,name,role,platform,status FROM agents")])
    exf = c.execute("SELECT COUNT(*) n, COALESCE(SUM(records),0) r FROM exfil_log WHERE mode='guard'").fetchone()
    pend = c.execute("SELECT COUNT(*) FROM human_queue WHERE status='pending'").fetchone()[0]
    c.close()
    ver = gw_get("/audit/verify") or {}
    quar = int((agents["status"] == "quarantined").sum()) if len(agents) else 0

    k = st.columns(6)
    k[0].metric("SWARM ACTIVE / ISOLATED", f"{len(agents) - quar} / {quar}")
    k[1].metric("ACTIONS PERMITTED / BLOCKED", f"{stats['allowed']} / {stats['denied'] + stats['held']}")
    k[2].metric("CORRECTIVE SELF-HEALED", f"{stats['chains_recovered_by_correction']} of {stats['violation_chains']}")
    k[3].metric("TIME TO QUARANTINE", "-" if stats["mean_time_to_quarantine_s"] is None else f"{stats['mean_time_to_quarantine_s']} s")
    k[4].metric("LATENCY P50 / P95", "-" if stats["latency_ms_p50"] is None else f"{stats['latency_ms_p50']} / {stats['latency_ms_p95']} ms")
    k[5].metric("EXFILTRATED RECORDS", int(exf["r"]), help="Records that left to non-approved destinations while protected by the gateway.")

    # Status strip
    chain_status = ver.get("chain_ok")
    chain_msg = "✅ AUDIT CHAIN VERIFIED [CRYPTOGRAPHIC MERKLE SEAL OK]" if chain_status else (f"❌ CHAIN BROKEN AT ROW {ver.get('first_broken_row')}" if ver else "—")
    st.markdown(f"""
    <div style="background: rgba(10, 14, 23, 0.7); border: 1px solid rgba(0, 240, 255, 0.18); padding: 6px 12px; margin: 10px 0; font-size: 0.75rem; display: flex; justify-content: space-between; align-items: center;">
      <span style="color: {'#10b981' if chain_status else '#ff0055'}; font-weight: bold;">{chain_msg}</span>
      <span style="color: #64748b;">{ver.get('rows_checked', 0)} AUDIT EVENTS SEALED &bull; <strong style="color: #f59e0b;">{pend}</strong> PENDING HUMAN REVIEWS</span>
    </div>
    """, unsafe_allow_html=True)

    left, right = st.columns([1, 2])
    with left:
        st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #00f0ff; margin-bottom: 6px;'>🛰️ TACTICAL RADAR & AGENT SWARM</div>", unsafe_allow_html=True)
        render_tactical_radar()
        if len(agents):
            agents["status"] = agents["status"].map(lambda s: "🟥 QUARANTINED" if s == "quarantined" else "🟩 VERIFIED ACTIVE")
            st.dataframe(agents, hide_index=True, height=220)
    with right:
        st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #00f0ff; margin-bottom: 6px;'>💻 LIVE ACTION STREAM // HUD</div>", unsafe_allow_html=True)
        df = load_events(300)
        if len(df):
            rows = []
            for e in df[df["event_type"].isin(["ACTION", "QUARANTINE", "HUMAN_REVIEW", "AGENT_RELEASED"])].head(25).to_dict("records"):
                e = {k: (None if (isinstance(v, float) and pd.isna(v)) else v) for k, v in e.items()}
                if e["event_type"] == "ACTION":
                    rows.append({"time": e["ts"][11:23], "agent": e.get("agent_id"), "tool": e.get("tool_name"),
                                 "pipeline": chips(e), "result": e.get("final_decision"), "retry": e.get("correction_attempt")})
                else:
                    rows.append({"time": e["ts"][11:23], "agent": e.get("agent_id"), "tool": "—",
                                 "pipeline": f"{e['event_type']}: {e.get('reason') or e.get('decision') or ''}", "result": "", "retry": None})
            st.dataframe(pd.DataFrame(rows), hide_index=True, height=420)


live()

tab_inc, tab_q, tab_audit, tab_cmp = st.tabs([
    "🔎 [01 // INCIDENT DETAIL]",
    "🧑‍⚖️ [02 // HUMAN REVIEW QUEUE]",
    "📜 [03 // AUDIT & AI REPORT]",
    "📊 [04 // BENCHMARK EVALUATION]"
])

# ---------------------------------------------------------------- incident detail
with tab_inc:
    df = load_events(3000)
    if df.empty or "final_decision" not in df:
        st.info("No incidents yet. Run scenario S6 from the sidebar to inspect an attack interception.")
    else:
        acts = df[df["event_type"] == "ACTION"]
        roots = acts[(acts["parent_event_id"].isna()) & (acts["final_decision"].isin(["denied", "held"]))]
        if roots.empty:
            st.info("No blocked actions yet. Run scenario S6 from the sidebar.")
        else:
            opts = {f"{r.ts[11:23]} · {r.agent_id} · {r.tool_name} · {r.policy_code}": r.event_id for r in roots.itertuples()}
            pick = st.selectbox("Pick an intercepted incident", list(opts))
            root = acts[acts["event_id"] == opts[pick]].iloc[0]
            kids = acts[acts["parent_event_id"] == opts[pick]].sort_values("correction_attempt")

            # Tactical Side-by-Side Comparison Box
            st.markdown(f"""
            <div style="background: rgba(10, 14, 23, 0.85); border: 1px solid rgba(0, 240, 255, 0.25); padding: 14px; margin: 10px 0;">
              <div style="font-size: 0.85rem; font-weight: bold; color: #00f0ff; margin-bottom: 8px;">
                INCIDENT TRACE: {root.tool_name} &bull; AGENT: <span style="color: #ff0055;">{root.agent_id}</span> &bull; CASE: {root.case_id}
              </div>
              <div style="font-size: 0.75rem; color: #94a3b8; margin-bottom: 12px;">
                POLICY DECISION: <strong style="color: #ff0055;">{root.policy_decision.upper()}</strong> (CODE: {root.policy_code}) &bull; 
                REASON: {root.policy_reason}
              </div>
            </div>
            """, unsafe_allow_html=True)

            c_raw, c_rewrite = st.columns(2)
            with c_raw:
                st.markdown("""
                <div style="background: rgba(255, 0, 85, 0.1); border: 1px solid rgba(255, 0, 85, 0.4); padding: 8px 12px; margin-bottom: 6px; font-size: 0.75rem; font-weight: bold; color: #ff0055;">
                  ⛔ INTERCEPTED RAW PAYLOAD [UNSAFE]
                </div>
                """, unsafe_allow_html=True)
                st.code(root.action or "")

            with c_rewrite:
                st.markdown("""
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.4); padding: 8px 12px; margin-bottom: 6px; font-size: 0.75rem; font-weight: bold; color: #10b981;">
                  ⚡ CORRECTIVE LLM REWRITE [AUTO-SANITIZED]
                </div>
                """, unsafe_allow_html=True)
                if isinstance(root.correction_recommendation, str):
                    st.code(f"Recommendation: {root.correction_recommendation}\nRevised: {root.revised_action or 'N/A'}")
                else:
                    st.code("No corrective revision available.")

            if isinstance(root.ml_decision, str) and root.ml_decision != "skipped":
                st.markdown(f"**ML Anomaly Detector**: `{root.ml_decision}` (score: {root.ml_score})")

            st.markdown("<div style='font-size: 0.8rem; font-weight: bold; color: #00f0ff; margin-top: 10px;'>REVALIDATION & RETRY EXECUTION TRACE:</div>", unsafe_allow_html=True)
            for k in kids.itertuples():
                icon = "✅" if k.final_decision == "allowed" else "⛔"
                st.markdown(f"**Retry #{k.correction_attempt}** {icon} `{k.tool_name}` → **{k.final_decision}** ({k.policy_code or 'PASSED POLICY + ML'})")

            ok = (kids["final_decision"] == "allowed").any() if len(kids) else False
            q = df[(df["event_type"] == "QUARANTINE") & (df["jti"] == root.jti)]
            if ok:
                st.success("Outcome: The unsafe action was blocked; the self-corrected action passed full revalidation and executed safely.")
            elif len(q):
                st.error(f"Outcome: Agent quarantined — {q.iloc[0].reason}")
            else:
                st.warning("Outcome: Blocked; no safe alternative executed yet.")

# ---------------------------------------------------------------- human queue
with tab_q:
    c = conn()
    rows = [dict(r) for r in c.execute("SELECT * FROM human_queue ORDER BY id DESC LIMIT 50")] if c else []
    if not rows:
        st.info("Queue is empty. Scenarios S7 and S8 create items (reassigned tasks and held actions).")
    for r in rows:
        with st.container(border=True):
            st.markdown(f"**#{r['id']} · {r['kind']}** · agent `{r['agent_id']}` · case `{r['case_id']}` · reason `{r['reason']}` · status **{r['status']}**")
            if r["status"] == "pending":
                a, b2, _ = st.columns([1, 1, 4])
                if r["kind"] == "held_action":
                    if a.button("Approve & execute", key=f"ap{r['id']}"):
                        st.write(gw_post(f"/admin/human_queue/{r['id']}/decision", {"decision": "approve", "by": "dashboard"}))
                        st.rerun()
                    if b2.button("Reject", key=f"rj{r['id']}"):
                        st.write(gw_post(f"/admin/human_queue/{r['id']}/decision", {"decision": "reject", "by": "dashboard"}))
                        st.rerun()
                else:
                    if a.button("Mark task completed", key=f"cp{r['id']}"):
                        st.write(gw_post(f"/admin/human_queue/{r['id']}/decision", {"decision": "complete", "by": "dashboard"}))
                        st.rerun()
                    if b2.button("Release agent", key=f"rl{r['id']}"):
                        st.write(gw_post(f"/admin/release/{r['agent_id']}"))
                        st.rerun()

# ---------------------------------------------------------------- audit + AI report
with tab_audit:
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("<div style='font-size: 0.85rem; font-weight: bold; color: #00f0ff; margin-bottom: 6px;'>🔒 CRYPTOGRAPHIC TAMPER DEMO</div>", unsafe_allow_html=True)
        if st.button("VERIFY SHA-256 AUDIT CHAIN"):
            st.json(gw_get("/audit/verify"))
        c = conn()
        n = c.execute("SELECT COUNT(*) FROM audit").fetchone()[0] if c else 0
        row = st.number_input("Audit row to tamper with (demo)", min_value=1, max_value=max(1, n), value=min(4, max(1, n)))
        t1, t2 = st.columns(2)
        if t1.button("😈 Tamper with this row"):
            import db
            with db.session() as w:
                body = w.execute("SELECT body FROM audit WHERE id=?", (int(row),)).fetchone()["body"]
                BACKUP.write_text(json.dumps({"id": int(row), "body": body}))
                w.execute("UPDATE audit SET body=? WHERE id=?", (body.replace("agent_", "agent_X", 1) if "agent_" in body else body + " ", int(row)))
            st.warning("Row modified directly in the database. Now click 'VERIFY SHA-256 AUDIT CHAIN'.")
        if t2.button("↩ Undo tamper") and BACKUP.exists():
            import db
            b = json.loads(BACKUP.read_text())
            with db.session() as w:
                w.execute("UPDATE audit SET body=? WHERE id=?", (b["body"], b["id"]))
            st.success("Restored.")
    with c2:
        st.markdown("<div style='font-size: 0.85rem; font-weight: bold; color: #00f0ff; margin-bottom: 6px;'>🤖 RETROSPECTIVE AUDIT LLM</div>", unsafe_allow_html=True)
        qs = gw_get("/report/questions") or {}
        qid = st.selectbox("Question", list(qs), format_func=lambda k: qs[k]) if qs else None
        if qid and st.button("ASK AUDIT LLM"):
            with st.spinner("Analysing audit records ..."):
                ans = gw_get(f"/report/ask?q={qid}")
            if ans:
                st.write(ans["answer"])
                st.caption(f"written by: {ans['source']} (facts are computed from the log, not by the LLM)")
                with st.expander("Facts used"):
                    st.json(ans["facts"])

    st.markdown("<div style='font-size: 0.85rem; font-weight: bold; color: #00f0ff; margin-top: 15px; margin-bottom: 6px;'>⬇ FORENSIC EXPORTS</div>", unsafe_allow_html=True)
    df = load_events(5000)
    if len(df):
        c_exp1, c_exp2 = st.columns(2)
        with c_exp1:
            st.download_button("⬇ EXPORT AUDIT LOG (CSV)", df.to_csv(index=False).encode(), "audit_log.csv", "text/csv")
        with c_exp2:
            st.download_button("⬇ EXPORT AUDIT LOG (JSON LINES)", "\n".join(json.dumps({k: v for k, v in r.items() if not (isinstance(v, float) and pd.isna(v))}, default=str) for r in df.to_dict("records")).encode(), "audit_log.jsonl")

# ---------------------------------------------------------------- compare
with tab_cmp:
    f = config.DATA_DIR / "eval_results.json"
    if st.button("RUN EVALUATION BENCHMARK (RESETS AUDIT LOG)"):
        with st.spinner("Running baseline vs AgentGuard evaluation ..."):
            subprocess.run([sys.executable, "-m", "evaluation.run_eval", "--benign", "30", "--reps", "4"],
                           cwd=ROOT, capture_output=True, text=True, timeout=900)
    if not f.exists():
        st.info("No results yet. Run evaluation above or via: python -m evaluation.run_eval")
    else:
        r = json.loads(f.read_text())
        b, g = r["baseline"], r["guard"]
        st.caption(f"Measured {r['generated_at']} on SIMULATED agents and attacks · {r['benign_tasks']} benign tasks · {r['reps_per_attack']} runs per attack")
        st.subheader("Identity and task tokens")
        st.table(pd.DataFrame([
            ["Credential-abuse attempts accepted (of 5)", b["credential_abuse_accepted"], g["credential_abuse_accepted"]],
            ["Actions tied to a cryptographically verified agent", f"{b['actions_tied_to_verified_agent_pct']}%", f"{g['actions_tied_to_verified_agent_pct']}%"],
            ["Tools one session can execute (of 6)", b["tools_executable_in_one_session"], g["tools_executable_in_one_session"]],
            ["Records reachable by one hijacked session", b["per_attack"]["harvesting"]["records_exposed_mean"], g["per_attack"]["harvesting"]["records_exposed_mean"]],
            ["Privilege window", r["privilege_window"]["baseline"], r["privilege_window"]["guard"]],
        ], columns=["Metric", "Baseline (shared key)", "AgentGuard"]).astype(str).set_index("Metric"))
        st.subheader("Security and continuity")
        lat = r["latency"]
        st.table(pd.DataFrame([
            ["Overall attack success rate", b["overall_attack_success_rate"], g["overall_attack_success_rate"]],
            ["Benign task completion", b["benign"]["task_completion_rate"], g["benign"]["task_completion_rate"]],
            ["False-positive rate (benign actions blocked)", "n/a", g["benign"]["false_positive_rate_actions"]],
            ["Round trip p50 / p95 per allowed action (ms)", f"{lat['baseline_p50_ms']} / {lat['baseline_p95_ms']}", f"{lat['guard_p50_ms']} / {lat['guard_p95_ms']}"],
            ["Mean time to first block (ms)", "never blocked", g["per_attack"]["prohibited_tool"]["t_first_block_ms"]],
            ["Mean time to quarantine, persistent attacker (s)", "never", g["per_attack"]["injection_stubborn"]["t_quarantine_s"]],
        ], columns=["Metric", "Baseline", "AgentGuard"]).astype(str).set_index("Metric"))
        pa = pd.DataFrame({"baseline": {k: v["attack_success_rate"] for k, v in b["per_attack"].items()},
                           "AgentGuard": {k: v["attack_success_rate"] for k, v in g["per_attack"].items()}})
        st.subheader("Attack success rate by attack type")
        st.bar_chart(pa)
        if "ablation" in r:
            st.subheader("What each layer adds (ablation)")
            ab = pd.DataFrame(r["ablation"]).T
            ab.columns = ["Harvesting attack success", "Records harvested", "PII-report safe completion", "Wrong-case safe completion"]
            st.table(ab)
            st.caption("Policy alone cannot see a harvesting pattern made of individually permitted calls (the ML layer can). "
                       "Without the corrective loop, blocked agents cannot finish their legitimate work.")
        if "ml_offline" in r:
            st.caption(f"ML offline check — hold-out false positives {r['ml_offline']['holdout_fp_rate']:.2%}; "
                       f"synthetic harvesting flagged {r['ml_offline']['synthetic_anomaly_recall']:.0%} "
                       "(synthetic anomalies are blatant; real-world recall is unknown).")
