"""
CTIMAP — Italy Cyber Threat Intelligence Dashboard
Streamlit version — reads data from n8n webhook via HTTP GET

Usage:
    pip install streamlit requests pandas plotly
    streamlit run app.py
"""

import time
from datetime import datetime, timedelta

import requests
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

# ─── PAGE CONFIG ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="CTIMAP — Italy Cyber Threat Intelligence",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── CONFIG ──────────────────────────────────────────────────────────────────

WEBHOOK_URL     = "https://hierocratic-subumbellate-dionna.ngrok-free.dev/webhook/cyber-news"
REFRESH_SECONDS = 30
SEV_COLORS      = {"critical": "#ff3b3b", "high": "#ff8c00", "medium": "#f0c000", "low": "#00e676"}
SEV_ORDER       = ["critical", "high", "medium", "low"]

# ─── CSS ─────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap');

html, body, [class*="css"] {
    background-color: #060a14 !important;
    color: #c9d6e8 !important;
    font-family: 'Share Tech Mono', monospace !important;
}
.stApp { background: #060a14; }

.cti-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 0 16px 0; border-bottom: 1px solid #1e2d45; margin-bottom: 16px;
}
.cti-logo { display: flex; align-items: center; gap: 14px; }
.cti-logo-icon {
    width: 40px; height: 40px; border: 2px solid #00d4ff;
    display: inline-flex; align-items: center; justify-content: center;
    clip-path: polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);
    background: rgba(0,212,255,0.1); font-size: 1.1rem; color: #00d4ff;
}
.cti-logo-text { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 1.4rem; letter-spacing: 4px; color: #fff; }
.cti-logo-sub  { font-size: 0.58rem; color: #00d4ff; letter-spacing: 4px; text-transform: uppercase; }
.live-badge    { display: inline-flex; align-items: center; gap: 7px; font-size: 0.68rem; color: #00e676; letter-spacing: 2px; }
.live-dot      { width: 8px; height: 8px; border-radius: 50%; background: #00e676; display: inline-block; animation: blink 1s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
.cti-time { font-size: 0.7rem; color: #00d4ff; }

.stat-card { background: #0d1321; border: 1px solid #1e2d45; padding: 16px 20px; position: relative; overflow: hidden; }
.stat-card::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, var(--ac, #00d4ff), transparent); }
.stat-label { font-size: 0.58rem; color: #4a5568; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 5px; }
.stat-value { font-family: 'Syne', sans-serif; font-size: 2.4rem; font-weight: 800; line-height: 1; }
.stat-sub   { font-size: 0.56rem; color: #4a5568; margin-top: 3px; }

.section-title { font-size: 0.6rem; color: #00d4ff; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
.section-title::before { content: ''; width: 3px; height: 11px; background: #00d4ff; display: inline-block; }

.alert-banner {
    background: linear-gradient(90deg, rgba(255,59,59,0.15), rgba(255,59,59,0.05));
    border: 1px solid #ff3b3b; padding: 10px 16px; margin-bottom: 14px;
    font-size: 0.82rem; color: #ff3b3b; letter-spacing: 1px;
}

.feed-item {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 8px 12px; border-bottom: 1px solid rgba(30,45,69,0.6);
    text-decoration: none;
}
.feed-item:hover { background: rgba(0,212,255,0.04); }
.feed-dot  { width: 7px; min-width: 7px; height: 7px; border-radius: 50%; margin-top: 5px; }
.feed-body { flex: 1; min-width: 0; }
.feed-title { font-size: 0.72rem; color: #e2e8f0; line-height: 1.3; }
.feed-meta  { font-size: 0.58rem; color: #4a5568; margin-top: 3px; }
.feed-tag   { display: inline-block; background: rgba(31,111,235,0.2); border: 1px solid rgba(31,111,235,0.3); color: #7dd3fc; padding: 1px 5px; font-size: 0.54rem; letter-spacing: 1px; text-transform: uppercase; margin-right: 3px; }
.feed-tag-s { display: inline-block; background: rgba(124,58,237,0.15); border: 1px solid rgba(124,58,237,0.3); color: #a78bfa; padding: 1px 5px; font-size: 0.54rem; letter-spacing: 1px; text-transform: uppercase; margin-right: 3px; }
.feed-time  { font-size: 0.56rem; color: #4a5568; white-space: nowrap; }

.region-item { display: flex; align-items: center; gap: 10px; padding: 5px 0; border-bottom: 1px solid rgba(30,45,69,0.4); font-size: 0.68rem; }
.region-rank { color: #4a5568; width: 18px; text-align: right; }
.region-name { flex: 1; color: #c9d6e8; }
.region-count { color: #00d4ff; }

#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 0.8rem !important; max-width: 100% !important; }
section[data-testid="stSidebar"] { display: none; }

div[data-baseweb="select"] > div {
    background: #111827 !important; border-color: #1e2d45 !important;
    color: #c9d6e8 !important; font-family: 'Share Tech Mono', monospace !important; font-size: 0.72rem !important;
}
.stButton > button {
    background: transparent !important; border: 1px solid #1e2d45 !important;
    color: #4a5568 !important; font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.68rem !important; letter-spacing: 1px !important;
}
.stButton > button:hover { border-color: #00d4ff !important; color: #00d4ff !important; }
label { color: #4a5568 !important; font-size: 0.58rem !important; letter-spacing: 2px !important; text-transform: uppercase !important; }
</style>
""", unsafe_allow_html=True)

# ─── DATA FETCH ───────────────────────────────────────────────────────────────

@st.cache_data(ttl=REFRESH_SECONDS)
def fetch_data() -> list:
    try:
        r = requests.get(WEBHOOK_URL, headers={"ngrok-skip-browser-warning": "true"}, timeout=15)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in ("data", "events", "records", "items", "cyber_news"):
                if k in data and isinstance(data[k], list):
                    return data[k]
        return []
    except Exception as e:
        st.warning(f"Webhook error: {e}")
        return []

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None

def time_ago(raw) -> str:
    t = parse_ts(raw)
    if not t:
        return ""
    diff = datetime.utcnow() - t
    m = int(diff.total_seconds() // 60)
    if m < 1:   return "now"
    if m < 60:  return f"{m}m"
    h = m // 60
    if h < 24:  return f"{h}h"
    return f"{h//24}d"

def compute_stats(events: list) -> dict:
    now   = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week  = now - timedelta(days=7)
    month = now - timedelta(days=30)
    td = wk = mo = cr = 0
    for ev in events:
        t   = parse_ts(ev.get("created_at"))
        sev = (ev.get("severity") or "").lower()
        if sev == "critical": cr += 1
        if t:
            if t >= today: td += 1
            if t >= week:  wk += 1
            if t >= month: mo += 1
    return {"today": td, "week": wk, "month": mo, "critical": cr, "total": len(events)}

def to_df(events: list) -> pd.DataFrame:
    if not events:
        return pd.DataFrame()
    df = pd.DataFrame(events)
    if "created_at" in df.columns:
        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce", utc=True)
    for col in ["latitude", "longitude"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    for col in ["severity","attack_type","sector","target","source","title","link","threat_actor","country"]:
        if col not in df.columns:
            df[col] = ""
        else:
            df[col] = df[col].fillna("").astype(str)
    return df

def apply_filters(df, sev_f, atk_f, sec_f):
    if df.empty:
        return df
    if sev_f != "All":
        df = df[df["severity"].str.lower() == sev_f.lower()]
    if atk_f != "All":
        df = df[df["attack_type"].str.lower().str.contains(atk_f.lower(), na=False)]
    if sec_f != "All":
        df = df[df["sector"].str.lower().str.contains(sec_f.lower(), na=False)]
    return df

# ─── CHART LAYOUT BASE ───────────────────────────────────────────────────────

CL = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
          font=dict(family="Share Tech Mono", color="#c9d6e8", size=11),
          margin=dict(l=0, r=0, t=8, b=0))

# ─── CHARTS ──────────────────────────────────────────────────────────────────

def chart_sectors(df):
    if df.empty: return None
    c = df[df["sector"] != ""]["sector"].str.lower().value_counts().head(8).reset_index()
    c.columns = ["sector","count"]; c["sector"] = c["sector"].str.capitalize()
    fig = go.Figure(go.Bar(x=c["count"], y=c["sector"], orientation="h",
        marker=dict(color=c["count"], colorscale=[[0,"#1f2f5a"],[1,"#00d4ff"]], line=dict(width=0)),
        text=c["count"], textposition="outside", textfont=dict(size=9,color="#4a5568")))
    fig.update_layout(**CL, height=190,
        xaxis=dict(showgrid=True,gridcolor="#1e2d45",zeroline=False,tickfont=dict(color="#4a5568",size=9)),
        yaxis=dict(showgrid=False,tickfont=dict(size=9,color="#94a3b8")))
    return fig

def chart_attacks(df):
    if df.empty: return None
    c = df[df["attack_type"]!=""]["attack_type"].str.lower().value_counts().head(7).reset_index()
    c.columns = ["attack_type","count"]; c["attack_type"] = c["attack_type"].str.capitalize()
    colors = ["#ff3b3b","#ff8c00","#f0c000","#00e676","#00d4ff","#7c3aed","#ec4899"]
    fig = go.Figure(go.Pie(labels=c["attack_type"], values=c["count"], hole=0.62,
        marker=dict(colors=colors[:len(c)], line=dict(color="#060a14",width=2)),
        textinfo="none", hovertemplate="<b>%{label}</b><br>%{value}<extra></extra>"))
    fig.update_layout(**CL, height=190,
        legend=dict(font=dict(size=9,color="#94a3b8"),bgcolor="rgba(0,0,0,0)",x=1,y=0.5),
        showlegend=True)
    return fig

def chart_timeline(df):
    if df.empty or "created_at" not in df.columns: return None
    cutoff = pd.Timestamp.utcnow() - pd.Timedelta(hours=24)
    rec = df[df["created_at"] >= cutoff].copy()
    if rec.empty: return None
    rec["hour"] = rec["created_at"].dt.floor("h")
    c = rec.groupby("hour").size().reset_index(name="count")
    fig = go.Figure(go.Scatter(x=c["hour"], y=c["count"], mode="lines+markers",
        line=dict(color="#00d4ff",width=1.5), marker=dict(size=4,color="#00d4ff"),
        fill="tozeroy", fillcolor="rgba(0,212,255,0.1)",
        hovertemplate="%{x|%H:%M} — %{y} attacks<extra></extra>"))
    fig.update_layout(**CL, height=155,
        xaxis=dict(showgrid=True,gridcolor="#1e2d45",tickformat="%H:%M",tickfont=dict(color="#4a5568",size=9),zeroline=False),
        yaxis=dict(showgrid=True,gridcolor="rgba(30,45,69,0.4)",tickfont=dict(color="#4a5568",size=9),zeroline=False))
    return fig

def chart_severity(df):
    if df.empty: return None
    c = df[df["severity"]!=""]["severity"].str.lower().value_counts().reindex(SEV_ORDER).dropna().reset_index()
    c.columns = ["severity","count"]; c["color"] = c["severity"].map(SEV_COLORS).fillna("#7dd3fc")
    c["label"] = c["severity"].str.capitalize()
    fig = go.Figure(go.Bar(x=c["label"], y=c["count"],
        marker=dict(color=c["color"],line=dict(width=0)),
        text=c["count"], textposition="outside", textfont=dict(size=9,color="#4a5568")))
    fig.update_layout(**CL, height=155,
        xaxis=dict(showgrid=False,tickfont=dict(color="#94a3b8",size=10)),
        yaxis=dict(showgrid=True,gridcolor="#1e2d45",tickfont=dict(color="#4a5568",size=9),zeroline=False))
    return fig

def chart_map(df):
    m = df.dropna(subset=["latitude","longitude"]).copy()
    m = m[(m["latitude"].abs() > 0.01) | (m["longitude"].abs() > 0.01)]
    if m.empty: return None
    m["color"] = m["severity"].str.lower().map(SEV_COLORS).fillna("#7dd3fc")
    m["size"]  = m["severity"].str.lower().map({"critical":14,"high":11,"medium":9,"low":7}).fillna(8)
    m["hover"] = ("<b>" + m["title"].str[:70] + "</b><br>"
                  + "Type: " + m["attack_type"].str.capitalize() + "<br>"
                  + "Sector: " + m["sector"].str.capitalize() + "<br>"
                  + "Severity: " + m["severity"].str.upper() + "<br>"
                  + "Target: " + m["target"])
    fig = go.Figure(go.Scattermapbox(
        lat=m["latitude"], lon=m["longitude"], mode="markers",
        marker=go.scattermapbox.Marker(size=m["size"], color=m["color"], opacity=0.85),
        text=m["hover"], hovertemplate="%{text}<extra></extra>"))
    fig.update_layout(
        mapbox=dict(style="carto-darkmatter", center=dict(lat=42.5,lon=12.5), zoom=5.2),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0,r=0,t=0,b=0), height=430,
        font=dict(family="Share Tech Mono",color="#c9d6e8"),
        hoverlabel=dict(bgcolor="#0d1321",bordercolor="#1e2d45",font=dict(family="Share Tech Mono",size=11)))
    return fig

# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    # Header
    now_str = datetime.utcnow().strftime("%d %b %Y  %H:%M:%S UTC")
    st.markdown(f"""
    <div class="cti-header">
      <div class="cti-logo">
        <div class="cti-logo-icon">⬡</div>
        <div>
          <div class="cti-logo-text">CTIMAP</div>
          <div class="cti-logo-sub">Italy Cyber Threat Intelligence</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:22px;">
        <div class="live-badge"><span class="live-dot"></span>&nbsp;LIVE</div>
        <div class="cti-time">{now_str}</div>
      </div>
    </div>""", unsafe_allow_html=True)

    # Fetch
    raw = fetch_data()
    all_df = to_df(raw)

    # Filters
    fc1, fc2, fc3, fc4 = st.columns([1,1,1,0.5])
    sev_opts = ["All"] + [s.capitalize() for s in SEV_ORDER]
    atk_opts = ["All"] + sorted({(e.get("attack_type") or "").strip().capitalize() for e in raw if e.get("attack_type")})
    sec_opts = ["All"] + sorted({(e.get("sector") or "").strip().capitalize() for e in raw if e.get("sector")})
    with fc1: sev_f = st.selectbox("SEVERITY",     sev_opts, key="fsev")
    with fc2: atk_f = st.selectbox("ATTACK TYPE",  atk_opts, key="fatk")
    with fc3: sec_f = st.selectbox("SECTOR",       sec_opts, key="fsec")
    with fc4:
        st.write("")
        if st.button("↺  RESET", use_container_width=True):
            st.session_state.fsev = "All"
            st.session_state.fatk = "All"
            st.session_state.fsec = "All"
            st.rerun()

    df = apply_filters(all_df.copy(), sev_f, atk_f, sec_f)

    # Critical alert
    if not df.empty:
        crit = df[df["severity"].str.lower() == "critical"]
        if not crit.empty:
            row = crit.iloc[0]
            st.markdown(f"""<div class="alert-banner">
              ⚠&nbsp;&nbsp;CRITICAL {(row.get('attack_type','')).upper()} DETECTED
              — {row.get('target','') or str(row.get('title',''))[:70]}
            </div>""", unsafe_allow_html=True)

    # Stats
    stats = compute_stats(raw)
    def scard(label, val, color, sub):
        return f'<div class="stat-card" style="--ac:{color};"><div class="stat-label">{label}</div><div class="stat-value" style="color:{color};">{val}</div><div class="stat-sub">{sub}</div></div>'

    s1,s2,s3,s4 = st.columns(4)
    with s1: st.markdown(scard("Today",      stats["today"],    "#00d4ff", "attacks detected"),  unsafe_allow_html=True)
    with s2: st.markdown(scard("This Week",  stats["week"],     "#7dd3fc", "incidents logged"),   unsafe_allow_html=True)
    with s3: st.markdown(scard("This Month", stats["month"],    "#93c5fd", "events tracked"),     unsafe_allow_html=True)
    with s4: st.markdown(scard("Critical",   stats["critical"], "#ff3b3b", "high-priority threats"), unsafe_allow_html=True)

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)

    # Map + sidebar
    mc, sc = st.columns([3, 1.25])
    with mc:
        st.markdown(f'<div class="section-title">◈ LIVE THREAT MAP — ITALY &nbsp;<span style="color:#4a5568;font-size:0.58rem;">{len(df)} EVENTS</span></div>', unsafe_allow_html=True)
        fig_m = chart_map(df)
        if fig_m:
            st.plotly_chart(fig_m, use_container_width=True, config={"displayModeBar": False})
        else:
            st.markdown('<div style="height:430px;display:flex;align-items:center;justify-content:center;color:#4a5568;border:1px solid #1e2d45;font-size:0.75rem;">No geo-located events found</div>', unsafe_allow_html=True)

    with sc:
        st.markdown('<div class="section-title">Sector Distribution</div>', unsafe_allow_html=True)
        f = chart_sectors(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar": False})

        st.markdown('<div class="section-title" style="margin-top:6px;">Attack Types</div>', unsafe_allow_html=True)
        f = chart_attacks(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar": False})

    # Bottom row
    bc, tc = st.columns([3, 1.25])
    with bc:
        st.markdown('<div class="section-title">Recent Incidents</div>', unsafe_allow_html=True)
        recent = df.head(40) if not df.empty else pd.DataFrame()
        if not recent.empty:
            html = ""
            for _, row in recent.iterrows():
                sev   = (row.get("severity") or "low").lower()
                dc    = SEV_COLORS.get(sev, "#7dd3fc")
                link  = row.get("link") or "#"
                title = str(row.get("title") or "Unknown")[:80]
                atk   = str(row.get("attack_type") or "?").capitalize()
                sec   = str(row.get("sector") or "?").capitalize()
                tgt   = str(row.get("target") or "")
                ta    = time_ago(row.get("created_at"))
                tgt_html = f'<span style="color:#4a5568;font-size:0.56rem;">→ {tgt}</span>' if tgt else ""
                html += f"""<a class="feed-item" href="{link}" target="_blank" rel="noopener" style="display:flex;">
                  <div class="feed-dot" style="background:{dc};box-shadow:0 0 5px {dc};min-width:7px;width:7px;height:7px;border-radius:50%;margin-top:5px;"></div>
                  <div class="feed-body" style="flex:1;min-width:0;padding-left:10px;">
                    <div class="feed-title">{title}</div>
                    <div class="feed-meta"><span class="feed-tag">{atk}</span><span class="feed-tag-s">{sec}</span>{tgt_html}</div>
                  </div>
                  <div class="feed-time">{ta}</div>
                </a>"""
            st.markdown(f'<div style="background:#0d1321;border:1px solid #1e2d45;max-height:265px;overflow-y:auto;">{html}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="color:#4a5568;font-size:0.72rem;padding:12px;">No incidents found</div>', unsafe_allow_html=True)

    with tc:
        st.markdown('<div class="section-title">Attack Timeline — 24h</div>', unsafe_allow_html=True)
        f = chart_timeline(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar": False})

        st.markdown('<div class="section-title" style="margin-top:6px;">Severity Breakdown</div>', unsafe_allow_html=True)
        f = chart_severity(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar": False})

    # Region ranking
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">Regional Ranking — Most Attacked</div>', unsafe_allow_html=True)
    if not df.empty and "target" in df.columns:
        rc = df[df["target"] != ""]["target"].value_counts().head(10)
        if not rc.empty:
            mx = rc.max()
            rhtml = ""
            for rank, (region, count) in enumerate(rc.items(), 1):
                pct = int(count / mx * 100)
                rhtml += f"""<div class="region-item">
                  <div class="region-rank">{rank}</div>
                  <div class="region-name">{region}</div>
                  <div style="width:90px;height:3px;background:#1e2d45;border-radius:2px;margin-right:8px;">
                    <div style="width:{pct}%;height:100%;background:#00d4ff;border-radius:2px;"></div>
                  </div>
                  <div class="region-count">{count}</div>
                </div>"""
            st.markdown(f'<div style="background:#0d1321;border:1px solid #1e2d45;padding:10px 16px;">{rhtml}</div>', unsafe_allow_html=True)

    # Footer
    st.markdown(f"""
    <div style="margin-top:18px;padding-top:10px;border-top:1px solid #1e2d45;
                display:flex;justify-content:space-between;align-items:center;">
      <div style="font-size:0.56rem;color:#4a5568;letter-spacing:2px;">
        AUTO-REFRESH {REFRESH_SECONDS}s &nbsp;·&nbsp; SOURCE: n8n WEBHOOK
        &nbsp;·&nbsp; TOTAL EVENTS: {stats['total']}
      </div>
      <div style="font-size:0.56rem;color:#4a5568;">CTIMAP v2.0 — STREAMLIT</div>
    </div>""", unsafe_allow_html=True)

    # Auto-rerun
    time.sleep(REFRESH_SECONDS)
    st.rerun()


main()
