"""
CTIMAP v3.1 — Italy Cyber Threat Intelligence
Streamlit — non-blocking webhook fetch — Italy dark map always visible

requirements.txt:
    streamlit
    requests
    pandas
    plotly
    streamlit-autorefresh
"""

import time
import threading
from datetime import datetime, timedelta

import requests
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

# ── PAGE CONFIG ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CTIMAP — Italy Cyber Threat Intelligence",
    page_icon="⬡", layout="wide", initial_sidebar_state="collapsed",
)

# ── AUTO-REFRESH every 30s ───────────────────────────────────────────────────
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=30_000, limit=None, key="cti_ar")
except Exception:
    pass

# ── CONFIG ───────────────────────────────────────────────────────────────────
WEBHOOK_URL = "https://hierocratic-subumbellate-dionna.ngrok-free.dev/webhook/cyber-news"
TIMEOUT_S   = 10
SEV_COLORS  = {"critical":"#ff3b3b","high":"#ff8c00","medium":"#f0c000","low":"#00e676"}
SEV_ORDER   = ["critical","high","medium","low"]

# ── CSS ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap');
html,body,[class*="css"]{background-color:#060a14!important;color:#c9d6e8!important;font-family:'Share Tech Mono',monospace!important}
.stApp{background:#060a14}
.stApp::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9998;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.035) 2px,rgba(0,0,0,.035) 4px)}
.cti-header{display:flex;align-items:center;justify-content:space-between;padding:10px 0 14px;border-bottom:1px solid #1e2d45;margin-bottom:12px}
.cti-logo{display:flex;align-items:center;gap:14px}
.cti-logo-icon{width:40px;height:40px;border:2px solid #00d4ff;display:inline-flex;align-items:center;justify-content:center;clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);background:rgba(0,212,255,.1);font-size:1.1rem;color:#00d4ff;animation:glow 2s ease-in-out infinite}
@keyframes glow{0%,100%{box-shadow:0 0 6px #00d4ff}50%{box-shadow:0 0 18px #00d4ff,0 0 32px rgba(0,212,255,.25)}}
.cti-logo-text{font-family:'Syne',sans-serif;font-weight:800;font-size:1.4rem;letter-spacing:4px;color:#fff}
.cti-logo-sub{font-size:.58rem;color:#00d4ff;letter-spacing:4px;text-transform:uppercase}
.live-badge{display:inline-flex;align-items:center;gap:7px;font-size:.68rem;color:#00e676;letter-spacing:2px}
.live-dot{width:8px;height:8px;border-radius:50%;background:#00e676;animation:blink 1s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.cti-time{font-size:.7rem;color:#00d4ff}
.st-ok{font-size:.62rem;color:#00e676;letter-spacing:1px}
.st-err{font-size:.62rem;color:#ff3b3b;letter-spacing:1px}
.st-warn{font-size:.62rem;color:#f0c000;letter-spacing:1px}
.stat-card{background:#0d1321;border:1px solid #1e2d45;padding:16px 20px;position:relative;overflow:hidden}
.stat-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--ac,#00d4ff),transparent)}
.stat-label{font-size:.58rem;color:#4a5568;letter-spacing:3px;text-transform:uppercase;margin-bottom:5px}
.stat-value{font-family:'Syne',sans-serif;font-size:2.3rem;font-weight:800;line-height:1}
.stat-sub{font-size:.56rem;color:#4a5568;margin-top:3px}
.section-title{font-size:.6rem;color:#00d4ff;letter-spacing:3px;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.section-title::before{content:'';width:3px;height:11px;background:#00d4ff;display:inline-block}
.alert-banner{background:linear-gradient(90deg,rgba(255,59,59,.15),rgba(255,59,59,.05));border:1px solid #ff3b3b;padding:10px 16px;margin-bottom:12px;font-size:.82rem;color:#ff3b3b;letter-spacing:1px}
.feed-wrap{background:#0d1321;border:1px solid #1e2d45;max-height:230px;overflow-y:auto}
.feed-item{display:flex;align-items:flex-start;gap:10px;padding:8px 12px;border-bottom:1px solid rgba(30,45,69,.6);text-decoration:none;color:inherit}
.feed-item:hover{background:rgba(0,212,255,.04)}
.feed-dot{width:7px;min-width:7px;height:7px;border-radius:50%;margin-top:5px;flex-shrink:0}
.feed-body{flex:1;min-width:0}
.feed-title{font-size:.72rem;color:#e2e8f0;line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.feed-meta{font-size:.58rem;color:#4a5568;margin-top:3px}
.feed-tag{display:inline-block;background:rgba(31,111,235,.2);border:1px solid rgba(31,111,235,.3);color:#7dd3fc;padding:1px 5px;font-size:.54rem;letter-spacing:1px;text-transform:uppercase;margin-right:3px}
.feed-tag-s{display:inline-block;background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.3);color:#a78bfa;padding:1px 5px;font-size:.54rem;letter-spacing:1px;text-transform:uppercase;margin-right:3px}
.feed-time{font-size:.56rem;color:#4a5568;white-space:nowrap}
.region-item{display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid rgba(30,45,69,.4);font-size:.68rem}
.region-rank{color:#4a5568;width:18px;text-align:right}
.region-name{flex:1;color:#c9d6e8}
.region-count{color:#00d4ff}
#MainMenu,footer,header{visibility:hidden}
.block-container{padding-top:.5rem!important;max-width:100%!important}
section[data-testid="stSidebar"]{display:none}
div[data-baseweb="select"]>div{background:#111827!important;border-color:#1e2d45!important;color:#c9d6e8!important;font-family:'Share Tech Mono',monospace!important;font-size:.72rem!important}
.stButton>button{background:transparent!important;border:1px solid #1e2d45!important;color:#4a5568!important;font-family:'Share Tech Mono',monospace!important;font-size:.68rem!important;letter-spacing:1px!important}
.stButton>button:hover{border-color:#00d4ff!important;color:#00d4ff!important}
label{color:#4a5568!important;font-size:.58rem!important;letter-spacing:2px!important;text-transform:uppercase!important}
</style>
""", unsafe_allow_html=True)

# ── NON-BLOCKING FETCH ────────────────────────────────────────────────────────
def _normalize(raw_list):
    """
    Handle all n8n webhook response shapes:
      - plain list of records
      - list of {json: {...}, pairedItem: {...}} wrappers (n8n default)
      - single dict
    Also remap field names to match our schema:
      type        -> attack_type
      tlp         -> admiralty_code  (if admiralty_code absent)
    """
    out = []
    for item in raw_list:
        # unwrap n8n pairedItem wrapper
        if isinstance(item, dict) and "json" in item and isinstance(item["json"], dict):
            rec = dict(item["json"])
        elif isinstance(item, dict):
            rec = dict(item)
        else:
            continue
        # remap 'type' -> 'attack_type'
        if "attack_type" not in rec or not rec.get("attack_type"):
            rec["attack_type"] = rec.get("type", "")
        # remap 'tlp' -> 'admiralty_code'
        if "admiralty_code" not in rec or not rec.get("admiralty_code"):
            rec["admiralty_code"] = rec.get("tlp", "")
        # lowercase severity for consistency
        if rec.get("severity"):
            rec["severity"] = str(rec["severity"]).lower()
        out.append(rec)
    return out

def _do_fetch():
    try:
        r = requests.get(WEBHOOK_URL,
                         headers={"ngrok-skip-browser-warning":"true"},
                         timeout=TIMEOUT_S)
        r.raise_for_status()
        data = r.json()

        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            for k in ("data","events","records","items","cyber_news"):
                if k in data and isinstance(data[k], list):
                    raw_list = data[k]
                    break
            if not raw_list:
                raw_list = [data]

        result = _normalize(raw_list)
        status = "ok" if result else "empty"

    except requests.exceptions.Timeout:
        result = st.session_state.get("_ev", [])
        status = "timeout"
    except requests.exceptions.ConnectionError:
        result = st.session_state.get("_ev", [])
        status = "conn_error"
    except Exception as e:
        result = st.session_state.get("_ev", [])
        status = f"error:{str(e)[:80]}"
    st.session_state["_ev"]      = result
    st.session_state["_status"]  = status
    st.session_state["_fetch_ts"]= datetime.utcnow()
    st.session_state["_running"] = False

def get_data():
    now  = datetime.utcnow()
    last = st.session_state.get("_fetch_ts")
    run  = st.session_state.get("_running", False)
    if not run and (last is None or (now - last).total_seconds() > 29):
        st.session_state["_running"] = True
        threading.Thread(target=_do_fetch, daemon=True).start()
    return st.session_state.get("_ev", []), st.session_state.get("_status", "loading")

# ── DATA HELPERS ──────────────────────────────────────────────────────────────
def parse_ts(raw):
    if not raw: return None
    try: return datetime.fromisoformat(str(raw).replace("Z","+00:00")).replace(tzinfo=None)
    except: return None

def time_ago(raw):
    t = parse_ts(raw)
    if not t: return ""
    m = int((datetime.utcnow()-t).total_seconds()//60)
    if m < 1:  return "now"
    if m < 60: return f"{m}m"
    h = m//60
    return f"{h}h" if h < 24 else f"{h//24}d"

def compute_stats(events):
    now=datetime.utcnow(); today=now.replace(hour=0,minute=0,second=0,microsecond=0)
    week=now-timedelta(days=7); month=now-timedelta(days=30)
    td=wk=mo=cr=0
    for ev in events:
        t=parse_ts(ev.get("created_at")); sev=(ev.get("severity") or "").lower()
        if sev=="critical": cr+=1
        if t:
            if t>=today: td+=1
            if t>=week:  wk+=1
            if t>=month: mo+=1
    return {"today":td,"week":wk,"month":mo,"critical":cr,"total":len(events)}

def to_df(events):
    if not events: return pd.DataFrame()
    df = pd.DataFrame(events)
    if "created_at" in df.columns:
        df["created_at"]=pd.to_datetime(df["created_at"],errors="coerce",utc=True)
    # remap 'type' -> 'attack_type' if needed
    if "attack_type" not in df.columns and "type" in df.columns:
        df["attack_type"] = df["type"]
    # remap 'tlp' -> 'admiralty_code' if needed
    if "admiralty_code" not in df.columns and "tlp" in df.columns:
        df["admiralty_code"] = df["tlp"]
    for col in ["latitude","longitude"]:
        if col not in df.columns: df[col]=float("nan")
        else: df[col]=pd.to_numeric(df[col],errors="coerce")
    for col in ["severity","attack_type","sector","target","source","title","link","threat_actor","country","admiralty_code"]:
        if col not in df.columns: df[col]=""
        else: df[col]=df[col].fillna("").astype(str)
    # normalize severity to lowercase
    df["severity"] = df["severity"].str.lower()
    return df

def apply_filters(df, sv, at, se):
    if df.empty: return df
    if sv!="All": df=df[df["severity"].str.lower()==sv.lower()]
    if at!="All": df=df[df["attack_type"].str.lower().str.contains(at.lower(),na=False)]
    if se!="All": df=df[df["sector"].str.lower().str.contains(se.lower(),na=False)]
    return df

# ── CHART BASE ────────────────────────────────────────────────────────────────
CL=dict(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Share Tech Mono",color="#c9d6e8",size=11),
        margin=dict(l=0,r=0,t=8,b=0))

# ── ITALY MAP (always visible) ────────────────────────────────────────────────
def chart_map(df):
    fig=go.Figure()
    fig.update_layout(
        geo=dict(
            scope="europe", projection_type="natural earth",
            center=dict(lat=42.5,lon=12.5),
            lonaxis=dict(range=[6.0,19.5]),
            lataxis=dict(range=[35.5,47.8]),
            showland=True,       landcolor="#0d1a2d",
            showocean=True,      oceancolor="#060d1a",
            showlakes=True,      lakecolor="#091220",
            showrivers=True,     rivercolor="#091220",
            showcountries=True,  countrycolor="#1e3a5f",
            showcoastlines=True, coastlinecolor="#1e4070",
            countrywidth=0.7,    coastlinewidth=0.9,
            bgcolor="#060a14",   framewidth=0,
            showsubunits=True,   subunitcolor="#162840",
        ),
        paper_bgcolor="#060a14", plot_bgcolor="#060a14",
        margin=dict(l=0,r=0,t=0,b=0), height=460,
        font=dict(family="Share Tech Mono",color="#c9d6e8"),
        hoverlabel=dict(bgcolor="#0d1321",bordercolor="#1e2d45",
                        font=dict(family="Share Tech Mono",size=11)),
    )
    # legend proxies
    for sev,color in SEV_COLORS.items():
        fig.add_trace(go.Scattergeo(lon=[None],lat=[None],mode="markers",
            marker=dict(size=9,color=color),name=sev.capitalize(),showlegend=True))
    fig.update_layout(legend=dict(x=0.01,y=0.99,bgcolor="rgba(6,10,20,0.85)",
        bordercolor="#1e2d45",borderwidth=1,font=dict(size=9,color="#94a3b8")))

    if df.empty: return fig
    try:
        m=df.copy()
        m["latitude"]=pd.to_numeric(m["latitude"],errors="coerce")
        m["longitude"]=pd.to_numeric(m["longitude"],errors="coerce")
        m=m.dropna(subset=["latitude","longitude"])
        m=m[(m["latitude"].abs()>0.1)|(m["longitude"].abs()>0.1)]
    except: return fig
    if m.empty: return fig

    m["color"]=m["severity"].str.lower().map(SEV_COLORS).fillna("#7dd3fc")
    m["psize"]=m["severity"].str.lower().map({"critical":16,"high":12,"medium":9,"low":7}).fillna(8)
    m["hover"]=("<b>"+m["title"].str[:70]+"</b><br>"
                +"Tipo: "+m["attack_type"].str.capitalize()+"<br>"
                +"Settore: "+m["sector"].str.capitalize()+"<br>"
                +"Gravità: "+m["severity"].str.upper()+"<br>"
                +"Target: "+m["target"])

    # pulse ring for critical
    crit=m[m["severity"].str.lower()=="critical"]
    if not crit.empty:
        fig.add_trace(go.Scattergeo(lon=crit["longitude"],lat=crit["latitude"],mode="markers",
            marker=dict(size=crit["psize"]*2.2,color="#ff3b3b",opacity=0.18),
            hoverinfo="skip",showlegend=False))
    # markers
    fig.add_trace(go.Scattergeo(lon=m["longitude"],lat=m["latitude"],mode="markers",
        marker=dict(size=m["psize"],color=m["color"],opacity=0.92,
                    line=dict(width=1,color="rgba(255,255,255,0.25)")),
        text=m["hover"],hovertemplate="%{text}<extra></extra>",showlegend=False))
    return fig

# ── OTHER CHARTS ──────────────────────────────────────────────────────────────
def chart_sectors(df):
    if df.empty: return None
    c=df[df["sector"]!=""]["sector"].str.lower().value_counts().head(8).reset_index()
    c.columns=["sector","count"]; c["sector"]=c["sector"].str.capitalize()
    fig=go.Figure(go.Bar(x=c["count"],y=c["sector"],orientation="h",
        marker=dict(color=c["count"],colorscale=[[0,"#1a3060"],[1,"#00d4ff"]],line=dict(width=0)),
        text=c["count"],textposition="outside",textfont=dict(size=9,color="#4a5568")))
    fig.update_layout(**CL,height=190,
        xaxis=dict(showgrid=True,gridcolor="#1e2d45",zeroline=False,tickfont=dict(color="#4a5568",size=9)),
        yaxis=dict(showgrid=False,tickfont=dict(size=9,color="#94a3b8")))
    return fig

def chart_attacks(df):
    if df.empty: return None
    c=df[df["attack_type"]!=""]["attack_type"].str.lower().value_counts().head(7).reset_index()
    c.columns=["attack_type","count"]; c["attack_type"]=c["attack_type"].str.capitalize()
    colors=["#ff3b3b","#ff8c00","#f0c000","#00e676","#00d4ff","#7c3aed","#ec4899"]
    fig=go.Figure(go.Pie(labels=c["attack_type"],values=c["count"],hole=0.62,
        marker=dict(colors=colors[:len(c)],line=dict(color="#060a14",width=2)),
        textinfo="none",hovertemplate="<b>%{label}</b><br>%{value}<extra></extra>"))
    fig.update_layout(**CL,height=190,
        legend=dict(font=dict(size=9,color="#94a3b8"),bgcolor="rgba(0,0,0,0)",x=1,y=0.5),
        showlegend=True)
    return fig

def chart_timeline(df):
    if df.empty or "created_at" not in df.columns: return None
    cutoff=pd.Timestamp.utcnow()-pd.Timedelta(hours=24)
    rec=df[df["created_at"]>=cutoff].copy()
    if rec.empty: return None
    rec["hour"]=rec["created_at"].dt.floor("h")
    c=rec.groupby("hour").size().reset_index(name="count")
    fig=go.Figure(go.Scatter(x=c["hour"],y=c["count"],mode="lines+markers",
        line=dict(color="#00d4ff",width=1.5),marker=dict(size=4,color="#00d4ff"),
        fill="tozeroy",fillcolor="rgba(0,212,255,0.08)",
        hovertemplate="%{x|%H:%M} — %{y}<extra></extra>"))
    fig.update_layout(**CL,height=150,
        xaxis=dict(showgrid=True,gridcolor="#1e2d45",tickformat="%H:%M",
                   tickfont=dict(color="#4a5568",size=9),zeroline=False),
        yaxis=dict(showgrid=True,gridcolor="rgba(30,45,69,0.4)",
                   tickfont=dict(color="#4a5568",size=9),zeroline=False))
    return fig

def chart_severity(df):
    if df.empty: return None
    c=df[df["severity"]!=""]["severity"].str.lower().value_counts()
    c=c.reindex([s for s in SEV_ORDER if s in c.index]).dropna().reset_index()
    c.columns=["severity","count"]; c["color"]=c["severity"].map(SEV_COLORS).fillna("#7dd3fc")
    c["label"]=c["severity"].str.capitalize()
    fig=go.Figure(go.Bar(x=c["label"],y=c["count"],
        marker=dict(color=c["color"],line=dict(width=0)),
        text=c["count"],textposition="outside",textfont=dict(size=9,color="#4a5568")))
    fig.update_layout(**CL,height=150,
        xaxis=dict(showgrid=False,tickfont=dict(color="#94a3b8",size=10)),
        yaxis=dict(showgrid=True,gridcolor="#1e2d45",tickfont=dict(color="#4a5568",size=9),zeroline=False))
    return fig

# ── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    now_str=datetime.utcnow().strftime("%d %b %Y  %H:%M:%S UTC")
    st.markdown(f"""
    <div class="cti-header">
      <div class="cti-logo">
        <div class="cti-logo-icon">⬡</div>
        <div><div class="cti-logo-text">CTIMAP</div>
        <div class="cti-logo-sub">Italy Cyber Threat Intelligence</div></div>
      </div>
      <div style="display:flex;align-items:center;gap:24px;">
        <div class="live-badge"><span class="live-dot"></span>&nbsp;LIVE</div>
        <div class="cti-time">{now_str}</div>
      </div>
    </div>""", unsafe_allow_html=True)

    raw, status = get_data()

    fetch_ts = st.session_state.get("_fetch_ts")
    ts_str   = fetch_ts.strftime("%H:%M:%S") if fetch_ts else "—"
    running  = st.session_state.get("_running", False)

    if   running and not raw:  st.markdown('<span class="st-warn">● CONNESSIONE AL WEBHOOK IN CORSO…</span>', unsafe_allow_html=True)
    elif status=="ok":         st.markdown(f'<span class="st-ok">● WEBHOOK OK — {len(raw)} eventi — aggiornato {ts_str}</span>', unsafe_allow_html=True)
    elif status=="timeout":    st.markdown(f'<span class="st-err">● TIMEOUT — ngrok offline o lento (ultimo: {ts_str}) — riprovo tra 30s</span>', unsafe_allow_html=True)
    elif status=="conn_error": st.markdown('<span class="st-err">● CONNESSIONE RIFIUTATA — avvia ngrok e n8n</span>', unsafe_allow_html=True)
    elif status=="loading":    st.markdown('<span class="st-warn">● CARICAMENTO INIZIALE…</span>', unsafe_allow_html=True)
    elif status=="empty":      st.markdown('<span class="st-warn">● WEBHOOK RAGGIUNTO — nessun dato ancora</span>', unsafe_allow_html=True)
    else:                      st.markdown(f'<span class="st-err">● ERRORE: {status.replace("error:","")[:100]}</span>', unsafe_allow_html=True)

    all_df=to_df(raw)

    fc1,fc2,fc3,fc4=st.columns([1,1,1,0.5])
    sev_opts=["All"]+[s.capitalize() for s in SEV_ORDER]
    atk_opts=["All"]+sorted({(e.get("attack_type") or "").strip().capitalize() for e in raw if e.get("attack_type")})
    sec_opts=["All"]+sorted({(e.get("sector") or "").strip().capitalize() for e in raw if e.get("sector")})
    with fc1: sev_f=st.selectbox("SEVERITY",    sev_opts,key="fsev")
    with fc2: atk_f=st.selectbox("ATTACK TYPE", atk_opts,key="fatk")
    with fc3: sec_f=st.selectbox("SECTOR",      sec_opts,key="fsec")
    with fc4:
        st.write("")
        if st.button("↺  RESET",use_container_width=True):
            for k in ("fsev","fatk","fsec"): st.session_state[k]="All"
            st.rerun()

    df=apply_filters(all_df.copy(),sev_f,atk_f,sec_f)

    if not df.empty:
        crit=df[df["severity"].str.lower()=="critical"]
        if not crit.empty:
            row=crit.iloc[0]
            atk=str(row.get("attack_type","")).upper(); tgt=str(row.get("target","") or row.get("title",""))[:70]
            st.markdown(f'<div class="alert-banner">⚠&nbsp;&nbsp;CRITICO — {atk} rilevato — {tgt}</div>',unsafe_allow_html=True)

    stats=compute_stats(raw)
    def scard(l,v,c,s): return (f'<div class="stat-card" style="--ac:{c};">'
        f'<div class="stat-label">{l}</div><div class="stat-value" style="color:{c};">{v}</div>'
        f'<div class="stat-sub">{s}</div></div>')
    s1,s2,s3,s4=st.columns(4)
    with s1: st.markdown(scard("Today",     stats["today"],   "#00d4ff","attacchi rilevati"),unsafe_allow_html=True)
    with s2: st.markdown(scard("This Week", stats["week"],    "#7dd3fc","incidenti"),        unsafe_allow_html=True)
    with s3: st.markdown(scard("Month",     stats["month"],   "#93c5fd","eventi tracciati"), unsafe_allow_html=True)
    with s4: st.markdown(scard("Critical",  stats["critical"],"#ff3b3b","alta priorità"),   unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>",unsafe_allow_html=True)

    mc,sc=st.columns([3,1.25])
    with mc:
        n=len(df)
        st.markdown(f'<div class="section-title">◈ LIVE THREAT MAP — ITALY &nbsp;<span style="color:#4a5568;font-size:.58rem;">{n} EVENTI</span></div>',unsafe_allow_html=True)
        st.plotly_chart(chart_map(df),use_container_width=True,config={"displayModeBar":False})
    with sc:
        st.markdown('<div class="section-title">Settori Colpiti</div>',unsafe_allow_html=True)
        f=chart_sectors(df)
        if f: st.plotly_chart(f,use_container_width=True,config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:14px 0;">In attesa di dati…</div>',unsafe_allow_html=True)
        st.markdown('<div class="section-title" style="margin-top:4px;">Tipi di Attacco</div>',unsafe_allow_html=True)
        f=chart_attacks(df)
        if f: st.plotly_chart(f,use_container_width=True,config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:14px 0;">In attesa di dati…</div>',unsafe_allow_html=True)

    bc,tc=st.columns([3,1.25])
    with bc:
        st.markdown('<div class="section-title">Incidenti Recenti</div>',unsafe_allow_html=True)
        recent=df.head(60) if not df.empty else pd.DataFrame()
        if not recent.empty:
            html=""
            for _,row in recent.iterrows():
                sev=(row.get("severity") or "low").lower(); dc=SEV_COLORS.get(sev,"#7dd3fc")
                link=str(row.get("link") or "#"); title=str(row.get("title") or "Incidente sconosciuto")[:80]
                atk=str(row.get("attack_type") or "?").capitalize(); sec=str(row.get("sector") or "?").capitalize()
                tgt=str(row.get("target") or ""); ta=time_ago(row.get("created_at"))
                tgt_h=f'<span style="color:#4a5568;font-size:.56rem;">→ {tgt}</span>' if tgt else ""
                html+=(f'<a class="feed-item" href="{link}" target="_blank" rel="noopener" style="display:flex;">'
                       f'<div class="feed-dot" style="background:{dc};box-shadow:0 0 5px {dc};"></div>'
                       f'<div class="feed-body" style="padding-left:10px;">'
                       f'<div class="feed-title">{title}</div>'
                       f'<div class="feed-meta"><span class="feed-tag">{atk}</span>'
                       f'<span class="feed-tag-s">{sec}</span>{tgt_h}</div>'
                       f'</div><div class="feed-time">{ta}</div></a>')
            st.markdown(f'<div class="feed-wrap">{html}</div>',unsafe_allow_html=True)
        else:
            st.markdown('<div class="feed-wrap" style="padding:20px;color:#4a5568;font-size:.7rem;">In attesa di dati dal webhook…</div>',unsafe_allow_html=True)
    with tc:
        st.markdown('<div class="section-title">Timeline 24h</div>',unsafe_allow_html=True)
        f=chart_timeline(df)
        if f: st.plotly_chart(f,use_container_width=True,config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:12px 0;">Nessun evento 24h</div>',unsafe_allow_html=True)
        st.markdown('<div class="section-title" style="margin-top:4px;">Severity</div>',unsafe_allow_html=True)
        f=chart_severity(df)
        if f: st.plotly_chart(f,use_container_width=True,config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:12px 0;">Nessun dato</div>',unsafe_allow_html=True)

    st.markdown("<div style='height:6px'></div>",unsafe_allow_html=True)
    st.markdown('<div class="section-title">Ranking Regionale</div>',unsafe_allow_html=True)
    if not df.empty and "target" in df.columns:
        rc=df[df["target"]!=""]["target"].value_counts().head(10)
        if not rc.empty:
            mx=rc.max(); rhtml=""
            for rank,(region,count) in enumerate(rc.items(),1):
                pct=int(count/mx*100)
                rhtml+=(f'<div class="region-item"><div class="region-rank">{rank}</div>'
                        f'<div class="region-name">{region}</div>'
                        f'<div style="width:90px;height:3px;background:#1e2d45;border-radius:2px;margin-right:8px;">'
                        f'<div style="width:{pct}%;height:100%;background:#00d4ff;border-radius:2px;"></div></div>'
                        f'<div class="region-count">{count}</div></div>')
            st.markdown(f'<div style="background:#0d1321;border:1px solid #1e2d45;padding:10px 16px;">{rhtml}</div>',unsafe_allow_html=True)
    else:
        st.markdown('<div style="background:#0d1321;border:1px solid #1e2d45;padding:14px 16px;color:#4a5568;font-size:.7rem;">Nessun dato regionale</div>',unsafe_allow_html=True)

    st.markdown(f"""
    <div style="margin-top:14px;padding-top:10px;border-top:1px solid #1e2d45;display:flex;justify-content:space-between;align-items:center;">
      <div style="font-size:.54rem;color:#4a5568;letter-spacing:2px;">AUTO-REFRESH 30s &nbsp;·&nbsp; n8n WEBHOOK &nbsp;·&nbsp; TOTALE: {stats['total']} eventi</div>
      <div style="font-size:.54rem;color:#4a5568;">CTIMAP v3.1</div>
    </div>""",unsafe_allow_html=True)

    try:
        from streamlit_autorefresh import st_autorefresh  # noqa
    except ImportError:
        time.sleep(30)
        st.rerun()

main()
