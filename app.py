"""
CTIMAP v5 — Italy Cyber Threat Intelligence
- Pallini interattivi sulla mappa Italia per ogni notizia
- Geocoding automatico città/regioni italiane
- Filtri per severity, tipo attacco, settore
- Auto-refresh ogni 30s
"""

import time
from datetime import datetime, timedelta

import requests
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

st.set_page_config(
    page_title="CTIMAP — Italy Cyber Threat Intelligence",
    page_icon="⬡", layout="wide", initial_sidebar_state="collapsed",
)

try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=30_000, limit=None, key="cti_ar")
except Exception:
    pass

WEBHOOK_URL = "https://hierocratic-subumbellate-dionna.ngrok-free.dev/webhook/cyber-news"
TIMEOUT_S   = 10
SEV_COLORS  = {"critical":"#ff3b3b","high":"#ff8c00","medium":"#f0c000","low":"#00e676"}
SEV_ORDER   = ["critical","high","medium","low"]

# ── GEOCODING DICT — città/regioni italiane + entità comuni ──────────────────
GEO_IT = {
    # Città principali
    "roma":        (41.9028, 12.4964), "rome":        (41.9028, 12.4964),
    "milano":      (45.4654, 9.1859),  "milan":       (45.4654, 9.1859),
    "napoli":      (40.8518, 14.2681), "naples":      (40.8518, 14.2681),
    "torino":      (45.0703, 7.6869),  "turin":       (45.0703, 7.6869),
    "palermo":     (38.1157, 13.3615),
    "genova":      (44.4056, 8.9463),  "genoa":       (44.4056, 8.9463),
    "bologna":     (44.4949, 11.3426),
    "firenze":     (43.7696, 11.2558), "florence":    (43.7696, 11.2558),
    "bari":        (41.1171, 16.8719),
    "catania":     (37.5023, 15.0873),
    "venezia":     (45.4408, 12.3155), "venice":      (45.4408, 12.3155),
    "verona":      (45.4384, 10.9916),
    "messina":     (38.1938, 15.5540),
    "padova":      (45.4064, 11.8768), "padua":       (45.4064, 11.8768),
    "trieste":     (45.6495, 13.7768),
    "brescia":     (45.5416, 10.2118),
    "taranto":     (40.4644, 17.2470),
    "prato":       (43.8777, 11.1022),
    "modena":      (44.6471, 10.9252),
    "reggio calabria": (38.1111, 15.6476),
    "reggio emilia":   (44.6989, 10.6297),
    "perugia":     (43.1122, 12.3888),
    "livorno":     (43.5485, 10.3106),
    "ravenna":     (44.4175, 12.2023),
    "cagliari":    (39.2238, 9.1217),
    "foggia":      (41.4621, 15.5446),
    "rimini":      (44.0678, 12.5695),
    "salerno":     (40.6824, 14.7681),
    "ferrara":     (44.8381, 11.6198),
    "sassari":     (40.7259, 8.5557),
    "monza":       (45.5845, 9.2744),
    "bergamo":     (45.6983, 9.6773),
    "trento":      (46.0748, 11.1217),
    "vicenza":     (45.5455, 11.5354),
    "ancona":      (43.6158, 13.5189),
    "lecce":       (40.3516, 18.1750),
    "pescara":     (42.4618, 14.2160),
    "udine":       (46.0644, 13.2353),
    "bolzano":     (46.4983, 11.3548),
    "andria":      (41.2289, 16.2955),
    "barletta":    (41.3197, 16.2835),
    "novara":      (45.4468, 8.6215),
    "piacenza":    (45.0526, 9.6929),
    "l'aquila":    (42.3498, 13.3995),
    "arezzo":      (43.4623, 11.8796),
    "siena":       (43.3186, 11.3308),
    "alessandria": (44.9124, 8.6151),
    "varese":      (45.8206, 8.8257),
    "como":        (45.8080, 9.0852),
    "catanzaro":   (38.9098, 16.5872),
    "cosenza":     (39.3008, 16.2511),
    # Regioni
    "lombardia":   (45.4654, 9.1859),  "lombardy":    (45.4654, 9.1859),
    "lazio":       (41.9028, 12.4964),
    "campania":    (40.8333, 14.2500),
    "sicilia":     (37.6000, 14.0154), "sicily":      (37.6000, 14.0154),
    "veneto":      (45.4408, 12.3155),
    "piemonte":    (45.0703, 7.6869),  "piedmont":    (45.0703, 7.6869),
    "emilia-romagna": (44.4949, 11.3426), "emilia romagna": (44.4949, 11.3426),
    "toscana":     (43.7696, 11.2558), "tuscany":     (43.7696, 11.2558),
    "puglia":      (41.1171, 16.8719), "apulia":      (41.1171, 16.8719),
    "calabria":    (38.9098, 16.5872),
    "sardegna":    (39.2238, 9.1217),  "sardinia":    (39.2238, 9.1217),
    "marche":      (43.6158, 13.5189),
    "abruzzo":     (42.3498, 13.3995),
    "friuli":      (46.0644, 13.2353),
    "trentino":    (46.0748, 11.1217),
    "umbria":      (43.1122, 12.3888),
    "basilicata":  (40.6391, 15.8050),
    "molise":      (41.5622, 14.6680),
    "valle d'aosta": (45.7369, 7.3208),
    "liguria":     (44.4056, 8.9463),
    # Enti / organizzazioni italiane comuni
    "governo italiano":    (41.9028, 12.4964),
    "governo":             (41.9028, 12.4964),
    "parlamento":          (41.9022, 12.4761),
    "presidenza del consiglio": (41.9028, 12.4964),
    "ministero":           (41.9028, 12.4964),
    "polizia":             (41.9028, 12.4964),
    "carabinieri":         (41.9028, 12.4964),
    "comune di roma":      (41.8902, 12.4922),
    "comune di milano":    (45.4654, 9.1859),
    "comune di napoli":    (40.8400, 14.2490),
    "inps":                (41.9028, 12.4964),
    "agenzia delle entrate": (41.9028, 12.4964),
    "eni":                 (45.4467, 9.1553),
    "enel":                (41.9028, 12.4964),
    "leonardo":            (41.8476, 12.5891),
    "finmeccanica":        (41.8476, 12.5891),
    "unicredit":           (45.4654, 9.1859),
    "intesa sanpaolo":     (45.0703, 7.6869),
    "banca d'italia":      (41.8985, 12.4780),
    "telecom italia":      (41.9028, 12.4964),
    "tim":                 (41.9028, 12.4964),
    "fastweb":             (45.4654, 9.1859),
    "poste italiane":      (41.9028, 12.4964),
    "trenitalia":          (41.9028, 12.4964),
    "atm":                 (45.4654, 9.1859),
    "ospedale":            (41.9028, 12.4964),
    # Fallback Italy centroid
    "italy":               (42.5000, 12.5000),
    "italia":              (42.5000, 12.5000),
}

def geocode_italian(text: str):
    """
    Try to extract lat/lon from a text string by matching Italian place names.
    Returns (lat, lon) or None.
    """
    if not text:
        return None
    t = text.lower().strip()
    # exact match first
    if t in GEO_IT:
        return GEO_IT[t]
    # substring match — longest key wins
    matches = [(k, v) for k, v in GEO_IT.items() if k in t]
    if matches:
        best = max(matches, key=lambda x: len(x[0]))
        return best[1]
    return None

def add_jitter(lat, lon, idx, total):
    """Slightly spread overlapping markers."""
    import math
    if total <= 1:
        return lat, lon
    angle = (2 * math.pi * idx) / max(total, 1)
    r = 0.08 * (idx % 3 + 1)
    return lat + r * math.sin(angle), lon + r * math.cos(angle)


# ── CSS ──────────────────────────────────────────────────────────────────────
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap');
html,body,[class*="css"]{background-color:#060a14!important;color:#c9d6e8!important;font-family:'Share Tech Mono',monospace!important}
.stApp{background:#060a14!important}
.stApp::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9998;
background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px)}
.cti-header{display:flex;align-items:center;justify-content:space-between;padding:10px 0 14px;border-bottom:1px solid #1e2d45;margin-bottom:12px}
.cti-logo{display:flex;align-items:center;gap:14px}
.cti-logo-icon{width:40px;height:40px;border:2px solid #00d4ff;display:inline-flex;align-items:center;justify-content:center;
clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);background:rgba(0,212,255,.1);font-size:1.1rem;color:#00d4ff;animation:glow 2s ease-in-out infinite}
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
</style>""", unsafe_allow_html=True)


# ── FETCH ────────────────────────────────────────────────────────────────────
def _normalize(raw_list):
    out = []
    for item in raw_list:
        try:
            r = item.get("json", item) if isinstance(item, dict) else {}
            if not isinstance(r, dict): continue
            r = dict(r)
            if not r.get("attack_type"):
                r["attack_type"] = r.get("type", "") or ""
            if not r.get("admiralty_code"):
                r["admiralty_code"] = r.get("tlp", "") or ""
            if r.get("severity"):
                r["severity"] = str(r["severity"]).lower().strip()
            out.append(r)
        except Exception:
            continue
    return out

@st.cache_data(ttl=30, show_spinner=False)
def _cached_fetch():
    try:
        r = requests.get(WEBHOOK_URL,
                         headers={"ngrok-skip-browser-warning": "true"},
                         timeout=TIMEOUT_S)
        r.raise_for_status()
        data = r.json()
        raw_list = []
        if isinstance(data, list):
            raw_list = data
        elif isinstance(data, dict):
            for k in ("data","events","records","items","cyber_news"):
                if k in data and isinstance(data[k], list):
                    raw_list = data[k]; break
            if not raw_list and data:
                raw_list = [data]
        result = _normalize(raw_list)
        return result, "ok" if result else "empty"
    except requests.exceptions.Timeout:
        return None, "timeout"
    except requests.exceptions.ConnectionError:
        return None, "conn_error"
    except Exception as e:
        return None, f"error:{str(e)[:120]}"

def get_data():
    result, status = _cached_fetch()
    if result is not None:
        st.session_state["_ev_cache"] = result
        st.session_state["_last_ok"]  = datetime.utcnow()
    else:
        result = st.session_state.get("_ev_cache", [])
    return result, status


# ── DATA HELPERS ─────────────────────────────────────────────────────────────
def parse_ts(raw):
    if not raw: return None
    try: return datetime.fromisoformat(str(raw).replace("Z","+00:00")).replace(tzinfo=None)
    except: return None

def time_ago(raw):
    t = parse_ts(raw)
    if not t: return ""
    m = int((datetime.utcnow()-t).total_seconds()//60)
    if m<1: return "now"
    if m<60: return f"{m}m"
    h=m//60
    return f"{h}h" if h<24 else f"{h//24}d"

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
    if "attack_type" not in df.columns and "type" in df.columns:
        df["attack_type"]=df["type"]
    if "admiralty_code" not in df.columns and "tlp" in df.columns:
        df["admiralty_code"]=df["tlp"]
    for col in ["latitude","longitude"]:
        if col not in df.columns: df[col]=float("nan")
        else: df[col]=pd.to_numeric(df[col],errors="coerce")
    for col in ["severity","attack_type","sector","target","source","title","link","threat_actor","country","admiralty_code"]:
        if col not in df.columns: df[col]=""
        else: df[col]=df[col].fillna("").astype(str)
    df["severity"]=df["severity"].str.lower().str.strip()
    # Auto-geocode: fill missing lat/lon from target/title/country
    for i, row in df.iterrows():
        if pd.isna(row["latitude"]) or row["latitude"] == 0.0:
            coord = (geocode_italian(str(row.get("target",""))) or
                     geocode_italian(str(row.get("country",""))) or
                     geocode_italian(str(row.get("title",""))))
            if coord:
                df.at[i,"latitude"]  = coord[0]
                df.at[i,"longitude"] = coord[1]
    return df

def apply_filters(df, sv, at, se):
    if df.empty: return df
    if sv!="All": df=df[df["severity"]==sv.lower()]
    if at!="All": df=df[df["attack_type"].str.lower().str.contains(at.lower(),na=False)]
    if se!="All": df=df[df["sector"].str.lower().str.contains(se.lower(),na=False)]
    return df


# ── CHARTS ───────────────────────────────────────────────────────────────────
CL=dict(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Share Tech Mono",color="#c9d6e8",size=11),
        margin=dict(l=0,r=0,t=8,b=0))

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
                        font=dict(family="Share Tech Mono",size=12)),
    )

    if df.empty:
        # empty map — just legend
        for sev,col in SEV_COLORS.items():
            fig.add_trace(go.Scattergeo(lon=[None],lat=[None],mode="markers",
                marker=dict(size=9,color=col),name=sev.capitalize(),showlegend=True))
        fig.update_layout(legend=dict(x=0.01,y=0.99,bgcolor="rgba(6,10,20,0.85)",
            bordercolor="#1e2d45",borderwidth=1,font=dict(size=9,color="#94a3b8")))
        return fig

    try:
        m = df.copy()
        m["latitude"]  = pd.to_numeric(m["latitude"],  errors="coerce")
        m["longitude"] = pd.to_numeric(m["longitude"], errors="coerce")
        m = m.dropna(subset=["latitude","longitude"])
        m = m[(m["latitude"].abs()>0.1)|(m["longitude"].abs()>0.1)]
    except:
        m = pd.DataFrame()

    # Group by location for jitter
    if not m.empty:
        loc_counts = {}
        for idx, row in m.iterrows():
            key = (round(row["latitude"],2), round(row["longitude"],2))
            loc_counts[key] = loc_counts.get(key, 0) + 1

        loc_seen = {}
        lats, lons, colors, sizes, hovers, links = [], [], [], [], [], []
        for idx, row in m.iterrows():
            key = (round(row["latitude"],2), round(row["longitude"],2))
            loc_seen[key] = loc_seen.get(key, 0) + 1
            jlat, jlon = add_jitter(row["latitude"], row["longitude"],
                                    loc_seen[key]-1, loc_counts[key])
            sev = str(row.get("severity","low")).lower()
            col = SEV_COLORS.get(sev, "#7dd3fc")
            sz  = {"critical":16,"high":12,"medium":9,"low":7}.get(sev, 8)
            atk  = str(row.get("attack_type","?")).capitalize()
            sec  = str(row.get("sector","?")).capitalize()
            tgt  = str(row.get("target",""))
            ta   = str(row.get("threat_actor",""))
            title = str(row.get("title",""))[:80]
            hover = (f"<b>{title}</b><br>"
                     f"🎯 Tipo: {atk}<br>"
                     f"🏭 Settore: {sec}<br>"
                     f"⚡ Gravità: {sev.upper()}<br>"
                     + (f"🏢 Target: {tgt}<br>" if tgt else "")
                     + (f"👤 Attore: {ta}<br>" if ta else "")
                     + "<br><i>Clicca per aprire la notizia</i>")
            lats.append(jlat); lons.append(jlon)
            colors.append(col); sizes.append(sz)
            hovers.append(hover)
            links.append(str(row.get("link","#")))

        # Pulse rings for critical
        crit_mask = m["severity"]=="critical"
        if crit_mask.any():
            fig.add_trace(go.Scattergeo(
                lon=m.loc[crit_mask,"longitude"].tolist(),
                lat=m.loc[crit_mask,"latitude"].tolist(),
                mode="markers",
                marker=dict(size=[18]*crit_mask.sum(), color="#ff3b3b", opacity=0.15),
                hoverinfo="skip", showlegend=False))
            fig.add_trace(go.Scattergeo(
                lon=m.loc[crit_mask,"longitude"].tolist(),
                lat=m.loc[crit_mask,"latitude"].tolist(),
                mode="markers",
                marker=dict(size=[26]*crit_mask.sum(), color="#ff3b3b", opacity=0.07),
                hoverinfo="skip", showlegend=False))

        # Main markers — one trace per severity level for clean legend
        for sev in SEV_ORDER:
            mask = [c == SEV_COLORS.get(sev,"#7dd3fc") for c in colors]
            sl = [i for i,v in enumerate(mask) if v]
            if not sl: continue
            fig.add_trace(go.Scattergeo(
                lon=[lons[i] for i in sl],
                lat=[lats[i] for i in sl],
                mode="markers",
                marker=dict(
                    size=[sizes[i] for i in sl],
                    color=SEV_COLORS[sev],
                    opacity=0.92,
                    line=dict(width=1.2, color="rgba(255,255,255,0.3)")
                ),
                text=[hovers[i] for i in sl],
                customdata=[links[i] for i in sl],
                hovertemplate="%{text}<extra></extra>",
                name=sev.capitalize(),
                showlegend=True,
            ))

    else:
        # No geodata — still show legend
        for sev,col in SEV_COLORS.items():
            fig.add_trace(go.Scattergeo(lon=[None],lat=[None],mode="markers",
                marker=dict(size=9,color=col),name=sev.capitalize(),showlegend=True))

    fig.update_layout(legend=dict(x=0.01,y=0.99,bgcolor="rgba(6,10,20,0.85)",
        bordercolor="#1e2d45",borderwidth=1,font=dict(size=9,color="#94a3b8")))
    return fig

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
    c=df[df["severity"]!=""]["severity"].value_counts()
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
    st.markdown(f"""<div class="cti-header">
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
    last_ok  = st.session_state.get("_last_ok")
    ts_str   = last_ok.strftime("%H:%M:%S") if last_ok else "—"
    cached_n = len(st.session_state.get("_ev_cache", []))

    if   status=="ok":         st.markdown(f'<span class="st-ok">● WEBHOOK OK — {len(raw)} eventi — {datetime.utcnow().strftime("%H:%M:%S")} UTC</span>', unsafe_allow_html=True)
    elif status=="timeout":    st.markdown(f'<span class="st-err">● TIMEOUT — ngrok lento/offline — cache: {cached_n} eventi (agg. {ts_str})</span>', unsafe_allow_html=True)
    elif status=="conn_error": st.markdown(f'<span class="st-err">● CONNESSIONE RIFIUTATA — avvia ngrok+n8n — cache: {cached_n} eventi</span>', unsafe_allow_html=True)
    elif status=="empty":      st.markdown('<span class="st-warn">● WEBHOOK OK — nessun dato ancora</span>', unsafe_allow_html=True)
    else:                      st.markdown(f'<span class="st-err">● ERRORE: {status.replace("error:","")[:120]}</span>', unsafe_allow_html=True)

    all_df = to_df(raw)

    # ── Filters
    fc1,fc2,fc3,fc4=st.columns([1,1,1,0.5])
    sev_opts=["All"]+[s.capitalize() for s in SEV_ORDER]
    atk_opts=["All"]+sorted({(e.get("attack_type") or "").strip().capitalize() for e in raw if e.get("attack_type")})
    sec_opts=["All"]+sorted({(e.get("sector") or "").strip().capitalize() for e in raw if e.get("sector")})
    with fc1: sev_f=st.selectbox("SEVERITY",    sev_opts, key="fsev")
    with fc2: atk_f=st.selectbox("ATTACK TYPE", atk_opts, key="fatk")
    with fc3: sec_f=st.selectbox("SECTOR",      sec_opts, key="fsec")
    with fc4:
        st.write("")
        if st.button("↺  RESET", use_container_width=True):
            for k in ("fsev","fatk","fsec"): st.session_state[k]="All"
            st.rerun()

    df = apply_filters(all_df.copy(), sev_f, atk_f, sec_f)

    # ── Critical alert
    if not df.empty:
        crit=df[df["severity"]=="critical"]
        if not crit.empty:
            row=crit.iloc[0]
            atk=str(row.get("attack_type","")).upper()
            tgt=str(row.get("target","") or row.get("title",""))[:70]
            st.markdown(f'<div class="alert-banner">⚠&nbsp;&nbsp;CRITICO — {atk} — {tgt}</div>', unsafe_allow_html=True)

    # ── KPI cards
    stats=compute_stats(raw)
    def scard(l,v,c,s): return (f'<div class="stat-card" style="--ac:{c};">'
        f'<div class="stat-label">{l}</div><div class="stat-value" style="color:{c};">{v}</div>'
        f'<div class="stat-sub">{s}</div></div>')
    s1,s2,s3,s4=st.columns(4)
    with s1: st.markdown(scard("Today",     stats["today"],   "#00d4ff","attacchi rilevati"), unsafe_allow_html=True)
    with s2: st.markdown(scard("This Week", stats["week"],    "#7dd3fc","incidenti"),          unsafe_allow_html=True)
    with s3: st.markdown(scard("Month",     stats["month"],   "#93c5fd","eventi tracciati"),   unsafe_allow_html=True)
    with s4: st.markdown(scard("Critical",  stats["critical"],"#ff3b3b","alta priorità"),     unsafe_allow_html=True)

    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)

    # ── Map + sidebar
    mc,sc=st.columns([3,1.25])
    with mc:
        n=len(df)
        geo_n = len(df.dropna(subset=["latitude","longitude"])) if not df.empty else 0
        st.markdown(
            f'<div class="section-title">◈ LIVE THREAT MAP — ITALY'
            f'&nbsp;<span style="color:#4a5568;font-size:.58rem;">{n} EVENTI &nbsp;·&nbsp; {geo_n} GEOLOCALIZZATI</span></div>',
            unsafe_allow_html=True)
        st.plotly_chart(chart_map(df), use_container_width=True, config={"displayModeBar":False})

    with sc:
        st.markdown('<div class="section-title">Settori Colpiti</div>', unsafe_allow_html=True)
        f=chart_sectors(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:14px 0;">In attesa di dati…</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title" style="margin-top:4px;">Tipi di Attacco</div>', unsafe_allow_html=True)
        f=chart_attacks(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:14px 0;">In attesa di dati…</div>', unsafe_allow_html=True)

    # ── Feed + timeline
    bc,tc=st.columns([3,1.25])
    with bc:
        st.markdown('<div class="section-title">Incidenti Recenti</div>', unsafe_allow_html=True)
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
            st.markdown(f'<div class="feed-wrap">{html}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="feed-wrap" style="padding:20px;color:#4a5568;font-size:.7rem;">In attesa di dati dal webhook…</div>', unsafe_allow_html=True)

    with tc:
        st.markdown('<div class="section-title">Timeline 24h</div>', unsafe_allow_html=True)
        f=chart_timeline(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:12px 0;">Nessun evento 24h</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title" style="margin-top:4px;">Severity</div>', unsafe_allow_html=True)
        f=chart_severity(df)
        if f: st.plotly_chart(f, use_container_width=True, config={"displayModeBar":False})
        else: st.markdown('<div style="color:#4a5568;font-size:.7rem;padding:12px 0;">Nessun dato</div>', unsafe_allow_html=True)

    # ── Regional ranking
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">Ranking Target</div>', unsafe_allow_html=True)
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
            st.markdown(f'<div style="background:#0d1321;border:1px solid #1e2d45;padding:10px 16px;">{rhtml}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="background:#0d1321;border:1px solid #1e2d45;padding:14px 16px;color:#4a5568;font-size:.7rem;">Nessun dato</div>', unsafe_allow_html=True)

    st.markdown(
        f'<div style="margin-top:14px;padding-top:10px;border-top:1px solid #1e2d45;display:flex;justify-content:space-between;">'
        f'<div style="font-size:.54rem;color:#4a5568;letter-spacing:2px;">AUTO-REFRESH 30s · n8n WEBHOOK · TOTALE: {stats["total"]} eventi</div>'
        f'<div style="font-size:.54rem;color:#4a5568;">CTIMAP v5</div></div>',
        unsafe_allow_html=True)

    try:
        from streamlit_autorefresh import st_autorefresh  # noqa
    except ImportError:
        time.sleep(30)
        st.rerun()

main()
