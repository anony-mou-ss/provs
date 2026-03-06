"""
ITALY & WORLD CYBER THREAT MAP  v7.0
Fonte unica: ransomware.live API (https://api.ransomware.live)

Endpoints usati:
  GET /recentvictims   → ultime 100 vittime (aggiornato in quasi real-time)
  GET /victims         → archivio esteso
  GET /stats           → totali globali

Architettura:
  st.cache_data(ttl=60) → fetch ogni 60s senza thread
  st_autorefresh(60s)   → rerun automatico ogni minuto
  main() chiamato direttamente a module level

pip install streamlit plotly requests pandas streamlit-autorefresh
streamlit run italy_cybermap.py
"""

import re, hashlib, random, time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import streamlit as st
import plotly.graph_objects as go
import requests
import pandas as pd

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AR = True
except ImportError:
    HAS_AR = False

# ── PAGE CONFIG ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="Ransomware Live Map",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600&display=swap');
:root{--bg:#0a0c0f;--card:#141920;--brd:#1e2730;
      --red:#ff3b30;--ora:#ff9f0a;--grn:#30d158;--dim:#586374;--txt:#c8d0dc;}
html,body,[class*="css"]{background:var(--bg)!important;color:var(--txt)!important;
  font-family:'IBM Plex Sans',sans-serif!important;}
[data-testid="stSidebar"]{background:#0f1318!important;border-right:1px solid var(--brd)!important;}
[data-testid="stSidebar"] *{color:var(--txt)!important;}
[data-testid="metric-container"]{background:var(--card)!important;border:1px solid var(--brd)!important;
  border-radius:6px!important;padding:12px 16px!important;}
[data-testid="metric-container"] label{color:var(--dim)!important;
  font-family:'IBM Plex Mono',monospace!important;font-size:.65rem!important;
  text-transform:uppercase;letter-spacing:.1em;}
[data-testid="metric-container"] [data-testid="stMetricValue"]{
  font-family:'IBM Plex Mono',monospace!important;font-size:1.5rem!important;color:var(--red)!important;}
.stMultiSelect>div>div,.stTextInput>div>div,.stDateInput>div>div,.stSelectbox>div>div{
  background:var(--card)!important;border:1px solid var(--brd)!important;color:var(--txt)!important;}
.stButton>button{background:transparent!important;border:1px solid var(--red)!important;
  color:var(--red)!important;font-family:'IBM Plex Mono',monospace!important;
  font-size:.7rem!important;border-radius:3px!important;}
hr{border-color:var(--brd)!important;}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}
#MainMenu,footer,header{visibility:hidden!important;}
.block-container{padding-top:1.2rem!important;}

/* ── Cards stile ransomware.live ────────────────────────────────── */
.vcard{
  background:var(--card);border:1px solid var(--brd);border-radius:6px;
  padding:12px 14px;margin-bottom:8px;border-left:3px solid var(--red);
  transition:border-color .2s;
}
.vcard.med{border-left-color:var(--ora);}
.vcard.low{border-left-color:var(--grn);}
.vcard.nw{animation:sld .4s ease-out;}
@keyframes sld{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:none}}
.vname{font-weight:600;font-size:.88rem;color:#e8ecf0;margin-bottom:4px;}
.vname a{color:#e8ecf0;text-decoration:none;}.vname a:hover{color:var(--red);}
.vmeta{font-family:'IBM Plex Mono',monospace;font-size:.61rem;color:var(--dim);
  line-height:1.8;margin-bottom:4px;}
.vdesc{font-size:.73rem;color:var(--dim);line-height:1.45;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}
.tag{display:inline-block;padding:2px 8px;border-radius:3px;font-family:'IBM Plex Mono',monospace;
  font-size:.6rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;margin-right:4px;}
.tg{background:#1a2a1a;color:var(--grn);border:1px solid #1a4a1a;}   /* group */
.tc{background:#1a1f2a;color:#7eb3d4;border:1px solid #2a3a4d;}       /* country */
.ts{background:#2a1a2a;color:#c07aff;border:1px solid #4a2a6a;}       /* sector */
.tl{background:#0d2418;color:var(--grn);border:1px solid var(--grn);animation:blk .6s step-end 5;} /* new */
.tcr{background:#3d1515;color:var(--red);border:1px solid var(--red);}   /* critical */
.tmd{background:#2d1f08;color:var(--ora);border:1px solid var(--ora);}   /* medium */
@keyframes blk{50%{opacity:0}}

/* ── Status / pulse ─────────────────────────────────────────────── */
.pulse{display:inline-block;width:7px;height:7px;background:var(--red);
  border-radius:50%;margin-right:6px;animation:pls 1.4s infinite;vertical-align:middle;}
@keyframes pls{0%{box-shadow:0 0 0 0 rgba(255,59,48,.7)}
  70%{box-shadow:0 0 0 7px rgba(255,59,48,0)}100%{box-shadow:0 0 0 0 rgba(255,59,48,0)}}
.sbar{font-family:'IBM Plex Mono',monospace;font-size:.61rem;color:var(--dim);padding:4px 0;}
</style>
""", unsafe_allow_html=True)

# ── CONSTANTS ─────────────────────────────────────────────────────────
TZ  = ZoneInfo("Europe/Rome")
HDR = {"User-Agent": "Mozilla/5.0 RansomwareMap/7.0", "Accept": "application/json"}

# ── GEO: country → (lat, lon) ─────────────────────────────────────────
# Coordinate dei centroidi nazionali per la mappa
COUNTRY_GEO = {
    "Italy":(41.87,12.57),"Italia":(41.87,12.57),
    "United States":(37.09,-95.71),"United States of America":(37.09,-95.71),"USA":(37.09,-95.71),
    "United Kingdom":(55.37,-3.44),"UK":(55.37,-3.44),
    "Germany":(51.17,10.45),"France":(46.23,2.21),
    "Spain":(40.46,-3.75),"Italy":(41.87,12.57),
    "Canada":(56.13,-106.35),"Australia":(-25.27,133.78),
    "Japan":(36.20,138.25),"China":(35.86,104.19),
    "Brazil":(-14.24,-51.93),"Mexico":(23.63,-102.55),
    "India":(20.59,78.96),"Russia":(61.52,105.32),
    "Netherlands":(52.13,5.29),"Belgium":(50.50,4.47),
    "Switzerland":(46.82,8.23),"Austria":(47.52,14.55),
    "Sweden":(60.13,18.64),"Norway":(60.47,8.47),
    "Denmark":(56.26,9.50),"Finland":(61.92,25.75),
    "Poland":(51.92,19.14),"Czech Republic":(49.82,15.47),
    "Romania":(45.94,24.97),"Hungary":(47.16,19.50),
    "Portugal":(39.40,-8.22),"Greece":(39.07,21.82),
    "Turkey":(38.96,35.24),"Israel":(31.05,34.85),
    "Saudi Arabia":(23.89,45.08),"UAE":(23.42,53.85),
    "South Africa":(-30.56,22.94),"Argentina":(-38.42,-63.62),
    "Chile":(-35.68,-71.54),"Colombia":(4.57,-74.30),
    "South Korea":(35.91,127.77),"Taiwan":(23.70,121.00),
    "Singapore":(1.35,103.82),"Thailand":(15.87,100.99),
    "Indonesia":(-0.79,113.92),"Malaysia":(4.21,101.98),
    "New Zealand":(-40.90,174.89),"Ireland":(53.41,-8.24),
    "Luxembourg":(49.82,6.13),"Slovakia":(48.67,19.70),
    "Slovenia":(46.15,14.99),"Croatia":(45.10,15.20),
    "Serbia":(44.02,21.01),"Ukraine":(48.38,31.17),
    "Bulgaria":(42.73,25.49),"Lithuania":(55.17,23.88),
    "Latvia":(56.88,24.60),"Estonia":(58.60,25.01),
    "Cyprus":(35.13,33.43),"Malta":(35.94,14.37),
    "Iceland":(64.96,-19.02),"Liechtenstein":(47.17,9.56),
    "Monaco":(43.73,7.40),"Andorra":(42.55,1.60),
    "N/A":(0.0,0.0),"Unknown":(0.0,0.0),"":( 0.0,0.0),
}

def _geo(country):
    """Restituisce (lat, lon) dal nome nazione, con jitter."""
    c = (country or "").strip()
    coords = COUNTRY_GEO.get(c)
    if not coords:
        # Cerca parziale
        for k, v in COUNTRY_GEO.items():
            if k.lower() in c.lower() or c.lower() in k.lower():
                coords = v
                break
    if not coords or coords == (0.0, 0.0):
        # Fallback random su mappa mondo
        coords = (random.uniform(-50, 70), random.uniform(-150, 150))
    lat = coords[0] + random.uniform(-0.8, 0.8)
    lon = coords[1] + random.uniform(-0.8, 0.8)
    return round(lat, 4), round(lon, 4)

# ── FETCH ─────────────────────────────────────────────────────────────

def _parse_date(s):
    if not s: return datetime.now(TZ)
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:26], fmt).replace(
                tzinfo=ZoneInfo("UTC")).astimezone(TZ)
        except: pass
    return datetime.now(TZ)

def _sev(group):
    g = (group or "").lower()
    # Gruppi noti come high-severity
    if any(x in g for x in ["lockbit","cl0p","blackcat","alphv","rhysida",
                              "akira","play","royal","conti","hive","darkside",
                              "medusa","scatter","dragonforce","qilin","hunters"]):
        return "critical"
    return "medium"

@st.cache_data(ttl=60, show_spinner=False)
def fetch_victims():
    """
    Chiama ransomware.live API.
    Endpoint primario: /recentvictims (ultime 100)
    Endpoint secondario: /victims (archivio)
    Ritorna lista di dict normalizzati.
    """
    all_victims = []
    seen = set()

    endpoints = [
        "https://api.ransomware.live/recentvictims",
        "https://api.ransomware.live/victims",
    ]

    for ep in endpoints:
        try:
            r = requests.get(ep, timeout=20, headers=HDR)
            if not r.ok:
                continue
            data = r.json()
            # Normalizza struttura risposta
            if isinstance(data, dict):
                data = (data.get("data") or data.get("victims")
                        or data.get("result") or list(data.values())[0]
                        if data else [])
            if not isinstance(data, list):
                continue

            for v in data:
                if not isinstance(v, dict):
                    continue

                # Campi API ransomware.live
                victim   = (v.get("victim")      or v.get("name")      or
                            v.get("company")     or v.get("target")    or "").strip()
                group    = (v.get("group")        or v.get("ransomware_group") or
                            v.get("gang")        or "unknown").strip()
                country  = (v.get("country")      or v.get("Country")  or
                            v.get("nationality") or "Unknown").strip()
                domain   = (v.get("domain")       or v.get("website")  or
                            v.get("url")         or "").strip().lower()
                desc     = (v.get("description")  or v.get("summary")  or
                            v.get("details")     or "").strip()
                # Rimuovi HTML dal desc
                desc = re.sub(r"<[^>]+>", "", desc)
                sector   = (v.get("activity")     or v.get("sector")   or
                            v.get("industry")    or "").strip()
                raw_date = (v.get("discovered")   or v.get("published") or
                            v.get("date")        or v.get("added")     or
                            v.get("created_at")  or "")
                link     = (v.get("post")         or v.get("url")      or
                            v.get("link")        or
                            f"https://www.ransomware.live/#victim={victim}")
                # Stima data attacco
                atk_date = (v.get("infostealer")  or v.get("attack_date") or
                            v.get("estimated_attack") or "")

                if not victim:
                    continue

                uid = hashlib.md5(f"{victim}{group}".lower().encode()).hexdigest()[:10]
                if uid in seen:
                    continue
                seen.add(uid)

                pub = _parse_date(raw_date)
                lat, lon = _geo(country)

                all_victims.append({
                    "id":      uid,
                    "victim":  victim,
                    "group":   group,
                    "country": country,
                    "domain":  domain,
                    "desc":    desc[:400] if desc else "",
                    "sector":  sector,
                    "link":    link,
                    "pub":     pub,
                    "ts":      pub.strftime("%d/%m/%Y %H:%M"),
                    "date_str":pub.strftime("%Y-%m-%d"),
                    "lat":     lat,
                    "lon":     lon,
                    "sev":     _sev(group),
                    "is_italy":(country.lower() in ("italy","italia")
                                or domain.endswith(".it")),
                })
        except Exception:
            continue

    # Ordine: più recenti prima
    all_victims.sort(key=lambda x: x["pub"], reverse=True)
    return all_victims


@st.cache_data(ttl=300, show_spinner=False)
def fetch_stats():
    """Statistiche globali da ransomware.live."""
    try:
        r = requests.get("https://api.ransomware.live/stats", timeout=10, headers=HDR)
        if r.ok:
            return r.json()
    except:
        pass
    return {}


# ── MAP ───────────────────────────────────────────────────────────────
SC  = {"critical": "#ff3b30", "medium": "#ff9f0a", "low": "#30d158"}
SG  = {"critical": "rgba(255,59,48,.18)", "medium": "rgba(255,159,10,.18)", "low": "rgba(48,209,88,.18)"}
SS  = {"critical": 12, "medium": 9, "low": 7}
SGS = {"critical": 24, "medium": 18, "low": 13}

def build_map(victims, focus_italy=False):
    df = pd.DataFrame(victims) if victims else pd.DataFrame()
    fig = go.Figure()

    if len(df) == 0:
        fig.update_layout(
            paper_bgcolor="#0a0c0f", plot_bgcolor="#0a0c0f",
            height=600, margin=dict(l=0,r=0,t=0,b=0),
            mapbox=dict(style="carto-darkmatter",
                        center=dict(lat=20, lon=10), zoom=1.2),
        )
        return fig

    for sev in ["critical", "medium"]:
        sub = df[df["sev"] == sev]
        if sub.empty:
            continue

        hover = [
            f"<b>{r['victim']}</b><br>"
            f"<span style='color:#c07aff'>🔓 {r['group'].upper()}</span><br>"
            f"<span style='color:#7eb3d4'>🌍 {r['country']}</span><br>"
            f"<span style='color:#586374'>📅 {r['date_str']}</span>"
            + (f"<br><span style='color:#586374'>🏭 {r['sector']}</span>" if r.get("sector") else "")
            for _, r in sub.iterrows()
        ]

        lons, lats = sub["lon"].tolist(), sub["lat"].tolist()
        links = sub["link"].tolist()

        # Glow esterno
        fig.add_trace(go.Scattermapbox(
            lon=lons, lat=lats, mode="markers", name=f"_g{sev}",
            marker=dict(size=SGS[sev], color=SG[sev], opacity=.6),
            hoverinfo="skip", showlegend=False,
        ))
        # Core marker
        fig.add_trace(go.Scattermapbox(
            lon=lons, lat=lats, mode="markers", name=sev.upper(),
            marker=dict(size=SS[sev], color=SC[sev], opacity=.92),
            text=hover, hovertemplate="%{text}<extra></extra>",
            customdata=links,
        ))

    center = dict(lat=42.5, lon=12.5) if focus_italy else dict(lat=20, lon=10)
    zoom   = 4.8 if focus_italy else 1.5

    fig.update_layout(
        paper_bgcolor="#0a0c0f", plot_bgcolor="#0a0c0f",
        height=610, margin=dict(l=0,r=0,t=0,b=0),
        mapbox=dict(
            style="carto-darkmatter",
            center=center, zoom=zoom,
        ),
        legend=dict(
            orientation="h", yanchor="bottom", y=0.02, xanchor="left", x=0.01,
            bgcolor="rgba(10,12,15,.85)", bordercolor="#1e2730", borderwidth=1,
            font=dict(family="IBM Plex Mono", size=10, color="#c8d0dc"),
            itemsizing="constant",
        ),
        hoverlabel=dict(bgcolor="#0f1318", bordercolor="#2a3540",
                        font=dict(family="IBM Plex Sans", size=12, color="#c8d0dc"),
                        align="left"),
        dragmode="pan",
        uirevision="rw_map",
    )
    for tr in fig.data:
        if tr.name and tr.name.startswith("_"):
            tr.showlegend = False
    return fig


# ── CARD HTML ─────────────────────────────────────────────────────────
FLAG = {
    "Italy":"🇮🇹","Italia":"🇮🇹","United States":"🇺🇸","United States of America":"🇺🇸",
    "United Kingdom":"🇬🇧","Germany":"🇩🇪","France":"🇫🇷","Spain":"🇪🇸",
    "Canada":"🇨🇦","Australia":"🇦🇺","Japan":"🇯🇵","China":"🇨🇳",
    "Brazil":"🇧🇷","Mexico":"🇲🇽","India":"🇮🇳","Russia":"🇷🇺",
    "Netherlands":"🇳🇱","Belgium":"🇧🇪","Switzerland":"🇨🇭","Austria":"🇦🇹",
    "Sweden":"🇸🇪","Norway":"🇳🇴","Denmark":"🇩🇰","Finland":"🇫🇮",
    "Poland":"🇵🇱","Portugal":"🇵🇹","Greece":"🇬🇷","Turkey":"🇹🇷",
    "Israel":"🇮🇱","South Africa":"🇿🇦","Argentina":"🇦🇷","South Korea":"🇰🇷",
    "Singapore":"🇸🇬","Taiwan":"🇹🇼","Ireland":"🇮🇪","Romania":"🇷🇴",
    "Ukraine":"🇺🇦","Czech Republic":"🇨🇿","Hungary":"🇭🇺","Slovakia":"🇸🇰",
}

def _flag(country):
    return FLAG.get(country, "🌍")

def _card(v, is_new=False):
    sev  = v["sev"]
    cls  = "" if sev == "critical" else "med"
    nw   = "nw" if is_new else ""
    link = v.get("link", "#")
    fl   = _flag(v["country"])
    bn   = '<span class="tag tl">● NEW</span>' if is_new else ""
    sc   = "tcr" if sev == "critical" else "tmd"
    desc = v.get("desc","")
    dom  = f'<span style="color:#586374;font-size:.6rem">{v["domain"]}</span> · ' if v.get("domain") else ""

    return (
        f'<div class="vcard {cls} {nw}">'
        f'<div class="vname"><a href="{link}" target="_blank">{v["victim"]}</a></div>'
        f'<div class="vmeta">'
        f'{bn}'
        f'<span class="tag tg">{v["group"]}</span>'
        f'<span class="tag tc">{fl} {v["country"]}</span>'
        + (f'<span class="tag ts">{v["sector"]}</span>' if v.get("sector") else "")
        + f'<br>{dom}📅 {v["date_str"]}'
        f'</div>'
        + (f'<div class="vdesc">{desc[:180]}{"…" if len(desc)>180 else ""}</div>' if desc else "")
        + f'</div>'
    )


# ── MAIN ──────────────────────────────────────────────────────────────
def main():
    # Autorefresh ogni 60s (uguale al TTL cache)
    if HAS_AR:
        st_autorefresh(interval=60_000, limit=None, key="ar")

    # ── Fetch ─────────────────────────────────────────────────────────
    with st.spinner("Caricamento dati ransomware.live…"):
        victims = fetch_victims()
    stats   = fetch_stats()

    if not victims:
        st.error("⚠️ Impossibile contattare ransomware.live — riprova tra qualche secondo.")
        st.info("Assicurati che Streamlit abbia accesso a internet (api.ransomware.live)")
        st.stop()

    # ── Traccia nuovi (vs sessione precedente) ────────────────────────
    prev_ids = st.session_state.get("prev_ids", set())
    new_ids  = {v["id"] for v in victims} - prev_ids
    st.session_state["prev_ids"] = {v["id"] for v in victims}

    # ── Header ────────────────────────────────────────────────────────
    now = datetime.now(TZ)
    st.markdown(
        f"""<div style='display:flex;align-items:center;margin-bottom:4px;'>
          <div style='font-family:"IBM Plex Mono",monospace;font-size:1.4rem;
                      font-weight:600;color:#e8ecf0;letter-spacing:-.02em;'>
            <span style='color:#ff3b30'>◈</span> RANSOMWARE LIVE MAP
          </div>
          <div style='margin-left:auto;font-family:"IBM Plex Mono",monospace;
                      font-size:.6rem;color:#586374;'>
            fonte: ransomware.live · aggiornato ogni 60s
          </div>
        </div>""", unsafe_allow_html=True)

    # ── Sidebar ───────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.7rem;
          color:#586374;letter-spacing:.12em;text-transform:uppercase;
          padding:4px 0 14px;border-bottom:1px solid #1e2730;margin-bottom:14px;'>
          ◈ FILTERS</div>""", unsafe_allow_html=True)

        # Toggle Italia / Mondo
        view_mode = st.radio("VISTA", ["🌍 Tutto il mondo", "🇮🇹 Solo Italia"],
                             index=0, horizontal=True)
        only_italy = "Italia" in view_mode

        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

        # Gruppi disponibili
        avail_groups = sorted(set(v["group"] for v in victims))
        sel_groups   = st.multiselect("GRUPPO RANSOMWARE", avail_groups,
                                      default=[], placeholder="Tutti i gruppi")

        # Paesi
        avail_countries = sorted(set(v["country"] for v in victims if v["country"] not in ("Unknown","N/A","")))
        sel_countries   = st.multiselect("PAESE", avail_countries,
                                         default=[], placeholder="Tutti i paesi")

        # Settore
        avail_sectors = sorted(set(v["sector"] for v in victims if v.get("sector")))
        sel_sectors   = st.multiselect("SETTORE", avail_sectors,
                                       default=[], placeholder="Tutti i settori")

        # Date
        today = datetime.now().date()
        c1, c2 = st.columns(2)
        with c1: d_from = st.date_input("DA",  value=today - timedelta(days=30))
        with c2: d_to   = st.date_input("A",   value=today)

        # Severity
        sel_sev = st.multiselect("SEVERITY", ["critical","medium"],
                                 default=["critical","medium"], format_func=str.upper)

        search = st.text_input("🔍 CERCA", placeholder="lockbit, ospedale, milano…")

        st.markdown("<hr style='border-color:#1e2730;margin:10px 0'>", unsafe_allow_html=True)
        if st.button("↺  RESET FILTRI"):
            st.rerun()

        # Info sidebar
        n_it = sum(1 for v in victims if v["is_italy"])
        n_gr = len(set(v["group"] for v in victims))
        st.markdown(f"""<div style='font-family:"IBM Plex Mono",monospace;font-size:.56rem;
          color:#586374;margin-top:14px;line-height:1.9;'>
          <span style='color:#30d158'>● DATI LIVE</span><br>
          Vittime totali: <span style='color:#e8ecf0'>{len(victims)}</span><br>
          Vittime italiane: <span style='color:#ff3b30'>{n_it}</span><br>
          Gruppi attivi: <span style='color:#ff9f0a'>{n_gr}</span><br>
          <br>
          FONTE: ransomware.live<br>
          CACHE TTL: 60s<br>
          AUTOREFRESH: {"60s" if HAS_AR else "manuale (installa streamlit-autorefresh)"}<br>
          ULTIMO FETCH: {now.strftime('%H:%M:%S')}
        </div>""", unsafe_allow_html=True)

    # ── Filtro ────────────────────────────────────────────────────────
    filtered = victims
    if only_italy:
        filtered = [v for v in filtered if v["is_italy"]]
    if sel_groups:
        filtered = [v for v in filtered if v["group"] in sel_groups]
    if sel_countries:
        filtered = [v for v in filtered if v["country"] in sel_countries]
    if sel_sectors:
        filtered = [v for v in filtered if v.get("sector") in sel_sectors]
    if sel_sev:
        filtered = [v for v in filtered if v["sev"] in sel_sev]
    filtered = [v for v in filtered
                if d_from <= v["pub"].date() <= d_to]
    if search:
        q = search.lower()
        filtered = [v for v in filtered
                    if q in v["victim"].lower()
                    or q in v["group"].lower()
                    or q in v["country"].lower()
                    or q in (v.get("desc","")).lower()
                    or q in (v.get("sector","")).lower()
                    or q in (v.get("domain","")).lower()]

    # ── KPI ───────────────────────────────────────────────────────────
    tot_v   = stats.get("victims", len(victims)) if stats else len(victims)
    tot_gr  = stats.get("groups", len(set(v["group"] for v in victims))) if stats else len(set(v["group"] for v in victims))
    tot_mo  = stats.get("this_month", sum(1 for v in victims if
                         v["pub"].month == now.month and v["pub"].year == now.year))
    n_it    = sum(1 for v in filtered if v["is_italy"]) if not only_italy else len(filtered)
    n_crit  = sum(1 for v in filtered if v["sev"] == "critical")

    k1,k2,k3,k4,k5 = st.columns(5)
    k1.metric("VITTIME TOTALI", f"{tot_v:,}")
    k2.metric("GRUPPI ATTIVI", tot_gr)
    k3.metric("QUESTO MESE", tot_mo)
    k4.metric("🇮🇹 ITALIANE", n_it)
    k5.metric("⬤ CRITICAL", n_crit)

    # ── Status bar ────────────────────────────────────────────────────
    nxt = 60 - (int(time.time()) % 60)
    new_html = (f' · <span style="color:#30d158;font-weight:600">+{len(new_ids)} nuovi</span>'
                if new_ids else "")
    st.markdown(
        f"""<div class="sbar"><span class="pulse"></span>
        LIVE · {now.strftime('%d/%m/%Y %H:%M:%S')} IT ·
        {len(filtered)} eventi visualizzati · refresh ~{nxt}s{new_html}</div>""",
        unsafe_allow_html=True)

    # ── Layout mappa + feed ───────────────────────────────────────────
    map_col, feed_col = st.columns([3, 1.5], gap="medium")

    with map_col:
        fig = build_map(filtered, focus_italy=only_italy)
        st.plotly_chart(fig, use_container_width=True,
            config={"scrollZoom": True, "displayModeBar": True, "displaylogo": False,
                    "modeBarButtonsToRemove": ["select2d","lasso2d"],
                    "toImageButtonOptions": {"format":"png","filename":"ransomware_map"}})
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.6rem;
          color:#586374;text-align:center;margin-top:-8px;'>
          HOVER → DETTAGLIO · SCROLL TO ZOOM · DRAG TO PAN ·
          <a href="https://www.ransomware.live" target="_blank"
             style="color:#586374;">ransomware.live ↗</a></div>""",
                    unsafe_allow_html=True)

    with feed_col:
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.63rem;
          color:#586374;letter-spacing:.1em;text-transform:uppercase;
          padding-bottom:8px;border-bottom:1px solid #1e2730;margin-bottom:10px;'>
          ◈ VITTIME RECENTI</div>""", unsafe_allow_html=True)

        if not filtered:
            st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;
              font-size:.75rem;color:#586374;text-align:center;padding:40px 0;'>
              <div style='font-size:1.4rem;margin-bottom:8px'>◌</div>
              Nessuna vittima con i filtri selezionati.</div>""",
                        unsafe_allow_html=True)
        else:
            html = "".join(
                _card(v, is_new=(v["id"] in new_ids))
                for v in filtered[:200]
            )
            with st.container(height=620):
                st.markdown(html, unsafe_allow_html=True)

    if not HAS_AR:
        st.warning(
            "Aggiungi 'streamlit-autorefresh' a requirements.txt per aggiornamento automatico ogni 60s."
        )


main()
