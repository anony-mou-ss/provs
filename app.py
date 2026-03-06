"""
╔══════════════════════════════════════════════════════════════════╗
║         ITALY CYBER THREAT LIVE MAP — by @yourhandle            ║
║         Real-time cyber attack monitoring dashboard             ║
║         Sources: ransomware.live, darkfeed, cybersecurity feeds ║
╚══════════════════════════════════════════════════════════════════╝

Deps: streamlit, plotly, requests, feedparser, pandas, pytz
Run:  streamlit run italy_cybermap.py
"""

import streamlit as st
import plotly.graph_objects as go
import requests
import feedparser
import pandas as pd
import json
import re
import time
import random
import hashlib
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from typing import Optional

# ─────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Italy Cyber Threat Map",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
#  DARK THEME CSS — industrial / terminal aesthetic
# ─────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');

  :root {
    --bg:        #0a0c0f;
    --surface:   #0f1318;
    --card:      #141920;
    --border:    #1e2730;
    --accent:    #ff3b30;
    --accent2:   #ff9f0a;
    --accent3:   #30d158;
    --text:      #c8d0dc;
    --text-dim:  #586374;
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
  }

  html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--sans) !important;
  }

  /* Sidebar */
  [data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border) !important;
  }
  [data-testid="stSidebar"] * { color: var(--text) !important; }

  /* Headers */
  h1, h2, h3, h4 {
    font-family: var(--mono) !important;
    letter-spacing: -0.02em;
    color: #e8ecf0 !important;
  }

  /* Metrics */
  [data-testid="metric-container"] {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    padding: 12px 16px !important;
  }
  [data-testid="metric-container"] label {
    color: var(--text-dim) !important;
    font-family: var(--mono) !important;
    font-size: 0.65rem !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }
  [data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-family: var(--mono) !important;
    font-size: 1.6rem !important;
    color: var(--accent) !important;
  }

  /* Selectbox / multiselect */
  .stSelectbox > div > div,
  .stMultiSelect > div > div {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 4px !important;
    color: var(--text) !important;
  }

  /* Date input */
  .stDateInput > div > div {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
  }

  /* Buttons */
  .stButton > button {
    background: transparent !important;
    border: 1px solid var(--accent) !important;
    color: var(--accent) !important;
    font-family: var(--mono) !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    border-radius: 3px !important;
    transition: all 0.2s;
  }
  .stButton > button:hover {
    background: var(--accent) !important;
    color: #fff !important;
  }

  /* Dividers */
  hr { border-color: var(--border) !important; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* Feed cards */
  .feed-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 4px;
    padding: 10px 14px;
    margin-bottom: 8px;
    font-family: var(--sans);
    transition: border-color 0.2s;
  }
  .feed-card:hover { border-left-color: var(--accent2); }
  .feed-card.medium { border-left-color: var(--accent2); }
  .feed-card.low    { border-left-color: var(--accent3); }

  .feed-title {
    font-weight: 600;
    font-size: 0.82rem;
    color: #e8ecf0;
    margin-bottom: 3px;
    line-height: 1.3;
  }
  .feed-meta {
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--text-dim);
    margin-bottom: 4px;
  }
  .feed-desc {
    font-size: 0.75rem;
    color: var(--text-dim);
    line-height: 1.4;
  }
  .badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 2px;
    font-family: var(--mono);
    font-size: 0.6rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    margin-right: 4px;
    text-transform: uppercase;
  }
  .badge-critical { background: #3d1515; color: var(--accent); border: 1px solid var(--accent); }
  .badge-medium   { background: #2d1f08; color: var(--accent2); border: 1px solid var(--accent2); }
  .badge-low      { background: #0d2418; color: var(--accent3); border: 1px solid var(--accent3); }
  .badge-region   { background: #1a1f2a; color: #7eb3d4; border: 1px solid #2a3a4d; }

  .pulse-dot {
    display: inline-block;
    width: 7px; height: 7px;
    background: var(--accent);
    border-radius: 50%;
    margin-right: 6px;
    animation: pulse 1.4s infinite;
    vertical-align: middle;
  }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(255,59,48,0.7); }
    70%  { box-shadow: 0 0 0 7px rgba(255,59,48,0); }
    100% { box-shadow: 0 0 0 0 rgba(255,59,48,0); }
  }

  .status-bar {
    font-family: var(--mono);
    font-size: 0.62rem;
    color: var(--text-dim);
    padding: 4px 0;
    letter-spacing: 0.05em;
  }

  /* Hide Streamlit branding */
  #MainMenu, footer, header { visibility: hidden !important; }
  .block-container { padding-top: 1.2rem !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  ITALIAN CITIES / REGIONS GEO DATABASE
# ─────────────────────────────────────────────
ITALIAN_CITIES = {
    # Città → (lat, lon, regione)
    "roma": (41.9028, 12.4964, "Lazio"),
    "milan": (45.4654, 9.1859, "Lombardia"),
    "milano": (45.4654, 9.1859, "Lombardia"),
    "napoli": (40.8518, 14.2681, "Campania"),
    "naples": (40.8518, 14.2681, "Campania"),
    "torino": (45.0703, 7.6869, "Piemonte"),
    "turin": (45.0703, 7.6869, "Piemonte"),
    "palermo": (38.1157, 13.3615, "Sicilia"),
    "genova": (44.4056, 8.9463, "Liguria"),
    "genoa": (44.4056, 8.9463, "Liguria"),
    "bologna": (44.4949, 11.3426, "Emilia-Romagna"),
    "firenze": (43.7696, 11.2558, "Toscana"),
    "florence": (43.7696, 11.2558, "Toscana"),
    "bari": (41.1171, 16.8719, "Puglia"),
    "catania": (37.5079, 15.0830, "Sicilia"),
    "venezia": (45.4408, 12.3155, "Veneto"),
    "venice": (45.4408, 12.3155, "Veneto"),
    "verona": (45.4384, 10.9916, "Veneto"),
    "messina": (38.1938, 15.5540, "Sicilia"),
    "padova": (45.4064, 11.8768, "Veneto"),
    "trieste": (45.6495, 13.7768, "Friuli-Venezia Giulia"),
    "taranto": (40.4644, 17.2470, "Puglia"),
    "brescia": (45.5416, 10.2118, "Lombardia"),
    "reggio": (38.1147, 15.6615, "Calabria"),
    "modena": (44.6471, 10.9252, "Emilia-Romagna"),
    "prato": (43.8777, 11.1023, "Toscana"),
    "parma": (44.8015, 10.3279, "Emilia-Romagna"),
    "perugia": (43.1107, 12.3908, "Umbria"),
    "cagliari": (39.2238, 9.1217, "Sardegna"),
    "livorno": (43.5485, 10.3106, "Toscana"),
    "catanzaro": (38.9098, 16.5872, "Calabria"),
    "bergamo": (45.6983, 9.6773, "Lombardia"),
    "trento": (46.0748, 11.1217, "Trentino-Alto Adige"),
    "ancona": (43.6158, 13.5189, "Marche"),
    "lecce": (40.3515, 18.1750, "Puglia"),
    "pescara": (42.4606, 14.2156, "Abruzzo"),
    "udine": (46.0711, 13.2344, "Friuli-Venezia Giulia"),
    "salerno": (40.6824, 14.7681, "Campania"),
    "pisa": (43.7228, 10.4017, "Toscana"),
    "ravenna": (44.4175, 12.2035, "Emilia-Romagna"),
    "foggia": (41.4621, 15.5446, "Puglia"),
    "rimini": (44.0678, 12.5695, "Emilia-Romagna"),
    "siracusa": (37.0755, 15.2866, "Sicilia"),
    "ferrara": (44.8381, 11.6198, "Emilia-Romagna"),
    "sassari": (40.7259, 8.5557, "Sardegna"),
    "monza": (45.5845, 9.2744, "Lombardia"),
    "reggio emilia": (44.6989, 10.6297, "Emilia-Romagna"),
    "latina": (41.4677, 12.9035, "Lazio"),
    "giugliano": (40.9314, 14.1958, "Campania"),
    "l'aquila": (42.3498, 13.3995, "Abruzzo"),
    "potenza": (40.6404, 15.8057, "Basilicata"),
    "campobasso": (41.5603, 14.6564, "Molise"),
    "aosta": (45.7373, 7.3154, "Valle d'Aosta"),
    "italia": (42.5, 12.5, "Nazionale"),
    "italy": (42.5, 12.5, "Nazionale"),
}

REGIONS_COORDS = {
    "Lazio":                    (41.9028, 12.4964),
    "Lombardia":                (45.4654, 9.1859),
    "Campania":                 (40.8518, 14.2681),
    "Piemonte":                 (45.0703, 7.6869),
    "Sicilia":                  (37.5999, 14.0154),
    "Liguria":                  (44.4056, 8.9463),
    "Emilia-Romagna":           (44.4949, 11.3426),
    "Toscana":                  (43.7696, 11.2558),
    "Puglia":                   (41.1171, 16.8719),
    "Veneto":                   (45.4408, 12.3155),
    "Friuli-Venezia Giulia":    (45.6495, 13.7768),
    "Trentino-Alto Adige":      (46.0748, 11.1217),
    "Umbria":                   (43.1107, 12.3908),
    "Sardegna":                 (39.2238, 9.1217),
    "Calabria":                 (38.9098, 16.5872),
    "Marche":                   (43.6158, 13.5189),
    "Abruzzo":                  (42.3498, 13.3995),
    "Basilicata":               (40.6404, 15.8057),
    "Molise":                   (41.5603, 14.6564),
    "Valle d'Aosta":            (45.7373, 7.3154),
    "Nazionale":                (42.5, 12.5),
}

ALL_REGIONS = sorted(REGIONS_COORDS.keys())

# ─────────────────────────────────────────────
#  NEWS / ATTACK FEED SOURCES
# ─────────────────────────────────────────────
FEED_SOURCES = [
    {
        "name": "Ransomware.live",
        "url": "https://www.ransomware.live/rss.xml",
        "type": "ransomware",
    },
    {
        "name": "CERT-AgID",
        "url": "https://cert-agid.gov.it/feed/",
        "type": "cert",
    },
    {
        "name": "Red Hot Cyber",
        "url": "https://www.redhotcyber.com/feed/",
        "type": "news",
    },
    {
        "name": "Cybersecurity360",
        "url": "https://www.cybersecurity360.it/feed/",
        "type": "news",
    },
    {
        "name": "DarkReading Italy",
        "url": "https://www.darkreading.com/rss.xml",
        "type": "news",
    },
]

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def _uid(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()[:8]


def _severity(text: str) -> str:
    text_l = text.lower()
    if any(w in text_l for w in ["ransomware", "critico", "critical", "data breach", "exfiltration", "lockbit", "blackcat", "cl0p", "darkside", "conti", "hive", "scattered spider"]):
        return "critical"
    if any(w in text_l for w in ["phishing", "malware", "ddos", "vulnerability", "attacco", "attack", "exploit", "compromesso", "breach", "leak"]):
        return "medium"
    return "low"


def _extract_location(text: str):
    """Cerca città/regione italiana nel testo, ritorna (lat, lon, place_name, region)."""
    text_l = text.lower()
    # Prova prima match esatto città
    for city, (lat, lon, region) in ITALIAN_CITIES.items():
        if city in text_l:
            return lat, lon, city.title(), region
    # Poi prova regioni
    for region, (lat, lon) in REGIONS_COORDS.items():
        if region.lower() in text_l:
            return lat, lon, region, region
    return None


def _jitter(lat: float, lon: float, amount: float = 0.05) -> tuple:
    """Small jitter to avoid perfect overlap, clamped to Italy's land bounding box."""
    # Italy approximate land bounds: lat 36.6–47.1, lon 6.6–18.5
    new_lat = lat + random.uniform(-amount, amount)
    new_lon = lon + random.uniform(-amount, amount)
    new_lat = max(36.6, min(47.1, new_lat))
    new_lon = max(6.6, min(18.5, new_lon))
    return new_lat, new_lon


def _parse_date(entry) -> datetime:
    tz_it = ZoneInfo("Europe/Rome")
    for attr in ("published_parsed", "updated_parsed", "created_parsed"):
        t = getattr(entry, attr, None)
        if t:
            try:
                return datetime(*t[:6], tzinfo=ZoneInfo("UTC")).astimezone(tz_it)
            except Exception:
                pass
    return datetime.now(tz_it)


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


# ─────────────────────────────────────────────
#  DATA FETCHING
# ─────────────────────────────────────────────

@st.cache_data(ttl=28, show_spinner=False)
def fetch_all_attacks() -> list[dict]:
    """Fetch & parse RSS feeds, extract Italian geo info."""
    attacks = []
    tz_it = ZoneInfo("Europe/Rome")

    for source in FEED_SOURCES:
        try:
            feed = feedparser.parse(source["url"])
            for entry in feed.entries[:30]:
                title = entry.get("title", "")
                summary = _strip_html(entry.get("summary", entry.get("description", "")))
                link = entry.get("link", "#")
                combined = f"{title} {summary}"

                # Only keep Italy-related OR generic (ransomware type)
                is_italian = any(kw in combined.lower() for kw in [
                    "ital", "roma", "milan", "napol", "torin", "firenz", "bologna",
                    "venezia", "sicilia", "sardegna", "puglia", "lazio", "lombardia",
                    ".it ", ".it/", "governo", "agenzia", "comune", "regione",
                    "inail", "inps", "polizia", "carabinieri", "finanza"
                ]) or source["type"] in ("ransomware", "cert")

                if not is_italian:
                    continue

                geo = _extract_location(combined)
                if geo is None:
                    # Default to Rome (capital) with very small jitter — always on land
                    lat, lon = _jitter(41.9028, 12.4964, 0.4)
                    place = "Italia"
                    region = "Nazionale"
                else:
                    lat, lon, place, region = geo
                    lat, lon = _jitter(lat, lon, 0.08)

                severity = _severity(combined)
                published = _parse_date(entry)

                uid = _uid(title + link)
                attacks.append({
                    "id": uid,
                    "title": title[:120],
                    "summary": summary[:280],
                    "link": link,
                    "source": source["name"],
                    "type": source["type"],
                    "severity": severity,
                    "lat": lat,
                    "lon": lon,
                    "place": place,
                    "region": region,
                    "published": published,
                    "ts": published.strftime("%d/%m/%Y %H:%M"),
                })
        except Exception:
            continue

    # Deduplicate by id
    seen = set()
    unique = []
    for a in attacks:
        if a["id"] not in seen:
            seen.add(a["id"])
            unique.append(a)

    # Sort newest first
    unique.sort(key=lambda x: x["published"], reverse=True)
    return unique


# ─────────────────────────────────────────────
#  MAP BUILDER
# ─────────────────────────────────────────────

SEVERITY_COLOR = {
    "critical": "#ff3b30",
    "medium":   "#ff9f0a",
    "low":      "#30d158",
}
SEVERITY_GLOW = {
    "critical": "rgba(255,59,48,0.18)",
    "medium":   "rgba(255,159,10,0.18)",
    "low":      "rgba(48,209,88,0.18)",
}
SEVERITY_SIZE = {
    "critical": 14,
    "medium":   10,
    "low":      8,
}
SEVERITY_GLOW_SIZE = {
    "critical": 32,
    "medium":   24,
    "low":      18,
}


def build_map(attacks: list[dict]) -> go.Figure:
    if not attacks:
        df = pd.DataFrame(columns=["lat", "lon", "title", "place", "region", "severity", "ts", "source", "link"])
    else:
        df = pd.DataFrame(attacks)

    fig = go.Figure()

    for sev in ["critical", "medium", "low"]:
        sub = df[df["severity"] == sev] if len(df) > 0 else pd.DataFrame()
        if sub.empty:
            continue

        hover = [
            f"<b style='font-size:13px'>{row['title'][:65]}{'…' if len(row['title'])>65 else ''}</b><br>"
            f"<span style='color:#7eb3d4'>📍 {row['place']} — {row['region']}</span><br>"
            f"<span style='color:#586374'>🕒 {row['ts']} &nbsp;·&nbsp; {row['source']}</span><br>"
            f"<span style='color:{SEVERITY_COLOR[sev]}; font-weight:600; font-size:10px; "
            f"letter-spacing:0.08em'>▲ {sev.upper()}</span>"
            for _, row in sub.iterrows()
        ]

        # Outer glow ring (large, transparent)
        fig.add_trace(go.Scattermapbox(
            lon=sub["lon"].tolist(),
            lat=sub["lat"].tolist(),
            mode="markers",
            name=f"_{sev}_glow",
            marker=dict(
                size=SEVERITY_GLOW_SIZE[sev],
                color=SEVERITY_GLOW[sev],
                opacity=0.55,
            ),
            hoverinfo="skip",
            showlegend=False,
        ))

        # Mid ring
        fig.add_trace(go.Scattermapbox(
            lon=sub["lon"].tolist(),
            lat=sub["lat"].tolist(),
            mode="markers",
            name=f"_{sev}_mid",
            marker=dict(
                size=SEVERITY_GLOW_SIZE[sev] * 0.58,
                color=SEVERITY_GLOW[sev],
                opacity=0.45,
            ),
            hoverinfo="skip",
            showlegend=False,
        ))

        # Core dot (solid, crisp)
        fig.add_trace(go.Scattermapbox(
            lon=sub["lon"].tolist(),
            lat=sub["lat"].tolist(),
            mode="markers",
            name=sev.upper(),
            marker=dict(
                size=SEVERITY_SIZE[sev],
                color=SEVERITY_COLOR[sev],
                opacity=0.95,
            ),
            text=hover,
            hovertemplate="%{text}<extra></extra>",
            customdata=sub["link"].tolist() if "link" in sub.columns else [],
        ))

    fig.update_layout(
        paper_bgcolor="#0a0c0f",
        plot_bgcolor="#0a0c0f",
        margin=dict(l=0, r=0, t=0, b=0),
        mapbox=dict(
            style="carto-darkmatter",   # crisp dark tiles, no token needed
            center=dict(lat=42.0, lon=12.6),
            zoom=5.1,
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom", y=0.02,
            xanchor="left", x=0.01,
            bgcolor="rgba(10,12,15,0.82)",
            bordercolor="#1e2730",
            borderwidth=1,
            font=dict(family="IBM Plex Mono", size=10, color="#c8d0dc"),
            itemsizing="constant",
            traceorder="normal",
        ),
        hoverlabel=dict(
            bgcolor="#0f1318",
            bordercolor="#2a3540",
            font=dict(family="IBM Plex Sans", size=12, color="#c8d0dc"),
            align="left",
        ),
        dragmode="pan",
        uirevision="italy_map",   # keeps zoom/pan on rerender
    )

    # Hide glow traces from legend (they start with _)
    for trace in fig.data:
        if trace.name and trace.name.startswith("_"):
            trace.showlegend = False

    return fig


# ─────────────────────────────────────────────
#  SIDEBAR — FILTERS
# ─────────────────────────────────────────────

def render_sidebar(attacks: list[dict]):
    with st.sidebar:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace; font-size:0.7rem;
                    color:#586374; letter-spacing:0.12em; text-transform:uppercase;
                    padding:4px 0 16px 0; border-bottom:1px solid #1e2730; margin-bottom:16px;'>
            ◈ FILTERS
        </div>
        """, unsafe_allow_html=True)

        # Severity
        severity_opts = ["critical", "medium", "low"]
        sel_severity = st.multiselect(
            "SEVERITY",
            options=severity_opts,
            default=severity_opts,
            format_func=lambda x: x.upper(),
        )

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        # Region
        available_regions = sorted(set(a["region"] for a in attacks)) if attacks else ALL_REGIONS
        sel_regions = st.multiselect(
            "REGION",
            options=available_regions,
            default=[],
            placeholder="All regions",
        )

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        # Date range
        today = datetime.now().date()
        week_ago = today - timedelta(days=7)
        col1, col2 = st.columns(2)
        with col1:
            date_from = st.date_input("FROM", value=week_ago, label_visibility="visible")
        with col2:
            date_to = st.date_input("TO", value=today, label_visibility="visible")

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        # Source
        available_sources = sorted(set(a["source"] for a in attacks)) if attacks else []
        sel_sources = st.multiselect(
            "SOURCE",
            options=available_sources,
            default=[],
            placeholder="All sources",
        )

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        # Search
        search_text = st.text_input("🔍 SEARCH", placeholder="keyword…")

        st.markdown("<hr style='border-color:#1e2730;margin:16px 0'>", unsafe_allow_html=True)

        if st.button("↺  RESET FILTERS"):
            st.rerun()

        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace; font-size:0.6rem; color:#586374;
                    margin-top:24px; line-height:1.8;'>
            SOURCES<br>
            · ransomware.live<br>
            · cert-agid.gov.it<br>
            · redhotcyber.com<br>
            · cybersecurity360.it<br>
            · darkreading.com<br>
            <br>
            AUTO-REFRESH: 30s
        </div>
        """, unsafe_allow_html=True)

    return sel_severity, sel_regions, date_from, date_to, sel_sources, search_text


def apply_filters(attacks, sel_severity, sel_regions, date_from, date_to, sel_sources, search_text):
    filtered = attacks
    if sel_severity:
        filtered = [a for a in filtered if a["severity"] in sel_severity]
    if sel_regions:
        filtered = [a for a in filtered if a["region"] in sel_regions]
    if sel_sources:
        filtered = [a for a in filtered if a["source"] in sel_sources]
    filtered = [
        a for a in filtered
        if date_from <= a["published"].date() <= date_to
    ]
    if search_text:
        q = search_text.lower()
        filtered = [
            a for a in filtered
            if q in a["title"].lower() or q in a["summary"].lower() or q in a["place"].lower()
        ]
    return filtered


# ─────────────────────────────────────────────
#  FEED CARD RENDERER
# ─────────────────────────────────────────────

def render_feed(attacks: list[dict]):
    if not attacks:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace; font-size:0.75rem;
                    color:#586374; text-align:center; padding:32px 0;'>
            NO EVENTS MATCH CURRENT FILTERS
        </div>""", unsafe_allow_html=True)
        return

    for a in attacks:
        sev = a["severity"]
        sev_class = sev
        badge_class = f"badge-{sev}"
        card_class = f"feed-card {'' if sev=='critical' else sev}"
        link = a.get("link", "#")

        st.markdown(f"""
        <div class="{card_class}">
            <div class="feed-title">
                <a href="{link}" target="_blank"
                   style="color:#e8ecf0; text-decoration:none;">
                    {a['title']}
                </a>
            </div>
            <div class="feed-meta">
                <span class="badge {badge_class}">{sev}</span>
                <span class="badge badge-region">{a['region']}</span>
                📍 {a['place']} &nbsp;·&nbsp; {a['ts']} &nbsp;·&nbsp; {a['source']}
            </div>
            <div class="feed-desc">{a['summary'][:200]}{'…' if len(a['summary'])>200 else ''}</div>
        </div>
        """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    # Header
    st.markdown("""
    <div style='display:flex; align-items:center; gap:12px; margin-bottom:4px;'>
        <div style='font-family:"IBM Plex Mono",monospace; font-size:1.5rem;
                    font-weight:600; color:#e8ecf0; letter-spacing:-0.02em;'>
            <span style='color:#ff3b30;'>◈</span> ITALY CYBER THREAT MAP
        </div>
        <div style='margin-left:auto; font-family:"IBM Plex Mono",monospace;
                    font-size:0.62rem; color:#586374; letter-spacing:0.08em;'>
            LIVE INTELLIGENCE DASHBOARD
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Auto-refresh counter
    now = datetime.now(ZoneInfo("Europe/Rome"))
    refresh_key = int(time.time() // 30)  # changes every 30s

    # Fetch data (cached 28s)
    with st.spinner(""):
        all_attacks = fetch_all_attacks()

    # Sidebar filters
    sel_severity, sel_regions, date_from, date_to, sel_sources, search_text = render_sidebar(all_attacks)

    # Apply filters
    filtered = apply_filters(all_attacks, sel_severity, sel_regions, date_from, date_to, sel_sources, search_text)

    # KPI bar
    total = len(all_attacks)
    critical_n = sum(1 for a in all_attacks if a["severity"] == "critical")
    medium_n = sum(1 for a in all_attacks if a["severity"] == "medium")
    low_n = sum(1 for a in all_attacks if a["severity"] == "low")
    regions_hit = len(set(a["region"] for a in all_attacks))

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.metric("TOTAL EVENTS", total)
    with k2:
        st.metric("⬤ CRITICAL", critical_n)
    with k3:
        st.metric("⬤ MEDIUM", medium_n)
    with k4:
        st.metric("⬤ LOW", low_n)
    with k5:
        st.metric("REGIONS HIT", regions_hit)

    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

    # Status bar
    st.markdown(f"""
    <div class="status-bar">
        <span class="pulse-dot"></span>
        LIVE · {now.strftime('%d/%m/%Y %H:%M:%S')} IT ·
        {len(filtered)} events shown (filtered) · {total} total in history ·
        next refresh in ~{30 - (int(time.time()) % 30)}s
    </div>
    """, unsafe_allow_html=True)

    # Layout: map left, feed right
    map_col, feed_col = st.columns([3, 1.5], gap="medium")

    with map_col:
        fig = build_map(filtered)
        fig.update_layout(height=640)
        st.plotly_chart(
            fig,
            use_container_width=True,
            config={
                "scrollZoom": True,
                "displayModeBar": True,
                "modeBarButtonsToRemove": ["select2d", "lasso2d", "autoScale2d", "resetScale2d"],
                "displaylogo": False,
                "toImageButtonOptions": {"format": "png", "filename": "italy_cybermap"},
            },
            key=f"map_{refresh_key}",
        )
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace; font-size:0.6rem;
                    color:#586374; text-align:center; margin-top:-8px;'>
            CLICK ON A MARKER TO OPEN THE INCIDENT REPORT · SCROLL TO ZOOM · DRAG TO PAN
        </div>""", unsafe_allow_html=True)

    with feed_col:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace; font-size:0.65rem;
                    color:#586374; letter-spacing:0.1em; text-transform:uppercase;
                    padding-bottom:8px; border-bottom:1px solid #1e2730; margin-bottom:12px;'>
            ◈ INCIDENT FEED — STORICO COMPLETO
        </div>""", unsafe_allow_html=True)

        feed_container = st.container(height=640)
        with feed_container:
            render_feed(filtered)

    # Auto-refresh with st.rerun via time-based trigger
    time.sleep(0.5)
    st.markdown("""
    <script>
    setTimeout(function() {
        window.location.reload();
    }, 30000);
    </script>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
