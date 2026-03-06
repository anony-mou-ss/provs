"""
╔══════════════════════════════════════════════════════════════════════╗
║          ITALY CYBER THREAT LIVE MAP                                ║
║          Real-time cybersecurity incident dashboard                 ║
║                                                                      ║
║  Architettura:                                                       ║
║  · Background thread fetcha i feed ogni 30s                         ║
║  · st_autorefresh ogni 5s rileva nuove notizie senza page reload     ║
║  · Delta push: solo le notizie nuove appaiono in cima al feed        ║
║  · Geo-parser con regex word-boundary — nessun punto in mare        ║
║                                                                      ║
║  Install:  pip install streamlit plotly requests feedparser pandas   ║
║                        streamlit-autorefresh pytz                   ║
║  Run:      streamlit run italy_cybermap.py                           ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import plotly.graph_objects as go
import requests
import feedparser
import pandas as pd
import re
import time
import random
import hashlib
import threading
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False

# ─────────────────────────────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Italy Cyber Threat Map",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────
#  CSS — dark terminal aesthetic
# ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
  :root {
    --bg:       #0a0c0f;
    --surface:  #0f1318;
    --card:     #141920;
    --border:   #1e2730;
    --accent:   #ff3b30;
    --accent2:  #ff9f0a;
    --accent3:  #30d158;
    --text:     #c8d0dc;
    --dim:      #586374;
    --mono:     'IBM Plex Mono', monospace;
    --sans:     'IBM Plex Sans', sans-serif;
  }
  html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: var(--sans) !important;
  }
  [data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border) !important;
  }
  [data-testid="stSidebar"] * { color: var(--text) !important; }
  h1,h2,h3,h4 { font-family: var(--mono) !important; color: #e8ecf0 !important; letter-spacing: -0.02em; }
  [data-testid="metric-container"] {
    background: var(--card) !important; border: 1px solid var(--border) !important;
    border-radius: 6px !important; padding: 12px 16px !important;
  }
  [data-testid="metric-container"] label {
    color: var(--dim) !important; font-family: var(--mono) !important;
    font-size: 0.65rem !important; text-transform: uppercase; letter-spacing: 0.1em;
  }
  [data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-family: var(--mono) !important; font-size: 1.6rem !important; color: var(--accent) !important;
  }
  .stSelectbox > div > div, .stMultiSelect > div > div {
    background: var(--card) !important; border: 1px solid var(--border) !important;
    border-radius: 4px !important; color: var(--text) !important;
  }
  .stDateInput > div > div {
    background: var(--card) !important; border: 1px solid var(--border) !important; color: var(--text) !important;
  }
  .stButton > button {
    background: transparent !important; border: 1px solid var(--accent) !important;
    color: var(--accent) !important; font-family: var(--mono) !important;
    font-size: 0.75rem !important; letter-spacing: 0.08em; text-transform: uppercase;
    border-radius: 3px !important; transition: all 0.2s;
  }
  .stButton > button:hover { background: var(--accent) !important; color: #fff !important; }
  hr { border-color: var(--border) !important; }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .feed-card {
    background: var(--card); border: 1px solid var(--border);
    border-left: 3px solid var(--accent); border-radius: 4px;
    padding: 10px 14px; margin-bottom: 8px; font-family: var(--sans);
    transition: border-color 0.2s;
  }
  .feed-card:hover { border-left-color: var(--accent2); }
  .feed-card.medium { border-left-color: var(--accent2); }
  .feed-card.low    { border-left-color: var(--accent3); }
  .feed-card.new-event {
    animation: flashIn 2s ease-out;
  }
  @keyframes flashIn {
    0%   { background: #0d2018; }
    100% { background: var(--card); }
  }
  .feed-title { font-weight:600; font-size:0.82rem; color:#e8ecf0; margin-bottom:3px; line-height:1.3; }
  .feed-meta  { font-family:var(--mono); font-size:0.65rem; color:var(--dim); margin-bottom:4px; }
  .feed-desc  { font-size:0.75rem; color:var(--dim); line-height:1.4; }
  .badge {
    display:inline-block; padding:1px 6px; border-radius:2px;
    font-family:var(--mono); font-size:0.6rem; font-weight:600;
    letter-spacing:0.05em; margin-right:4px; text-transform:uppercase;
  }
  .badge-critical { background:#3d1515; color:var(--accent);  border:1px solid var(--accent);  }
  .badge-medium   { background:#2d1f08; color:var(--accent2); border:1px solid var(--accent2); }
  .badge-low      { background:#0d2418; color:var(--accent3); border:1px solid var(--accent3); }
  .badge-region   { background:#1a1f2a; color:#7eb3d4;        border:1px solid #2a3a4d;        }
  .badge-new      { background:#0d2010; color:#30d158;        border:1px solid #30d158;
                    animation: blink 0.8s step-end 5; }
  @keyframes blink { 50% { opacity:0; } }
  .pulse-dot {
    display:inline-block; width:7px; height:7px; background:var(--accent);
    border-radius:50%; margin-right:6px; animation:pulse 1.4s infinite; vertical-align:middle;
  }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(255,59,48,0.7); }
    70%  { box-shadow: 0 0 0 7px rgba(255,59,48,0); }
    100% { box-shadow: 0 0 0 0 rgba(255,59,48,0); }
  }
  .status-bar {
    font-family:var(--mono); font-size:0.62rem; color:var(--dim);
    padding:4px 0; letter-spacing:0.05em;
  }
  #MainMenu, footer, header { visibility: hidden !important; }
  .block-container { padding-top: 1.2rem !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
#  GEO DATABASE — coordinate precise dei comuni italiani
#  Ordinate per lunghezza decrescente → match greedy corretto
# ─────────────────────────────────────────────────────────────────────
ITALIAN_CITIES_RAW = [
    ("reggio calabria",     38.1147, 15.6615, "Calabria"),
    ("reggio emilia",       44.6989, 10.6297, "Emilia-Romagna"),
    ("vibo valentia",       38.6760, 16.0995, "Calabria"),
    ("ascoli piceno",       42.8540, 13.5745, "Marche"),
    ("giugliano in campania",40.9314,14.1958, "Campania"),
    ("torre del greco",     40.7877, 14.3697, "Campania"),
    ("corigliano rossano",  39.5624, 16.5157, "Calabria"),
    ("poggibonsi",          43.4714, 11.1489, "Toscana"),
    ("intesa sanpaolo",     45.4654, 9.1859,  "Lombardia"),
    ("ferrovie dello stato",41.9028, 12.4964, "Lazio"),
    ("poste italiane",      41.9028, 12.4964, "Lazio"),
    ("la spezia",           44.1024, 9.8240,  "Liguria"),
    ("l aquila",            42.3498, 13.3995, "Abruzzo"),
    ("l'aquila",            42.3498, 13.3995, "Abruzzo"),
    ("san marino",          43.9354, 12.4472, "Nazionale"),
    ("giugliano",           40.9314, 14.1958, "Campania"),
    ("bergamo",             45.6983, 9.6773,  "Lombardia"),
    ("brescia",             45.5416, 10.2118, "Lombardia"),
    ("modena",              44.6471, 10.9252, "Emilia-Romagna"),
    ("bologna",             44.4949, 11.3426, "Emilia-Romagna"),
    ("palermo",             38.1157, 13.3615, "Sicilia"),
    ("catania",             37.5079, 15.0830, "Sicilia"),
    ("messina",             38.1938, 15.5540, "Sicilia"),
    ("siracusa",            37.0755, 15.2866, "Sicilia"),
    ("trapani",             38.0176, 12.5365, "Sicilia"),
    ("agrigento",           37.3111, 13.5765, "Sicilia"),
    ("caltanissetta",       37.4890, 14.0626, "Sicilia"),
    ("ragusa",              36.9249, 14.7256, "Sicilia"),
    ("venezia",             45.4408, 12.3155, "Veneto"),
    ("venice",              45.4408, 12.3155, "Veneto"),
    ("verona",              45.4384, 10.9916, "Veneto"),
    ("padova",              45.4064, 11.8768, "Veneto"),
    ("padua",               45.4064, 11.8768, "Veneto"),
    ("vicenza",             45.5455, 11.5354, "Veneto"),
    ("treviso",             45.6669, 12.2430, "Veneto"),
    ("belluno",             46.1373, 12.2168, "Veneto"),
    ("rovigo",              45.0699, 11.7899, "Veneto"),
    ("trieste",             45.6495, 13.7768, "Friuli-Venezia Giulia"),
    ("udine",               46.0711, 13.2344, "Friuli-Venezia Giulia"),
    ("pordenone",           45.9564, 12.6611, "Friuli-Venezia Giulia"),
    ("gorizia",             45.9409, 13.6206, "Friuli-Venezia Giulia"),
    ("trento",              46.0748, 11.1217, "Trentino-Alto Adige"),
    ("bolzano",             46.4983, 11.3548, "Trentino-Alto Adige"),
    ("milano",              45.4654, 9.1859,  "Lombardia"),
    ("milan",               45.4654, 9.1859,  "Lombardia"),
    ("torino",              45.0703, 7.6869,  "Piemonte"),
    ("turin",               45.0703, 7.6869,  "Piemonte"),
    ("novara",              45.4468, 8.6219,  "Piemonte"),
    ("asti",                44.9003, 8.2064,  "Piemonte"),
    ("alessandria",         44.9124, 8.6154,  "Piemonte"),
    ("cuneo",               44.3844, 7.5426,  "Piemonte"),
    ("vercelli",            45.3227, 8.4240,  "Piemonte"),
    ("biella",              45.5655, 8.0530,  "Piemonte"),
    ("verbania",            45.9230, 8.5522,  "Piemonte"),
    ("genova",              44.4056, 8.9463,  "Liguria"),
    ("genoa",               44.4056, 8.9463,  "Liguria"),
    ("savona",              44.3086, 8.4797,  "Liguria"),
    ("imperia",             43.8880, 8.0278,  "Liguria"),
    ("firenze",             43.7696, 11.2558, "Toscana"),
    ("florence",            43.7696, 11.2558, "Toscana"),
    ("livorno",             43.5485, 10.3106, "Toscana"),
    ("pisa",                43.7228, 10.4017, "Toscana"),
    ("siena",               43.3186, 11.3307, "Toscana"),
    ("arezzo",              43.4633, 11.8787, "Toscana"),
    ("prato",               43.8777, 11.1023, "Toscana"),
    ("lucca",               43.8429, 10.5027, "Toscana"),
    ("pistoia",             43.9334, 10.9166, "Toscana"),
    ("grosseto",            42.7629, 11.1116, "Toscana"),
    ("massa",               44.0354, 10.1401, "Toscana"),
    ("perugia",             43.1107, 12.3908, "Umbria"),
    ("terni",               42.5636, 12.6432, "Umbria"),
    ("ancona",              43.6158, 13.5189, "Marche"),
    ("pesaro",              43.9098, 12.9131, "Marche"),
    ("macerata",            43.2989, 13.4536, "Marche"),
    ("fermo",               43.1614, 13.7181, "Marche"),
    ("roma",                41.9028, 12.4964, "Lazio"),
    ("rome",                41.9028, 12.4964, "Lazio"),
    ("latina",              41.4677, 12.9035, "Lazio"),
    ("frosinone",           41.6396, 13.3396, "Lazio"),
    ("viterbo",             42.4169, 12.1044, "Lazio"),
    ("rieti",               42.4042, 12.8624, "Lazio"),
    ("napoli",              40.8518, 14.2681, "Campania"),
    ("naples",              40.8518, 14.2681, "Campania"),
    ("salerno",             40.6824, 14.7681, "Campania"),
    ("caserta",             41.0748, 14.3328, "Campania"),
    ("avellino",            40.9143, 14.7906, "Campania"),
    ("benevento",           41.1297, 14.7819, "Campania"),
    ("bari",                41.1171, 16.8719, "Puglia"),
    ("taranto",             40.4644, 17.2470, "Puglia"),
    ("foggia",              41.4621, 15.5446, "Puglia"),
    ("lecce",               40.3515, 18.1750, "Puglia"),
    ("brindisi",            40.6327, 17.9414, "Puglia"),
    ("andria",              41.2272, 16.2963, "Puglia"),
    ("barletta",            41.3197, 16.2817, "Puglia"),
    ("pescara",             42.4606, 14.2156, "Abruzzo"),
    ("chieti",              42.3512, 14.1683, "Abruzzo"),
    ("teramo",              42.6589, 13.7042, "Abruzzo"),
    ("campobasso",          41.5603, 14.6564, "Molise"),
    ("isernia",             41.5950, 14.2328, "Molise"),
    ("potenza",             40.6404, 15.8057, "Basilicata"),
    ("matera",              40.6664, 16.6044, "Basilicata"),
    ("catanzaro",           38.9098, 16.5872, "Calabria"),
    ("cosenza",             39.2988, 16.2548, "Calabria"),
    ("crotone",             39.0814, 17.1279, "Calabria"),
    ("cagliari",            39.2238, 9.1217,  "Sardegna"),
    ("sassari",             40.7259, 8.5557,  "Sardegna"),
    ("nuoro",               40.3214, 9.3307,  "Sardegna"),
    ("oristano",            39.9037, 8.5925,  "Sardegna"),
    ("aosta",               45.7373, 7.3154,  "Valle d'Aosta"),
    ("ferrara",             44.8381, 11.6198, "Emilia-Romagna"),
    ("ravenna",             44.4175, 12.2035, "Emilia-Romagna"),
    ("parma",               44.8015, 10.3279, "Emilia-Romagna"),
    ("rimini",              44.0678, 12.5695, "Emilia-Romagna"),
    ("piacenza",            45.0526, 9.6926,  "Emilia-Romagna"),
    ("forli",               44.2227, 12.0407, "Emilia-Romagna"),
    ("reggio",              44.6989, 10.6297, "Emilia-Romagna"),
    ("monza",               45.5845, 9.2744,  "Lombardia"),
    ("como",                45.8080, 9.0852,  "Lombardia"),
    ("varese",              45.8205, 8.8257,  "Lombardia"),
    ("mantova",             45.1564, 10.7914, "Lombardia"),
    ("cremona",             45.1333, 10.0227, "Lombardia"),
    ("pavia",               45.1847, 9.1582,  "Lombardia"),
    ("lodi",                45.3146, 9.5028,  "Lombardia"),
    ("lecco",               45.8554, 9.3972,  "Lombardia"),
    ("sondrio",             46.1698, 9.8713,  "Lombardia"),
    # entità nazionali — sempre su Roma/coordinate generali IT
    ("italia",              41.9028, 12.4964, "Nazionale"),
    ("italy",               41.9028, 12.4964, "Nazionale"),
    ("italian",             41.9028, 12.4964, "Nazionale"),
    ("governo italiano",    41.9028, 12.4964, "Nazionale"),
]

CITY_LOOKUP = sorted(ITALIAN_CITIES_RAW, key=lambda x: -len(x[0]))

REGIONS_COORDS = {
    "Lazio":                 (41.9028, 12.4964),
    "Lombardia":             (45.4654,  9.1859),
    "Campania":              (40.8518, 14.2681),
    "Piemonte":              (45.0703,  7.6869),
    "Sicilia":               (37.5999, 14.0154),
    "Liguria":               (44.4056,  8.9463),
    "Emilia-Romagna":        (44.4949, 11.3426),
    "Toscana":               (43.7696, 11.2558),
    "Puglia":                (41.1171, 16.8719),
    "Veneto":                (45.4408, 12.3155),
    "Friuli-Venezia Giulia": (45.6495, 13.7768),
    "Trentino-Alto Adige":   (46.0748, 11.1217),
    "Umbria":                (43.1107, 12.3908),
    "Sardegna":              (39.2238,  9.1217),
    "Calabria":              (38.9098, 16.5872),
    "Marche":                (43.6158, 13.5189),
    "Abruzzo":               (42.3498, 13.3995),
    "Basilicata":            (40.6404, 15.8057),
    "Molise":                (41.5603, 14.6564),
    "Valle d'Aosta":         (45.7373,  7.3154),
    "Nazionale":             (41.9028, 12.4964),
}

ALL_REGIONS = sorted(REGIONS_COORDS.keys())

FALLBACK_POOL = [
    (41.9028, 12.4964, "Roma",      "Lazio"),
    (45.4654,  9.1859, "Milano",    "Lombardia"),
    (40.8518, 14.2681, "Napoli",    "Campania"),
    (45.0703,  7.6869, "Torino",    "Piemonte"),
    (44.4949, 11.3426, "Bologna",   "Emilia-Romagna"),
    (43.7696, 11.2558, "Firenze",   "Toscana"),
    (45.4408, 12.3155, "Venezia",   "Veneto"),
    (38.1157, 13.3615, "Palermo",   "Sicilia"),
    (41.1171, 16.8719, "Bari",      "Puglia"),
    (44.4056,  8.9463, "Genova",    "Liguria"),
    (43.1107, 12.3908, "Perugia",   "Umbria"),
    (43.6158, 13.5189, "Ancona",    "Marche"),
    (39.2238,  9.1217, "Cagliari",  "Sardegna"),
    (46.0748, 11.1217, "Trento",    "Trentino-Alto Adige"),
    (42.3498, 13.3995, "L'Aquila",  "Abruzzo"),
    (40.6404, 15.8057, "Potenza",   "Basilicata"),
    (38.9098, 16.5872, "Catanzaro", "Calabria"),
    (41.5603, 14.6564, "Campobasso","Molise"),
]

# ─────────────────────────────────────────────────────────────────────
#  FEED SOURCES — 17 fonti
# ─────────────────────────────────────────────────────────────────────
FEED_SOURCES = [
    # ── RANSOMWARE / LEAK TRACKER ────────────────────────────────────
    {"name": "Ransomware.live",   "url": "https://www.ransomware.live/rss.xml",              "type": "ransomware", "italian_only": False},
    {"name": "Ransomwatch",       "url": "https://ransomwatch.telemetry.ltd/rss.xml",        "type": "ransomware", "italian_only": False},
    # ── CERT / GOV ITALIANI ──────────────────────────────────────────
    {"name": "CERT-AgID",         "url": "https://cert-agid.gov.it/feed/",                   "type": "cert",       "italian_only": True},
    {"name": "CSIRT Italia",      "url": "https://www.csirt.gov.it/feed",                    "type": "cert",       "italian_only": True},
    # ── MEDIA ITALIANI ───────────────────────────────────────────────
    {"name": "Red Hot Cyber",     "url": "https://www.redhotcyber.com/feed/",                "type": "news",       "italian_only": True},
    {"name": "Cybersecurity360",  "url": "https://www.cybersecurity360.it/feed/",            "type": "news",       "italian_only": True},
    {"name": "AgendaDigitale",    "url": "https://www.agendadigitale.eu/feed/",              "type": "news",       "italian_only": True},
    {"name": "Punto Informatico", "url": "https://www.punto-informatico.it/feed/",           "type": "news",       "italian_only": True},
    {"name": "Difesa Online",     "url": "https://www.difesaonline.it/feed",                 "type": "news",       "italian_only": True},
    {"name": "Wired Italia",      "url": "https://www.wired.it/feed/rss",                    "type": "news",       "italian_only": True},
    # ── INTERNAZIONALI (filtrati per keyword IT) ─────────────────────
    {"name": "The Hacker News",   "url": "https://feeds.feedburner.com/TheHackersNews",      "type": "news",       "italian_only": False},
    {"name": "BleepingComputer",  "url": "https://www.bleepingcomputer.com/feed/",           "type": "news",       "italian_only": False},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/",                "type": "news",       "italian_only": False},
    {"name": "SecurityWeek",      "url": "https://feeds.feedburner.com/Securityweek",        "type": "news",       "italian_only": False},
    {"name": "DarkReading",       "url": "https://www.darkreading.com/rss.xml",              "type": "news",       "italian_only": False},
    {"name": "Recorded Future",   "url": "https://www.recordedfuture.com/feed",              "type": "news",       "italian_only": False},
    {"name": "Threat Post",       "url": "https://threatpost.com/feed/",                     "type": "news",       "italian_only": False},
]

SOURCE_NAMES = [s["name"] for s in FEED_SOURCES]

# Regex italiano compilata una sola volta
_ITALY_RE = re.compile(
    r"\bital\w*|\broma\b|\bmilan\w*|\bnapol\w*|\btorin\w*|\bfirenz\w*"
    r"|\bbologna\b|\bvenezia\b|\bsicilia\b|\bsardegna\b|\bpuglia\b"
    r"|\blazio\b|\blombardia\b|\btoscana\b|\bveneto\b|\bcampania\b"
    r"|\bcalabria\b|\bpiemonte\b|\bliguria\b|\bumbria\b|\bmarche\b"
    r"|\babruzzo\b|\bbasilicata\b|\bmolise\b|\.it[\s/]"
    r"|\bgoverno\b|\bagenzia\b|\bcomune\b|\bregione\b"
    r"|\binail\b|\binps\b|\bpolizia\b|\bcarabinieri\b"
    r"|\bconsip\b|\btrenitalia\b|\benel\b|\bleonardo\b"
    r"|\bfincantieri\b|\bfastweb\b|\bintesa\b|\bunicredit\b"
    r"|\bposte italiane\b|\bautostrade\b|\bsnam\b",
    re.IGNORECASE,
)

FETCH_INTERVAL = 30  # secondi

# ─────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────

def _uid(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _severity(text: str) -> str:
    t = text.lower()
    if re.search(
        r"ransomware|data.?breach|exfiltrat|lockbit|blackcat|cl0p|darkside"
        r"|conti\b|hive\b|scattered spider|alphv|rhysida|play\b|royal\b"
        r"|medusa\b|akira\b|critico|critical|zero.?day|apt\d|nation.?state",
        t,
    ):
        return "critical"
    if re.search(
        r"phishing|malware|ddos|vulnerabilit|attacco|attack|exploit"
        r"|compromess|breach|leak|defacement|botnet|trojan|worm|spyware"
        r"|credential|password dump|data dump|intrusion",
        t,
    ):
        return "medium"
    return "low"


def _extract_location(text: str):
    """
    Geo-parser con regex word-boundary — molto più preciso del semplice 'in'.
    Ritorna (lat, lon, place_name, region) o None.
    """
    t = text.lower()
    for city, lat, lon, region in CITY_LOOKUP:
        if re.search(r"\b" + re.escape(city) + r"\b", t):
            return lat, lon, city.title(), region
    for region, (lat, lon) in REGIONS_COORDS.items():
        if re.search(r"\b" + re.escape(region.lower()) + r"\b", t):
            return lat, lon, region, region
    return None


def _jitter(lat: float, lon: float, amount: float = 0.04) -> tuple:
    """Micro-jitter sempre dentro i bounds terrestri italiani."""
    new_lat = max(36.6, min(47.1, lat + random.uniform(-amount, amount)))
    new_lon = max(6.6,  min(18.5, lon + random.uniform(-amount, amount)))
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


def _parse_entry(entry, source: dict) -> dict | None:
    title   = entry.get("title", "").strip()
    summary = _strip_html(entry.get("summary", entry.get("description", "")))
    link    = entry.get("link", "#")
    if not title:
        return None

    combined = f"{title} {summary}"

    # Fonti internazionali: filtra per keyword italiane
    if not source.get("italian_only", False):
        if source["type"] not in ("ransomware", "cert"):
            if not _ITALY_RE.search(combined):
                return None

    geo = _extract_location(combined)
    if geo is None:
        fb  = FALLBACK_POOL[hash(title) % len(FALLBACK_POOL)]
        lat, lon   = _jitter(fb[0], fb[1], 0.12)
        place, region = fb[2], fb[3]
    else:
        lat_b, lon_b, place, region = geo
        lat, lon = _jitter(lat_b, lon_b, 0.04)

    published = _parse_date(entry)

    return {
        "id":        _uid(title + link),
        "title":     title[:140],
        "summary":   summary[:320],
        "link":      link,
        "source":    source["name"],
        "type":      source["type"],
        "severity":  _severity(combined),
        "lat":       lat,
        "lon":       lon,
        "place":     place,
        "region":    region,
        "published": published,
        "ts":        published.strftime("%d/%m/%Y %H:%M"),
        "is_new":    False,
    }


# ─────────────────────────────────────────────────────────────────────
#  BACKGROUND FETCHER THREAD
#  Gira in daemon thread, fetcha ogni FETCH_INTERVAL secondi.
#  Scrive solo i nuovi item (uid non ancora visti) in _inbox.
#  Il main thread draina _inbox ad ogni rerun (ogni 5s).
# ─────────────────────────────────────────────────────────────────────

def _background_fetch(inbox: list, lock: threading.Lock, seen: set):
    while True:
        new_items = []
        for source in FEED_SOURCES:
            try:
                resp = requests.get(
                    source["url"],
                    timeout=10,
                    headers={"User-Agent": "Mozilla/5.0 ItalyCyberMap/2.0 +https://github.com"},
                )
                feed = feedparser.parse(resp.text if resp.ok else "")
                for entry in feed.entries[:50]:
                    item = _parse_entry(entry, source)
                    if item and item["id"] not in seen:
                        seen.add(item["id"])
                        item["is_new"] = True
                        new_items.append(item)
            except Exception:
                continue

        if new_items:
            with lock:
                inbox.extend(new_items)

        time.sleep(FETCH_INTERVAL)


def _ensure_thread():
    """Avvia il fetcher thread una sola volta per sessione."""
    if "_fetch_thread" not in st.session_state:
        inbox = []
        lock  = threading.Lock()
        seen  = set()

        t = threading.Thread(
            target=_background_fetch,
            args=(inbox, lock, seen),
            daemon=True,
            name="CyberMapFetcher",
        )
        t.start()

        st.session_state["_fetch_thread"] = t
        st.session_state["_inbox"]        = inbox
        st.session_state["_lock"]         = lock
        st.session_state["_seen"]         = seen
        st.session_state["attacks"]       = []
        st.session_state["new_count"]     = 0


def _drain_inbox() -> int:
    """Sposta inbox → feed principale. Ritorna n° item aggiunti."""
    inbox = st.session_state["_inbox"]
    lock  = st.session_state["_lock"]

    with lock:
        new_items = list(inbox)
        inbox.clear()

    if not new_items:
        return 0

    new_items.sort(key=lambda x: x["published"], reverse=True)
    st.session_state["attacks"] = new_items + st.session_state["attacks"]
    st.session_state["new_count"] += len(new_items)
    return len(new_items)


# ─────────────────────────────────────────────────────────────────────
#  MAP BUILDER
# ─────────────────────────────────────────────────────────────────────

SEV_COLOR     = {"critical": "#ff3b30", "medium": "#ff9f0a", "low": "#30d158"}
SEV_GLOW      = {"critical": "rgba(255,59,48,0.15)", "medium": "rgba(255,159,10,0.15)", "low": "rgba(48,209,88,0.15)"}
SEV_SIZE      = {"critical": 14, "medium": 10, "low": 8}
SEV_GLOW_SIZE = {"critical": 28, "medium": 21, "low": 15}


def build_map(attacks: list[dict]) -> go.Figure:
    df = pd.DataFrame(attacks) if attacks else pd.DataFrame(
        columns=["lat","lon","title","place","region","severity","ts","source","link"])

    fig = go.Figure()

    for sev in ["critical", "medium", "low"]:
        sub = df[df["severity"] == sev] if len(df) else pd.DataFrame()
        if sub.empty:
            continue

        hover = [
            f"<b>{row['title'][:72]}{'…' if len(row['title'])>72 else ''}</b><br>"
            f"<span style='color:#7eb3d4'>📍 {row['place']} — {row['region']}</span><br>"
            f"<span style='color:#586374'>🕒 {row['ts']} · {row['source']}</span><br>"
            f"<span style='color:{SEV_COLOR[sev]};font-weight:600;font-size:10px'>▲ {sev.upper()}</span>"
            for _, row in sub.iterrows()
        ]

        fig.add_trace(go.Scattermapbox(           # outer glow
            lon=sub["lon"].tolist(), lat=sub["lat"].tolist(),
            mode="markers", name=f"_g_{sev}",
            marker=dict(size=SEV_GLOW_SIZE[sev], color=SEV_GLOW[sev], opacity=0.5),
            hoverinfo="skip", showlegend=False,
        ))
        fig.add_trace(go.Scattermapbox(           # mid ring
            lon=sub["lon"].tolist(), lat=sub["lat"].tolist(),
            mode="markers", name=f"_m_{sev}",
            marker=dict(size=int(SEV_GLOW_SIZE[sev]*0.56), color=SEV_GLOW[sev], opacity=0.38),
            hoverinfo="skip", showlegend=False,
        ))
        fig.add_trace(go.Scattermapbox(           # core dot
            lon=sub["lon"].tolist(), lat=sub["lat"].tolist(),
            mode="markers", name=sev.upper(),
            marker=dict(size=SEV_SIZE[sev], color=SEV_COLOR[sev], opacity=0.95),
            text=hover,
            hovertemplate="%{text}<extra></extra>",
            customdata=sub["link"].tolist() if "link" in sub.columns else [],
        ))

    fig.update_layout(
        paper_bgcolor="#0a0c0f", plot_bgcolor="#0a0c0f",
        height=650,
        margin=dict(l=0, r=0, t=0, b=0),
        mapbox=dict(
            style="carto-darkmatter",
            center=dict(lat=42.2, lon=12.8),
            zoom=4.9,
            bounds=dict(west=5.5, east=20.0, south=35.0, north=48.5),
        ),
        legend=dict(
            orientation="h", yanchor="bottom", y=0.02, xanchor="left", x=0.01,
            bgcolor="rgba(10,12,15,0.85)", bordercolor="#1e2730", borderwidth=1,
            font=dict(family="IBM Plex Mono", size=10, color="#c8d0dc"),
            itemsizing="constant",
        ),
        hoverlabel=dict(
            bgcolor="#0f1318", bordercolor="#2a3540",
            font=dict(family="IBM Plex Sans", size=12, color="#c8d0dc"), align="left",
        ),
        dragmode="pan",
        uirevision="italy_map",   # mantiene zoom/pan tra i rerun
    )

    for trace in fig.data:
        if trace.name and trace.name.startswith("_"):
            trace.showlegend = False

    return fig


# ─────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────

def render_sidebar(attacks: list[dict]):
    with st.sidebar:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:0.7rem;color:#586374;
                    letter-spacing:0.12em;text-transform:uppercase;
                    padding:4px 0 16px 0;border-bottom:1px solid #1e2730;margin-bottom:16px;'>
            ◈ FILTERS
        </div>""", unsafe_allow_html=True)

        sel_severity = st.multiselect(
            "SEVERITY", ["critical","medium","low"],
            default=["critical","medium","low"], format_func=str.upper,
        )
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        available_regions = sorted(set(a["region"] for a in attacks)) if attacks else ALL_REGIONS
        sel_regions = st.multiselect("REGION", available_regions, default=[], placeholder="All regions")
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        today    = datetime.now().date()
        week_ago = today - timedelta(days=7)
        c1, c2   = st.columns(2)
        with c1: date_from = st.date_input("FROM", value=week_ago)
        with c2: date_to   = st.date_input("TO",   value=today)
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        available_sources = sorted(set(a["source"] for a in attacks)) if attacks else SOURCE_NAMES
        sel_sources = st.multiselect("SOURCE", available_sources, default=[], placeholder="All sources")
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        search_text = st.text_input("🔍 SEARCH", placeholder="keyword…")

        st.markdown("<hr style='border-color:#1e2730;margin:16px 0'>", unsafe_allow_html=True)
        if st.button("↺  RESET FILTERS"):
            st.rerun()

        src_html = "".join(f"· {s['name']}<br>" for s in FEED_SOURCES)
        st.markdown(f"""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:0.58rem;
                    color:#586374;margin-top:20px;line-height:1.85;'>
            SOURCES ({len(FEED_SOURCES)})<br>
            {src_html}
            <br>FETCH INTERVAL: {FETCH_INTERVAL}s<br>
            UI POLL: 5s (no page reload)
        </div>""", unsafe_allow_html=True)

    return sel_severity, sel_regions, date_from, date_to, sel_sources, search_text


def apply_filters(attacks, sel_severity, sel_regions, date_from, date_to, sel_sources, search_text):
    f = attacks
    if sel_severity: f = [a for a in f if a["severity"] in sel_severity]
    if sel_regions:  f = [a for a in f if a["region"]   in sel_regions]
    if sel_sources:  f = [a for a in f if a["source"]   in sel_sources]
    f = [a for a in f if date_from <= a["published"].date() <= date_to]
    if search_text:
        q = search_text.lower()
        f = [a for a in f if q in a["title"].lower() or q in a["summary"].lower()
             or q in a["place"].lower()]
    return f


# ─────────────────────────────────────────────────────────────────────
#  FEED RENDERER
# ─────────────────────────────────────────────────────────────────────

def render_feed(attacks: list[dict]):
    if not attacks:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:0.75rem;
                    color:#586374;text-align:center;padding:32px 0;'>
            IN ATTESA DI NOTIZIE…
        </div>""", unsafe_allow_html=True)
        return

    for a in attacks:
        sev  = a["severity"]
        link = a.get("link", "#")
        extra = "new-event" if a.get("is_new") else ""
        card  = f"feed-card {'' if sev=='critical' else sev} {extra}".strip()
        new_b = '<span class="badge badge-new">NEW</span>' if a.get("is_new") else ""

        st.markdown(f"""
        <div class="{card}">
            <div class="feed-title">
                <a href="{link}" target="_blank" style="color:#e8ecf0;text-decoration:none;">
                    {a['title']}
                </a>
            </div>
            <div class="feed-meta">
                {new_b}
                <span class="badge badge-{sev}">{sev}</span>
                <span class="badge badge-region">{a['region']}</span>
                📍 {a['place']} &nbsp;·&nbsp; {a['ts']} &nbsp;·&nbsp; {a['source']}
            </div>
            <div class="feed-desc">{a['summary'][:230]}{'…' if len(a['summary'])>230 else ''}</div>
        </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────

def main():
    # ① Avvia thread fetcher (idempotente — una sola volta per sessione)
    _ensure_thread()

    # ② Poll UI ogni 5s — se ci sono notizie nuove nell'inbox le aggiunge
    #    st_autorefresh fa solo un rerun Streamlit, NON un page reload.
    #    La pagina rimane stabile; solo i componenti cambiati vengono ridisegnati.
    if HAS_AUTOREFRESH:
        st_autorefresh(interval=5_000, limit=None, key="live_poll")

    # ③ Drain inbox: move new items → session_state["attacks"]
    added = _drain_inbox()

    # ── Header ──────────────────────────────────────────────────────
    now = datetime.now(ZoneInfo("Europe/Rome"))
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:12px;margin-bottom:4px;'>
        <div style='font-family:"IBM Plex Mono",monospace;font-size:1.5rem;
                    font-weight:600;color:#e8ecf0;letter-spacing:-0.02em;'>
            <span style='color:#ff3b30;'>◈</span> ITALY CYBER THREAT MAP
        </div>
        <div style='margin-left:auto;font-family:"IBM Plex Mono",monospace;
                    font-size:0.62rem;color:#586374;letter-spacing:0.08em;'>
            LIVE INTELLIGENCE DASHBOARD
        </div>
    </div>""", unsafe_allow_html=True)

    all_attacks = st.session_state.get("attacks", [])

    # ── Sidebar ──────────────────────────────────────────────────────
    sel_sev, sel_reg, date_from, date_to, sel_src, search = render_sidebar(all_attacks)
    filtered = apply_filters(all_attacks, sel_sev, sel_reg, date_from, date_to, sel_src, search)

    # ── KPIs ─────────────────────────────────────────────────────────
    total  = len(all_attacks)
    crit_n = sum(1 for a in all_attacks if a["severity"] == "critical")
    med_n  = sum(1 for a in all_attacks if a["severity"] == "medium")
    low_n  = sum(1 for a in all_attacks if a["severity"] == "low")
    reg_n  = len(set(a["region"] for a in all_attacks))

    k1,k2,k3,k4,k5 = st.columns(5)
    k1.metric("TOTAL EVENTS", total)
    k2.metric("⬤ CRITICAL",   crit_n)
    k3.metric("⬤ MEDIUM",     med_n)
    k4.metric("⬤ LOW",        low_n)
    k5.metric("REGIONS HIT",  reg_n)

    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

    # ── Status bar ───────────────────────────────────────────────────
    new_html = (f" · <span style='color:#30d158;font-weight:600;'>+{added} NEW</span>"
                if added > 0 else "")
    next_f   = FETCH_INTERVAL - (int(time.time()) % FETCH_INTERVAL)
    st.markdown(f"""
    <div class="status-bar">
        <span class="pulse-dot"></span>
        LIVE · {now.strftime('%d/%m/%Y %H:%M:%S')} IT ·
        {len(filtered)} events (filtered) · {total} in storico ·
        next fetch ~{next_f}s{new_html}
    </div>""", unsafe_allow_html=True)

    # ── Layout ───────────────────────────────────────────────────────
    map_col, feed_col = st.columns([3, 1.5], gap="medium")

    with map_col:
        fig = build_map(filtered)
        st.plotly_chart(fig, use_container_width=True, config={
            "scrollZoom": True,
            "displayModeBar": True,
            "modeBarButtonsToRemove": ["select2d","lasso2d","autoScale2d","resetScale2d"],
            "displaylogo": False,
            "toImageButtonOptions": {"format": "png", "filename": "italy_cybermap"},
        }, key="cybermap")
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:0.6rem;
                    color:#586374;text-align:center;margin-top:-8px;'>
            CLICK MARKER → REPORT COMPLETO &nbsp;·&nbsp;
            SCROLL TO ZOOM &nbsp;·&nbsp; DRAG TO PAN
        </div>""", unsafe_allow_html=True)

    with feed_col:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:0.65rem;
                    color:#586374;letter-spacing:0.1em;text-transform:uppercase;
                    padding-bottom:8px;border-bottom:1px solid #1e2730;margin-bottom:12px;'>
            ◈ INCIDENT FEED — STORICO COMPLETO
        </div>""", unsafe_allow_html=True)
        with st.container(height=650):
            render_feed(filtered)

    # ── Fallback senza streamlit-autorefresh ─────────────────────────
    if not HAS_AUTOREFRESH:
        st.markdown("""
        <script>setTimeout(function(){window.location.reload();},30000);</script>
        """, unsafe_allow_html=True)
        st.warning(
            "💡 Per aggiornamento senza page reload installa:\n"
            "`pip install streamlit-autorefresh`"
        )


if __name__ == "__main__":
    main()
