"""
╔══════════════════════════════════════════════════════════════════════╗
║  ITALY CYBER THREAT MAP — Real-time attack tracker                  ║
║                                                                      ║
║  FONTI (solo attacchi informatici reali):                           ║
║  · ransomware.live  — API JSON + RSS (vittime italiane)             ║
║  · CERT-AgID        — alerting ufficiale italiano                   ║
║  · CSIRT Italia     — gov IT incident feed                          ║
║  · Red Hot Cyber    — notizie attacchi IT in italiano               ║
║  · Cybersecurity360 — threat news Italia                            ║
║  · BleepingComputer — global, filtrato stretto per .it / Italy      ║
║  · The Hacker News  — global, filtrato stretto per Italy            ║
║  · DarkFeed         — APT / malware campaigns                       ║
║  · Hackmanac        — database attacchi pubblici                    ║
║                                                                      ║
║  ARCHITETTURA:                                                       ║
║  · Daemon thread fetcha ogni 20s (ciclo su tutte le fonti)          ║
║  · ransomware.live API JSON polled ogni 60s (cache separata)        ║
║  · st_autorefresh ogni 5s — rerun leggero, no page reload           ║
║  · Delta push: solo uid non visti → inbox → feed                    ║
║  · Filtro attacchi: keyword whitelist STRETTA                       ║
║  · Geo-parser word-boundary su 120+ città/regioni IT                ║
║                                                                      ║
║  pip install streamlit plotly requests feedparser pandas             ║
║               streamlit-autorefresh                                  ║
║  streamlit run italy_cybermap.py                                     ║
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
#  CSS
# ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
  :root {
    --bg:      #0a0c0f; --surface: #0f1318; --card: #141920;
    --border:  #1e2730; --accent:  #ff3b30; --accent2: #ff9f0a;
    --accent3: #30d158; --text:    #c8d0dc; --dim:     #586374;
  }
  html,body,[class*="css"] { background-color:var(--bg)!important; color:var(--text)!important; font-family:'IBM Plex Sans',sans-serif!important; }
  [data-testid="stSidebar"] { background:var(--surface)!important; border-right:1px solid var(--border)!important; }
  [data-testid="stSidebar"] * { color:var(--text)!important; }
  h1,h2,h3,h4 { font-family:'IBM Plex Mono',monospace!important; color:#e8ecf0!important; letter-spacing:-0.02em; }
  [data-testid="metric-container"] { background:var(--card)!important; border:1px solid var(--border)!important; border-radius:6px!important; padding:12px 16px!important; }
  [data-testid="metric-container"] label { color:var(--dim)!important; font-family:'IBM Plex Mono',monospace!important; font-size:0.65rem!important; text-transform:uppercase; letter-spacing:0.1em; }
  [data-testid="metric-container"] [data-testid="stMetricValue"] { font-family:'IBM Plex Mono',monospace!important; font-size:1.6rem!important; color:var(--accent)!important; }
  .stSelectbox>div>div,.stMultiSelect>div>div { background:var(--card)!important; border:1px solid var(--border)!important; border-radius:4px!important; color:var(--text)!important; }
  .stDateInput>div>div { background:var(--card)!important; border:1px solid var(--border)!important; color:var(--text)!important; }
  .stTextInput>div>div { background:var(--card)!important; border:1px solid var(--border)!important; color:var(--text)!important; }
  .stButton>button { background:transparent!important; border:1px solid var(--accent)!important; color:var(--accent)!important; font-family:'IBM Plex Mono',monospace!important; font-size:0.75rem!important; letter-spacing:0.08em; text-transform:uppercase; border-radius:3px!important; transition:all 0.2s; }
  .stButton>button:hover { background:var(--accent)!important; color:#fff!important; }
  hr { border-color:var(--border)!important; }
  ::-webkit-scrollbar { width:4px; height:4px; }
  ::-webkit-scrollbar-track { background:var(--bg); }
  ::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }

  .feed-card { background:var(--card); border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:4px; padding:10px 14px; margin-bottom:8px; }
  .feed-card.medium { border-left-color:var(--accent2); }
  .feed-card.low    { border-left-color:var(--accent3); }
  .feed-card.new-event { animation:flashIn 2.5s ease-out; }
  @keyframes flashIn { 0%{background:#0d2018;} 100%{background:var(--card);} }
  .feed-title { font-weight:600; font-size:0.83rem; color:#e8ecf0; margin-bottom:3px; line-height:1.35; }
  .feed-meta  { font-family:'IBM Plex Mono',monospace; font-size:0.63rem; color:var(--dim); margin-bottom:5px; }
  .feed-desc  { font-size:0.74rem; color:var(--dim); line-height:1.45; }
  .badge { display:inline-block; padding:1px 6px; border-radius:2px; font-family:'IBM Plex Mono',monospace; font-size:0.58rem; font-weight:600; letter-spacing:0.06em; margin-right:4px; text-transform:uppercase; }
  .b-critical { background:#3d1515; color:var(--accent);  border:1px solid var(--accent); }
  .b-medium   { background:#2d1f08; color:var(--accent2); border:1px solid var(--accent2); }
  .b-low      { background:#0d2418; color:var(--accent3); border:1px solid var(--accent3); }
  .b-region   { background:#1a1f2a; color:#7eb3d4; border:1px solid #2a3a4d; }
  .b-new      { background:#0d2010; color:#30d158; border:1px solid #30d158; animation:blink 0.7s step-end 6; }
  .b-source   { background:#1a1520; color:#c07aff; border:1px solid #3a2560; }
  @keyframes blink { 50%{opacity:0;} }
  .pulse-dot { display:inline-block; width:7px; height:7px; background:var(--accent); border-radius:50%; margin-right:6px; animation:pulse 1.4s infinite; vertical-align:middle; }
  @keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(255,59,48,.7)} 70%{box-shadow:0 0 0 7px rgba(255,59,48,0)} 100%{box-shadow:0 0 0 0 rgba(255,59,48,0)} }
  .status-bar { font-family:'IBM Plex Mono',monospace; font-size:0.62rem; color:var(--dim); padding:4px 0; letter-spacing:0.05em; }
  #MainMenu,footer,header { visibility:hidden!important; }
  .block-container { padding-top:1.2rem!important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
#  GEO DATABASE — ~120 città italiane, word-boundary safe
#  Ordinate lunghezza decrescente → greedy match corretto
# ─────────────────────────────────────────────────────────────────────
_CITIES_RAW = [
    ("reggio calabria",38.1147,15.6615,"Calabria"),
    ("reggio emilia",44.6989,10.6297,"Emilia-Romagna"),
    ("vibo valentia",38.6760,16.0995,"Calabria"),
    ("ascoli piceno",42.8540,13.5745,"Marche"),
    ("torre del greco",40.7877,14.3697,"Campania"),
    ("corigliano rossano",39.5624,16.5157,"Calabria"),
    ("la spezia",44.1024,9.8240,"Liguria"),
    ("l'aquila",42.3498,13.3995,"Abruzzo"),
    ("l aquila",42.3498,13.3995,"Abruzzo"),
    ("san marino",43.9354,12.4472,"Nazionale"),
    ("giugliano",40.9314,14.1958,"Campania"),
    ("bergamo",45.6983,9.6773,"Lombardia"),
    ("brescia",45.5416,10.2118,"Lombardia"),
    ("modena",44.6471,10.9252,"Emilia-Romagna"),
    ("bologna",44.4949,11.3426,"Emilia-Romagna"),
    ("palermo",38.1157,13.3615,"Sicilia"),
    ("catania",37.5079,15.0830,"Sicilia"),
    ("messina",38.1938,15.5540,"Sicilia"),
    ("siracusa",37.0755,15.2866,"Sicilia"),
    ("trapani",38.0176,12.5365,"Sicilia"),
    ("agrigento",37.3111,13.5765,"Sicilia"),
    ("caltanissetta",37.4890,14.0626,"Sicilia"),
    ("ragusa",36.9249,14.7256,"Sicilia"),
    ("enna",37.5649,14.2767,"Sicilia"),
    ("venezia",45.4408,12.3155,"Veneto"),
    ("venice",45.4408,12.3155,"Veneto"),
    ("verona",45.4384,10.9916,"Veneto"),
    ("padova",45.4064,11.8768,"Veneto"),
    ("padua",45.4064,11.8768,"Veneto"),
    ("vicenza",45.5455,11.5354,"Veneto"),
    ("treviso",45.6669,12.2430,"Veneto"),
    ("belluno",46.1373,12.2168,"Veneto"),
    ("rovigo",45.0699,11.7899,"Veneto"),
    ("trieste",45.6495,13.7768,"Friuli-Venezia Giulia"),
    ("udine",46.0711,13.2344,"Friuli-Venezia Giulia"),
    ("pordenone",45.9564,12.6611,"Friuli-Venezia Giulia"),
    ("gorizia",45.9409,13.6206,"Friuli-Venezia Giulia"),
    ("trento",46.0748,11.1217,"Trentino-Alto Adige"),
    ("bolzano",46.4983,11.3548,"Trentino-Alto Adige"),
    ("milano",45.4654,9.1859,"Lombardia"),
    ("milan",45.4654,9.1859,"Lombardia"),
    ("torino",45.0703,7.6869,"Piemonte"),
    ("turin",45.0703,7.6869,"Piemonte"),
    ("novara",45.4468,8.6219,"Piemonte"),
    ("asti",44.9003,8.2064,"Piemonte"),
    ("alessandria",44.9124,8.6154,"Piemonte"),
    ("cuneo",44.3844,7.5426,"Piemonte"),
    ("vercelli",45.3227,8.4240,"Piemonte"),
    ("biella",45.5655,8.0530,"Piemonte"),
    ("verbania",45.9230,8.5522,"Piemonte"),
    ("genova",44.4056,8.9463,"Liguria"),
    ("genoa",44.4056,8.9463,"Liguria"),
    ("savona",44.3086,8.4797,"Liguria"),
    ("imperia",43.8880,8.0278,"Liguria"),
    ("firenze",43.7696,11.2558,"Toscana"),
    ("florence",43.7696,11.2558,"Toscana"),
    ("livorno",43.5485,10.3106,"Toscana"),
    ("pisa",43.7228,10.4017,"Toscana"),
    ("siena",43.3186,11.3307,"Toscana"),
    ("arezzo",43.4633,11.8787,"Toscana"),
    ("prato",43.8777,11.1023,"Toscana"),
    ("lucca",43.8429,10.5027,"Toscana"),
    ("pistoia",43.9334,10.9166,"Toscana"),
    ("grosseto",42.7629,11.1116,"Toscana"),
    ("massa",44.0354,10.1401,"Toscana"),
    ("perugia",43.1107,12.3908,"Umbria"),
    ("terni",42.5636,12.6432,"Umbria"),
    ("ancona",43.6158,13.5189,"Marche"),
    ("pesaro",43.9098,12.9131,"Marche"),
    ("macerata",43.2989,13.4536,"Marche"),
    ("fermo",43.1614,13.7181,"Marche"),
    ("roma",41.9028,12.4964,"Lazio"),
    ("rome",41.9028,12.4964,"Lazio"),
    ("latina",41.4677,12.9035,"Lazio"),
    ("frosinone",41.6396,13.3396,"Lazio"),
    ("viterbo",42.4169,12.1044,"Lazio"),
    ("rieti",42.4042,12.8624,"Lazio"),
    ("napoli",40.8518,14.2681,"Campania"),
    ("naples",40.8518,14.2681,"Campania"),
    ("salerno",40.6824,14.7681,"Campania"),
    ("caserta",41.0748,14.3328,"Campania"),
    ("avellino",40.9143,14.7906,"Campania"),
    ("benevento",41.1297,14.7819,"Campania"),
    ("bari",41.1171,16.8719,"Puglia"),
    ("taranto",40.4644,17.2470,"Puglia"),
    ("foggia",41.4621,15.5446,"Puglia"),
    ("lecce",40.3515,18.1750,"Puglia"),
    ("brindisi",40.6327,17.9414,"Puglia"),
    ("andria",41.2272,16.2963,"Puglia"),
    ("barletta",41.3197,16.2817,"Puglia"),
    ("pescara",42.4606,14.2156,"Abruzzo"),
    ("chieti",42.3512,14.1683,"Abruzzo"),
    ("teramo",42.6589,13.7042,"Abruzzo"),
    ("campobasso",41.5603,14.6564,"Molise"),
    ("isernia",41.5950,14.2328,"Molise"),
    ("potenza",40.6404,15.8057,"Basilicata"),
    ("matera",40.6664,16.6044,"Basilicata"),
    ("catanzaro",38.9098,16.5872,"Calabria"),
    ("cosenza",39.2988,16.2548,"Calabria"),
    ("crotone",39.0814,17.1279,"Calabria"),
    ("cagliari",39.2238,9.1217,"Sardegna"),
    ("sassari",40.7259,8.5557,"Sardegna"),
    ("nuoro",40.3214,9.3307,"Sardegna"),
    ("oristano",39.9037,8.5925,"Sardegna"),
    ("aosta",45.7373,7.3154,"Valle d'Aosta"),
    ("ferrara",44.8381,11.6198,"Emilia-Romagna"),
    ("ravenna",44.4175,12.2035,"Emilia-Romagna"),
    ("parma",44.8015,10.3279,"Emilia-Romagna"),
    ("rimini",44.0678,12.5695,"Emilia-Romagna"),
    ("piacenza",45.0526,9.6926,"Emilia-Romagna"),
    ("forli",44.2227,12.0407,"Emilia-Romagna"),
    ("monza",45.5845,9.2744,"Lombardia"),
    ("como",45.8080,9.0852,"Lombardia"),
    ("varese",45.8205,8.8257,"Lombardia"),
    ("mantova",45.1564,10.7914,"Lombardia"),
    ("cremona",45.1333,10.0227,"Lombardia"),
    ("pavia",45.1847,9.1582,"Lombardia"),
    ("lodi",45.3146,9.5028,"Lombardia"),
    ("lecco",45.8554,9.3972,"Lombardia"),
    ("sondrio",46.1698,9.8713,"Lombardia"),
    ("italia",41.9028,12.4964,"Nazionale"),
    ("italy",41.9028,12.4964,"Nazionale"),
    ("italian",41.9028,12.4964,"Nazionale"),
]
CITY_LOOKUP = sorted(_CITIES_RAW, key=lambda x: -len(x[0]))

REGIONS_COORDS = {
    "Lazio":(41.9028,12.4964),"Lombardia":(45.4654,9.1859),
    "Campania":(40.8518,14.2681),"Piemonte":(45.0703,7.6869),
    "Sicilia":(37.5999,14.0154),"Liguria":(44.4056,8.9463),
    "Emilia-Romagna":(44.4949,11.3426),"Toscana":(43.7696,11.2558),
    "Puglia":(41.1171,16.8719),"Veneto":(45.4408,12.3155),
    "Friuli-Venezia Giulia":(45.6495,13.7768),"Trentino-Alto Adige":(46.0748,11.1217),
    "Umbria":(43.1107,12.3908),"Sardegna":(39.2238,9.1217),
    "Calabria":(38.9098,16.5872),"Marche":(43.6158,13.5189),
    "Abruzzo":(42.3498,13.3995),"Basilicata":(40.6404,15.8057),
    "Molise":(41.5603,14.6564),"Valle d'Aosta":(45.7373,7.3154),
    "Nazionale":(41.9028,12.4964),
}
ALL_REGIONS = sorted(REGIONS_COORDS.keys())

FALLBACK_POOL = [
    (41.9028,12.4964,"Roma","Lazio"),(45.4654,9.1859,"Milano","Lombardia"),
    (40.8518,14.2681,"Napoli","Campania"),(45.0703,7.6869,"Torino","Piemonte"),
    (44.4949,11.3426,"Bologna","Emilia-Romagna"),(43.7696,11.2558,"Firenze","Toscana"),
    (45.4408,12.3155,"Venezia","Veneto"),(38.1157,13.3615,"Palermo","Sicilia"),
    (41.1171,16.8719,"Bari","Puglia"),(44.4056,8.9463,"Genova","Liguria"),
    (43.1107,12.3908,"Perugia","Umbria"),(43.6158,13.5189,"Ancona","Marche"),
    (39.2238,9.1217,"Cagliari","Sardegna"),(46.0748,11.1217,"Trento","Trentino-Alto Adige"),
    (42.3498,13.3995,"L'Aquila","Abruzzo"),(40.6404,15.8057,"Potenza","Basilicata"),
    (38.9098,16.5872,"Catanzaro","Calabria"),(41.5603,14.6564,"Campobasso","Molise"),
]

# ─────────────────────────────────────────────────────────────────────
#  FEED SOURCES
#
#  STRATEGIA: 3 tipologie di fonte, ognuna con logica di filtro diversa
#
#  1. RANSOMWARE_API  → ransomware.live JSON API — solo vittime italiane
#     endpoint: https://api.ransomware.live/victims  (public, no auth)
#     Filtra per country == "Italy" o domain .it
#
#  2. CERT_FEED       → feed istituzionali IT (CERT-AgID, CSIRT)
#     Tutto accettato — sono già focalizzati su attacchi in Italia
#
#  3. ATTACK_RSS      → RSS specializzati cyber, filtro STRETTO:
#     - Deve contenere keyword ATTACCO (vedi _is_attack())
#     - Deve contenere keyword ITALIA (vedi _is_italian())
#     Questo esclude notizie generiche, sconti, aggiornamenti software, ecc.
# ─────────────────────────────────────────────────────────────────────

FEED_SOURCES = [
    # ── Istituzionali IT ─────────────────────────────────────────────
    {"name":"CERT-AgID",        "url":"https://cert-agid.gov.it/feed/",              "type":"CERT_FEED"},
    {"name":"CSIRT Italia",     "url":"https://www.csirt.gov.it/feed",               "type":"CERT_FEED"},
    # ── Media italiani specializzati in attacchi ─────────────────────
    {"name":"Red Hot Cyber",    "url":"https://www.redhotcyber.com/feed/",           "type":"ATTACK_RSS"},
    {"name":"Cybersecurity360", "url":"https://www.cybersecurity360.it/feed/",       "type":"ATTACK_RSS"},
    # ── Internazionali: filtro doppio (IT + attack) ───────────────────
    {"name":"BleepingComputer", "url":"https://www.bleepingcomputer.com/feed/",      "type":"ATTACK_RSS"},
    {"name":"The Hacker News",  "url":"https://feeds.feedburner.com/TheHackersNews", "type":"ATTACK_RSS"},
    {"name":"SecurityWeek",     "url":"https://feeds.feedburner.com/Securityweek",   "type":"ATTACK_RSS"},
    {"name":"Krebs on Security","url":"https://krebsonsecurity.com/feed/",           "type":"ATTACK_RSS"},
    {"name":"DarkReading",      "url":"https://www.darkreading.com/rss.xml",         "type":"ATTACK_RSS"},
    {"name":"Recorded Future",  "url":"https://www.recordedfuture.com/feed",         "type":"ATTACK_RSS"},
]

# Endpoint JSON pubblici di ransomware.live (no auth)
RANSOMWARE_LIVE_ENDPOINTS = [
    "https://api.ransomware.live/victims",           # tutte le vittime recenti
    "https://api.ransomware.live/recentvictims",     # ultimi 7 giorni
]

# ─────────────────────────────────────────────────────────────────────
#  FILTRI SEMANTICI
# ─────────────────────────────────────────────────────────────────────

# Keyword ATTACCO — deve matchare almeno una per essere accettato
_ATTACK_RE = re.compile(
    r"ransomware|cyberattack|cyber.?attack|attacco\s+inform|attacco\s+cyber"
    r"|data.?breach|databreach|violazione.?dat|fuga.?dat|leak\b|leaked"
    r"|exfiltrat|hacked\b|hack\b|hackerato|compromess"
    r"|malware|phishing|ddos|d\.d\.o\.s|distributed denial"
    r"|intrusion|infiltrat|exploit\b|zero.?day|vulnerability.?exploit"
    r"|lockbit|blackcat|cl0p|alphv|rhysida|akira\b|play\b|royal\b"
    r"|conti\b|hive\b|darkside|medusa\b|scatter"
    r"|apt\d+|nation.?state|threat.?actor|tta\b"
    r"|defacement|defaced|backdoor|trojan|worm\b|spyware|botnet"
    r"|credential.?dump|password.?dump|data.?dump|stealer"
    r"|incidente\s+inform|incidente\s+sicurezza|violazione\s+sicurezza"
    r"|attacco\s+informatico|cyber\s+crimine|cybercrime"
    r"|sanzione.*hack|hack.*sanzione|furto.?dat|sottrazione.?dat",
    re.IGNORECASE,
)

# Keyword ITALIA — deve matchare almeno una
_ITALY_RE = re.compile(
    r"\bital\w+|\broma\b|\bmilan\w*|\bnapol\w*|\btorin\w*"
    r"|\bfirenz\w*|\bbologna\b|\bvenezia\b|\bgenov\w*"
    r"|\bsicilia\b|\bsardegna\b|\bpuglia\b|\blazio\b|\blombardia\b"
    r"|\btoscana\b|\bveneto\b|\bcampania\b|\bcalabria\b"
    r"|\bpiemonte\b|\bliguria\b|\bumbria\b|\bmarche\b"
    r"|\babruzzo\b|\bbasilicata\b|\bmolise\b"
    r"|\.it[\s/\"\']|[\"\']\w+\.it\b"
    r"|\binail\b|\binps\b|\bpolizia\s+di\s+stato\b|\bcarabinieri\b"
    r"|\bconsip\b|\btrenitalia\b|\benel\b|\beni\b|\bleonardo\s+spa\b"
    r"|\bfincantieri\b|\bfastweb\b|\bintesa\s+sanpaolo\b|\bunicredit\b"
    r"|\bposte\s+italiane\b|\bautostrade\b|\bsnam\b|\bfinmeccanica\b"
    r"|\bcomune\s+di\b|\bregione\s+\w+\b|\bprovincia\s+di\b"
    r"|\bgoverno\s+italiano\b|\bministero\b|\bprefettura\b"
    r"|\basl\b|\bospedal\w+\s+\w*ital|\bsanit\w+\s+italian",
    re.IGNORECASE,
)

# Blacklist: titoli che NON sono attacchi (falsi positivi comuni)
_NOISE_RE = re.compile(
    r"sconto|offerta|prezzo|acquisto|comprare|coupon|deal\b|sale\b"
    r"|aggiornamento\s+software|patch\s+tuesday|windows\s+update"
    r"|nuovo\s+smartphone|nuovo\s+laptop|recensione|review\b"
    r"|annuncio|lancio\s+prodotto|guadagna|investimento|bitcoin\s+price"
    r"|tutorial|how.to\b|corso\b|formazione\b|webinar\b|evento\b"
    r"|assunzioni|lavoro\b|offerta\s+di\s+lavoro|carriera",
    re.IGNORECASE,
)


def _is_attack(text: str) -> bool:
    return bool(_ATTACK_RE.search(text))

def _is_italian(text: str) -> bool:
    return bool(_ITALY_RE.search(text))

def _is_noise(text: str) -> bool:
    return bool(_NOISE_RE.search(text))


# ─────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────

def _uid(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:12]

def _strip_html(t: str) -> str:
    return re.sub(r"<[^>]+>", "", t or "").strip()

def _jitter(lat, lon, a=0.04):
    return (max(36.6, min(47.1, lat + random.uniform(-a, a))),
            max(6.6,  min(18.5, lon + random.uniform(-a, a))))

def _parse_date(entry) -> datetime:
    tz = ZoneInfo("Europe/Rome")
    for attr in ("published_parsed","updated_parsed","created_parsed"):
        t = getattr(entry, attr, None)
        if t:
            try: return datetime(*t[:6], tzinfo=ZoneInfo("UTC")).astimezone(tz)
            except: pass
    return datetime.now(tz)

def _severity(text: str) -> str:
    t = text.lower()
    if re.search(r"ransomware|data.?breach|exfiltrat|zero.?day"
                 r"|lockbit|blackcat|cl0p|alphv|rhysida|akira|play\b|royal\b"
                 r"|conti\b|hive\b|darkside|medusa|scattered spider"
                 r"|apt\d|nation.?state|critical|critico", t):
        return "critical"
    if re.search(r"phishing|malware|ddos|exploit|hacked|compromess"
                 r"|breach|leak|defacement|backdoor|trojan|botnet"
                 r"|credential|stealer|intrusion|attacco", t):
        return "medium"
    return "low"

def _extract_location(text: str):
    t = text.lower()
    for city, lat, lon, region in CITY_LOOKUP:
        if re.search(r"\b" + re.escape(city) + r"\b", t):
            return lat, lon, city.title(), region
    for region, (lat, lon) in REGIONS_COORDS.items():
        if re.search(r"\b" + re.escape(region.lower()) + r"\b", t):
            return lat, lon, region, region
    return None

def _make_item(title, summary, link, source_name, published=None) -> dict:
    combined = f"{title} {summary}"
    geo = _extract_location(combined)
    if geo is None:
        fb = FALLBACK_POOL[hash(title) % len(FALLBACK_POOL)]
        lat, lon, place, region = fb
        lat, lon = _jitter(lat, lon, 0.12)
    else:
        lat, lon, place, region = geo
        lat, lon = _jitter(lat, lon, 0.04)
    if published is None:
        published = datetime.now(ZoneInfo("Europe/Rome"))
    return {
        "id":        _uid(title + link),
        "title":     title[:140],
        "summary":   summary[:340],
        "link":      link,
        "source":    source_name,
        "severity":  _severity(combined),
        "lat":       lat, "lon": lon,
        "place":     place, "region": region,
        "published": published,
        "ts":        published.strftime("%d/%m/%Y %H:%M"),
        "is_new":    False,
    }


# ─────────────────────────────────────────────────────────────────────
#  FETCHER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────

_HEADERS = {"User-Agent": "Mozilla/5.0 ItalyCyberMap/3.0"}

def _fetch_ransomware_live_api(seen: set) -> list:
    """
    Chiama l'API JSON pubblica di ransomware.live.
    Filtra per country Italy o domain .it
    Molto più ricca dell'RSS — aggiornata in tempo quasi reale.
    """
    items = []
    for endpoint in RANSOMWARE_LIVE_ENDPOINTS:
        try:
            r = requests.get(endpoint, timeout=12, headers=_HEADERS)
            if not r.ok:
                continue
            data = r.json()
            # L'API ritorna una lista di oggetti vittima
            if isinstance(data, dict):
                data = data.get("data", data.get("victims", []))
            for v in (data or []):
                # Filtra solo vittime italiane
                country = (v.get("country","") or v.get("Country","") or "").lower()
                domain  = (v.get("domain","") or v.get("website","") or "").lower()
                victim  = (v.get("victim","") or v.get("name","") or v.get("company","") or "")
                desc    = _strip_html(v.get("description","") or v.get("summary","") or "")
                group   = (v.get("group","") or v.get("ransomware_group","") or "ransomware")
                link    = (v.get("url","") or v.get("link","") or
                           f"https://www.ransomware.live/#victim-{_uid(victim)}")

                is_it = (country in ("italy","it","italia")
                         or domain.endswith(".it")
                         or _is_italian(f"{victim} {desc}"))
                if not is_it:
                    continue

                title   = f"[{group.upper()}] {victim}" if victim else f"Attacco ransomware: {group}"
                summary = desc or f"Vittima italiana del gruppo ransomware {group}."

                # Data pubblicazione
                raw_date = (v.get("published","") or v.get("date","")
                            or v.get("discovered","") or v.get("added","") or "")
                pub = datetime.now(ZoneInfo("Europe/Rome"))
                if raw_date:
                    for fmt in ("%Y-%m-%dT%H:%M:%S",",%Y-%m-%d %H:%M:%S","%Y-%m-%d"):
                        try:
                            pub = datetime.strptime(raw_date[:19], fmt).replace(
                                tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("Europe/Rome"))
                            break
                        except: pass

                item = _make_item(title, summary, link, "Ransomware.live API", pub)
                if item["id"] not in seen:
                    seen.add(item["id"])
                    item["is_new"] = True
                    items.append(item)
        except Exception:
            continue
    return items


def _fetch_rss_source(source: dict, seen: set) -> list:
    """Fetcha un feed RSS e applica i filtri semantici."""
    items = []
    try:
        r    = requests.get(source["url"], timeout=10, headers=_HEADERS)
        feed = feedparser.parse(r.text if r.ok else "")
        for entry in feed.entries[:60]:
            title   = (entry.get("title","") or "").strip()
            summary = _strip_html(entry.get("summary", entry.get("description","")))
            link    = entry.get("link","#")
            if not title:
                continue
            combined = f"{title} {summary}"

            # Rimuovi rumore (sconti, tutorial, ecc.)
            if _is_noise(combined):
                continue

            stype = source["type"]

            if stype == "CERT_FEED":
                # Feed istituzionali: accetta tutto (già focalizzati su attacchi IT)
                pass
            elif stype == "ATTACK_RSS":
                # Deve parlare di un attacco E deve riguardare l'Italia
                if not _is_attack(combined):
                    continue
                if not _is_italian(combined):
                    continue

            item = _make_item(title, summary, link, source["name"], _parse_date(entry))
            if item["id"] not in seen:
                seen.add(item["id"])
                item["is_new"] = True
                items.append(item)
    except Exception:
        pass
    return items


# ─────────────────────────────────────────────────────────────────────
#  BACKGROUND THREAD
#  Ciclo continuo: ogni 20s fetcha tutti gli RSS
#                  ogni 60s fetcha anche l'API ransomware.live
# ─────────────────────────────────────────────────────────────────────

RSS_INTERVAL = 20   # secondi tra un fetch RSS e il successivo
API_INTERVAL = 60   # secondi tra fetch API ransomware.live

def _background_fetch(inbox: list, lock: threading.Lock, seen: set):
    last_api = 0.0
    while True:
        new_items = []

        # API ransomware.live (ogni 60s)
        if time.time() - last_api >= API_INTERVAL:
            new_items.extend(_fetch_ransomware_live_api(seen))
            last_api = time.time()

        # Tutti gli RSS (ogni 20s)
        for source in FEED_SOURCES:
            new_items.extend(_fetch_rss_source(source, seen))

        if new_items:
            new_items.sort(key=lambda x: x["published"], reverse=True)
            with lock:
                inbox.extend(new_items)

        time.sleep(RSS_INTERVAL)


def _ensure_thread():
    if "_fetch_thread" not in st.session_state:
        inbox = []
        lock  = threading.Lock()
        seen  = set()
        t = threading.Thread(
            target=_background_fetch, args=(inbox, lock, seen),
            daemon=True, name="CyberFetcher",
        )
        t.start()
        st.session_state.update({
            "_fetch_thread": t,
            "_inbox": inbox, "_lock": lock, "_seen": seen,
            "attacks": [], "new_count": 0,
        })


def _drain_inbox() -> int:
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
#  MAP
# ─────────────────────────────────────────────────────────────────────

SEV_COLOR = {"critical":"#ff3b30","medium":"#ff9f0a","low":"#30d158"}
SEV_GLOW  = {"critical":"rgba(255,59,48,.15)","medium":"rgba(255,159,10,.15)","low":"rgba(48,209,88,.15)"}
SEV_SIZE  = {"critical":14,"medium":10,"low":8}
SEV_GSIZ  = {"critical":28,"medium":21,"low":15}

def build_map(attacks: list) -> go.Figure:
    df = pd.DataFrame(attacks) if attacks else pd.DataFrame(
        columns=["lat","lon","title","place","region","severity","ts","source","link"])
    fig = go.Figure()

    for sev in ["critical","medium","low"]:
        sub = df[df["severity"]==sev] if len(df) else pd.DataFrame()
        if sub.empty: continue

        hover = [
            f"<b>{row['title'][:72]}{'…' if len(row['title'])>72 else ''}</b><br>"
            f"<span style='color:#7eb3d4'>📍 {row['place']} — {row['region']}</span><br>"
            f"<span style='color:#586374'>🕒 {row['ts']} · {row['source']}</span><br>"
            f"<span style='color:{SEV_COLOR[sev]};font-weight:600;font-size:10px'>▲ {sev.upper()}</span>"
            for _, row in sub.iterrows()
        ]
        lons, lats = sub["lon"].tolist(), sub["lat"].tolist()
        links = sub["link"].tolist() if "link" in sub.columns else []

        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=f"_g{sev}",
            marker=dict(size=SEV_GSIZ[sev],color=SEV_GLOW[sev],opacity=.5),
            hoverinfo="skip",showlegend=False))
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=f"_m{sev}",
            marker=dict(size=int(SEV_GSIZ[sev]*.56),color=SEV_GLOW[sev],opacity=.38),
            hoverinfo="skip",showlegend=False))
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=sev.upper(),
            marker=dict(size=SEV_SIZE[sev],color=SEV_COLOR[sev],opacity=.95),
            text=hover,hovertemplate="%{text}<extra></extra>",customdata=links))

    fig.update_layout(
        paper_bgcolor="#0a0c0f",plot_bgcolor="#0a0c0f",height=650,
        margin=dict(l=0,r=0,t=0,b=0),
        mapbox=dict(style="carto-darkmatter",center=dict(lat=42.2,lon=12.8),zoom=4.9,
                    bounds=dict(west=5.5,east=20.0,south=35.0,north=48.5)),
        legend=dict(orientation="h",yanchor="bottom",y=0.02,xanchor="left",x=0.01,
                    bgcolor="rgba(10,12,15,.85)",bordercolor="#1e2730",borderwidth=1,
                    font=dict(family="IBM Plex Mono",size=10,color="#c8d0dc"),itemsizing="constant"),
        hoverlabel=dict(bgcolor="#0f1318",bordercolor="#2a3540",
                        font=dict(family="IBM Plex Sans",size=12,color="#c8d0dc"),align="left"),
        dragmode="pan",uirevision="italy_map",
    )
    for trace in fig.data:
        if trace.name and trace.name.startswith("_"): trace.showlegend=False
    return fig


# ─────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────

def render_sidebar(attacks: list):
    with st.sidebar:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.7rem;color:#586374;
             letter-spacing:.12em;text-transform:uppercase;
             padding:4px 0 16px 0;border-bottom:1px solid #1e2730;margin-bottom:16px;'>
            ◈ FILTERS
        </div>""", unsafe_allow_html=True)

        sel_sev = st.multiselect("SEVERITY",["critical","medium","low"],
                                 default=["critical","medium","low"],format_func=str.upper)
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        avail_reg = sorted(set(a["region"] for a in attacks)) if attacks else ALL_REGIONS
        sel_reg   = st.multiselect("REGION",avail_reg,default=[],placeholder="All regions")
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        today,wago = datetime.now().date(), datetime.now().date()-timedelta(days=7)
        c1,c2 = st.columns(2)
        with c1: df_ = st.date_input("FROM",value=wago)
        with c2: dt_ = st.date_input("TO",  value=today)
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        avail_src = sorted(set(a["source"] for a in attacks)) if attacks else []
        sel_src   = st.multiselect("SOURCE",avail_src,default=[],placeholder="All sources")
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        search = st.text_input("🔍 SEARCH",placeholder="ransomware, bari, enel…")
        st.markdown("<hr style='border-color:#1e2730;margin:16px 0'>",unsafe_allow_html=True)

        if st.button("↺  RESET FILTERS"): st.rerun()

        src_html = "".join(
            f"<span style='color:#7eb3d4;'>·</span> {s['name']}"
            f"<span style='color:#3a2560;font-size:.55rem;'> [{s['type']}]</span><br>"
            for s in [{"name":"Ransomware.live API","type":"API"}] + FEED_SOURCES
        )
        st.markdown(f"""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.57rem;
                    color:#586374;margin-top:20px;line-height:1.9;'>
            SOURCES ({len(FEED_SOURCES)+1})<br>{src_html}
            <br>
            <span style='color:#30d158;'>● RSS FETCH:</span> ogni {RSS_INTERVAL}s<br>
            <span style='color:#ff3b30;'>● API FETCH:</span> ogni {API_INTERVAL}s<br>
            <span style='color:#ff9f0a;'>● UI POLL:</span> ogni 5s (no reload)
        </div>""", unsafe_allow_html=True)

    return sel_sev, sel_reg, df_, dt_, sel_src, search


def apply_filters(attacks, sel_sev, sel_reg, df_, dt_, sel_src, search):
    f = attacks
    if sel_sev: f = [a for a in f if a["severity"] in sel_sev]
    if sel_reg: f = [a for a in f if a["region"]   in sel_reg]
    if sel_src: f = [a for a in f if a["source"]   in sel_src]
    f = [a for a in f if df_ <= a["published"].date() <= dt_]
    if search:
        q = search.lower()
        f = [a for a in f if q in a["title"].lower()
             or q in a["summary"].lower() or q in a["place"].lower()
             or q in a["source"].lower()]
    return f


# ─────────────────────────────────────────────────────────────────────
#  FEED RENDERER
# ─────────────────────────────────────────────────────────────────────

def render_feed(attacks: list):
    if not attacks:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.75rem;
             color:#586374;text-align:center;padding:40px 0;'>
            <div style='font-size:1.5rem;margin-bottom:8px;'>◌</div>
            IN ATTESA DI NOTIZIE…<br>
            <span style='font-size:.6rem;'>fetch ogni 20s · API ogni 60s</span>
        </div>""", unsafe_allow_html=True)
        return

    for a in attacks:
        sev   = a["severity"]
        link  = a.get("link","#")
        extra = "new-event" if a.get("is_new") else ""
        card  = f"feed-card {'' if sev=='critical' else sev} {extra}".strip()
        new_b = '<span class="badge b-new">● NEW</span>' if a.get("is_new") else ""

        st.markdown(f"""
        <div class="{card}">
          <div class="feed-title">
            <a href="{link}" target="_blank" style="color:#e8ecf0;text-decoration:none;">
              {a['title']}
            </a>
          </div>
          <div class="feed-meta">
            {new_b}
            <span class="badge b-{sev}">{sev}</span>
            <span class="badge b-region">{a['region']}</span>
            <span class="badge b-source">{a['source']}</span>
            📍 {a['place']} &nbsp;·&nbsp; {a['ts']}
          </div>
          <div class="feed-desc">{a['summary'][:240]}{'…' if len(a['summary'])>240 else ''}</div>
        </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────

def main():
    _ensure_thread()

    if HAS_AUTOREFRESH:
        st_autorefresh(interval=5_000, limit=None, key="live_poll")

    added = _drain_inbox()

    now = datetime.now(ZoneInfo("Europe/Rome"))
    st.markdown("""
    <div style='display:flex;align-items:center;gap:12px;margin-bottom:4px;'>
      <div style='font-family:"IBM Plex Mono",monospace;font-size:1.5rem;
                  font-weight:600;color:#e8ecf0;letter-spacing:-0.02em;'>
        <span style='color:#ff3b30;'>◈</span> ITALY CYBER THREAT MAP
      </div>
      <div style='margin-left:auto;font-family:"IBM Plex Mono",monospace;
                  font-size:.62rem;color:#586374;letter-spacing:.08em;'>
        LIVE ATTACK INTELLIGENCE
      </div>
    </div>""", unsafe_allow_html=True)

    all_attacks = st.session_state.get("attacks", [])
    sel_sev,sel_reg,df_,dt_,sel_src,search = render_sidebar(all_attacks)
    filtered = apply_filters(all_attacks,sel_sev,sel_reg,df_,dt_,sel_src,search)

    total  = len(all_attacks)
    crit_n = sum(1 for a in all_attacks if a["severity"]=="critical")
    med_n  = sum(1 for a in all_attacks if a["severity"]=="medium")
    low_n  = sum(1 for a in all_attacks if a["severity"]=="low")
    reg_n  = len(set(a["region"] for a in all_attacks))

    k1,k2,k3,k4,k5 = st.columns(5)
    k1.metric("TOTAL ATTACKS", total)
    k2.metric("⬤ CRITICAL",    crit_n)
    k3.metric("⬤ MEDIUM",      med_n)
    k4.metric("⬤ LOW",         low_n)
    k5.metric("REGIONS HIT",   reg_n)

    st.markdown("<div style='height:4px'></div>",unsafe_allow_html=True)

    new_html = (f" · <span style='color:#30d158;font-weight:600;animation:blink .7s step-end 4;"
                f"'>+{added} NEW</span>" if added>0 else "")
    next_rss = RSS_INTERVAL - (int(time.time()) % RSS_INTERVAL)
    st.markdown(f"""
    <div class="status-bar">
      <span class="pulse-dot"></span>
      LIVE · {now.strftime('%d/%m/%Y %H:%M:%S')} IT ·
      {len(filtered)} eventi (filtrati) · {total} in storico ·
      next fetch ~{next_rss}s{new_html}
    </div>""", unsafe_allow_html=True)

    map_col, feed_col = st.columns([3,1.5], gap="medium")

    with map_col:
        fig = build_map(filtered)
        st.plotly_chart(fig, use_container_width=True, config={
            "scrollZoom":True,"displayModeBar":True,"displaylogo":False,
            "modeBarButtonsToRemove":["select2d","lasso2d","autoScale2d","resetScale2d"],
            "toImageButtonOptions":{"format":"png","filename":"italy_cybermap"},
        }, key="cybermap")
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.6rem;
                    color:#586374;text-align:center;margin-top:-8px;'>
          CLICK MARKER → REPORT COMPLETO &nbsp;·&nbsp; SCROLL TO ZOOM &nbsp;·&nbsp; DRAG TO PAN
        </div>""", unsafe_allow_html=True)

    with feed_col:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.65rem;color:#586374;
                    letter-spacing:.1em;text-transform:uppercase;
                    padding-bottom:8px;border-bottom:1px solid #1e2730;margin-bottom:12px;'>
            ◈ INCIDENT FEED — STORICO ATTACCHI
        </div>""", unsafe_allow_html=True)
        with st.container(height=650):
            render_feed(filtered)

    if not HAS_AUTOREFRESH:
        st.markdown("<script>setTimeout(()=>window.location.reload(),30000)</script>",
                    unsafe_allow_html=True)
        st.warning("💡 `pip install streamlit-autorefresh` per aggiornamento senza reload")


if __name__ == "__main__":
    main()
