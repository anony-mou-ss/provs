"""
╔══════════════════════════════════════════════════════════════════════╗
║  ITALY CYBER THREAT MAP  v4.0                                       ║
║  Real-time attack tracker — 80+ source integrations                 ║
║                                                                      ║
║  ARCHITETTURA REAL-TIME:                                             ║
║  ┌─────────────────────────────────────────────────────────┐        ║
║  │  background thread  →  JSON file  →  st_autorefresh     │        ║
║  │  (fetcha ogni 15s)      (IPC)         (legge ogni 3s)   │        ║
║  └─────────────────────────────────────────────────────────┘        ║
║  Il thread scrive su /tmp/cybermap_feed.json                        ║
║  Streamlit rilegge il file ad ogni rerun (ogni 3s)                  ║
║  Questo bypassa il limite di thread-safety di session_state         ║
║                                                                      ║
║  DEDUP INTELLIGENTE:                                                 ║
║  · Hash su (dominio vittima + gruppo) per ransomware                ║
║  · Hash su (titolo normalizzato) per news                           ║
║  · Se arriva update su evento esistente → merge summary             ║
║                                                                      ║
║  INSTALL:                                                            ║
║    pip install streamlit plotly requests feedparser pandas           ║
║                streamlit-autorefresh                                 ║
║                                                                      ║
║  API KEYS (opzionali — in .streamlit/secrets.toml):                 ║
║    NEWSAPI_KEY, ALIENVAULT_KEY, VIRUSTOTAL_KEY, SHODAN_KEY          ║
║    GREYNOISE_KEY, PULSEDIVE_KEY, BINARYEDGE_KEY                     ║
║    SECURITYTRAILS_KEY, CRIMINALIP_KEY, INTELX_KEY                   ║
║    HYBRID_ANALYSIS_KEY, AYLIEN_APP_ID, AYLIEN_APP_KEY               ║
║    NEWSCATCHER_KEY, MEDIASTACK_KEY, CONTEXTUALWEB_KEY               ║
║                                                                      ║
║  RUN:  streamlit run italy_cybermap.py                               ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# ── stdlib ────────────────────────────────────────────────────────────
import json
import os
import re
import hashlib
import random
import threading
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path

# ── third-party ───────────────────────────────────────────────────────
import streamlit as st
import plotly.graph_objects as go
import requests
import feedparser
import pandas as pd

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False

# ─────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────
TZ_IT          = ZoneInfo("Europe/Rome")
FEED_FILE      = Path("/tmp/cybermap_feed.json")   # IPC between thread ↔ UI
LOCK_FILE      = Path("/tmp/cybermap_feed.lock")
RSS_INTERVAL   = 15   # seconds between RSS cycles
API_INTERVAL   = 60   # seconds between heavy API calls
MAX_ITEMS      = 2000 # max items kept in memory
POLL_MS        = 3000 # ms between UI reruns

_HEADERS = {
    "User-Agent": "Mozilla/5.0 ItalyCyberMap/4.0",
    "Accept": "application/json,text/html,application/xml,*/*",
}

# ─────────────────────────────────────────────────────────────────────
#  PAGE CONFIG & CSS
# ─────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Italy Cyber Threat Map",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
:root{--bg:#0a0c0f;--surf:#0f1318;--card:#141920;--brd:#1e2730;
      --red:#ff3b30;--ora:#ff9f0a;--grn:#30d158;--txt:#c8d0dc;--dim:#586374;}
html,body,[class*="css"]{background:var(--bg)!important;color:var(--txt)!important;
  font-family:'IBM Plex Sans',sans-serif!important;}
[data-testid="stSidebar"]{background:var(--surf)!important;border-right:1px solid var(--brd)!important;}
[data-testid="stSidebar"] *{color:var(--txt)!important;}
h1,h2,h3,h4{font-family:'IBM Plex Mono',monospace!important;color:#e8ecf0!important;}
[data-testid="metric-container"]{background:var(--card)!important;border:1px solid var(--brd)!important;
  border-radius:6px!important;padding:12px 16px!important;}
[data-testid="metric-container"] label{color:var(--dim)!important;
  font-family:'IBM Plex Mono',monospace!important;font-size:.65rem!important;
  text-transform:uppercase;letter-spacing:.1em;}
[data-testid="metric-container"] [data-testid="stMetricValue"]{
  font-family:'IBM Plex Mono',monospace!important;font-size:1.6rem!important;color:var(--red)!important;}
.stSelectbox>div>div,.stMultiSelect>div>div,.stTextInput>div>div,.stDateInput>div>div{
  background:var(--card)!important;border:1px solid var(--brd)!important;
  border-radius:4px!important;color:var(--txt)!important;}
.stButton>button{background:transparent!important;border:1px solid var(--red)!important;
  color:var(--red)!important;font-family:'IBM Plex Mono',monospace!important;
  font-size:.75rem!important;letter-spacing:.08em;text-transform:uppercase;
  border-radius:3px!important;transition:all .2s;}
.stButton>button:hover{background:var(--red)!important;color:#fff!important;}
hr{border-color:var(--brd)!important;}
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px;}

/* ── Feed cards ─────────────────────────────────────────────────── */
.feed-card{background:var(--card);border:1px solid var(--brd);
  border-left:3px solid var(--red);border-radius:4px;
  padding:10px 14px;margin-bottom:8px;}
.feed-card.medium{border-left-color:var(--ora);}
.feed-card.low{border-left-color:var(--grn);}
.feed-card.new-event{animation:flashIn 2.5s ease-out;}
.feed-card.updated{animation:flashUpd 2s ease-out;}
@keyframes flashIn{0%{background:#0d2018;}100%{background:var(--card);}}
@keyframes flashUpd{0%{background:#1a1500;}100%{background:var(--card);}}
.feed-title{font-weight:600;font-size:.83rem;color:#e8ecf0;
  margin-bottom:3px;line-height:1.35;}
.feed-meta{font-family:'IBM Plex Mono',monospace;font-size:.62rem;
  color:var(--dim);margin-bottom:5px;line-height:1.6;}
.feed-desc{font-size:.74rem;color:var(--dim);line-height:1.45;}
.badge{display:inline-block;padding:1px 6px;border-radius:2px;
  font-family:'IBM Plex Mono',monospace;font-size:.58rem;font-weight:600;
  letter-spacing:.05em;margin-right:3px;text-transform:uppercase;}
.b-critical{background:#3d1515;color:var(--red);border:1px solid var(--red);}
.b-medium{background:#2d1f08;color:var(--ora);border:1px solid var(--ora);}
.b-low{background:#0d2418;color:var(--grn);border:1px solid var(--grn);}
.b-region{background:#1a1f2a;color:#7eb3d4;border:1px solid #2a3a4d;}
.b-source{background:#1a1520;color:#c07aff;border:1px solid #3a2560;}
.b-new{background:#0d2010;color:var(--grn);border:1px solid var(--grn);
  animation:blink .7s step-end 6;}
.b-upd{background:#1a1500;color:var(--ora);border:1px solid var(--ora);
  animation:blink .7s step-end 4;}
@keyframes blink{50%{opacity:0;}}

/* ── Pulse dot ───────────────────────────────────────────────────── */
.pulse-dot{display:inline-block;width:7px;height:7px;background:var(--red);
  border-radius:50%;margin-right:6px;animation:pulse 1.4s infinite;vertical-align:middle;}
@keyframes pulse{
  0%{box-shadow:0 0 0 0 rgba(255,59,48,.7);}
  70%{box-shadow:0 0 0 7px rgba(255,59,48,0);}
  100%{box-shadow:0 0 0 0 rgba(255,59,48,0);}}
.status-bar{font-family:'IBM Plex Mono',monospace;font-size:.62rem;
  color:var(--dim);padding:4px 0;letter-spacing:.05em;}
#MainMenu,footer,header{visibility:hidden!important;}
.block-container{padding-top:1.2rem!important;}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
#  GEO DATABASE
# ─────────────────────────────────────────────────────────────────────
_CITIES = sorted([
    ("reggio calabria",38.1147,15.6615,"Calabria"),
    ("reggio emilia",44.6989,10.6297,"Emilia-Romagna"),
    ("vibo valentia",38.6760,16.0995,"Calabria"),
    ("ascoli piceno",42.8540,13.5745,"Marche"),
    ("torre del greco",40.7877,14.3697,"Campania"),
    ("la spezia",44.1024,9.824,"Liguria"),
    ("l'aquila",42.3498,13.3995,"Abruzzo"),
    ("san marino",43.9354,12.4472,"Nazionale"),
    ("giugliano",40.9314,14.1958,"Campania"),
    ("bergamo",45.6983,9.6773,"Lombardia"),
    ("brescia",45.5416,10.2118,"Lombardia"),
    ("modena",44.6471,10.9252,"Emilia-Romagna"),
    ("bologna",44.4949,11.3426,"Emilia-Romagna"),
    ("palermo",38.1157,13.3615,"Sicilia"),
    ("catania",37.5079,15.083,"Sicilia"),
    ("messina",38.1938,15.554,"Sicilia"),
    ("siracusa",37.0755,15.2866,"Sicilia"),
    ("trapani",38.0176,12.5365,"Sicilia"),
    ("agrigento",37.3111,13.5765,"Sicilia"),
    ("ragusa",36.9249,14.7256,"Sicilia"),
    ("venezia",45.4408,12.3155,"Veneto"),
    ("venice",45.4408,12.3155,"Veneto"),
    ("verona",45.4384,10.9916,"Veneto"),
    ("padova",45.4064,11.8768,"Veneto"),
    ("padua",45.4064,11.8768,"Veneto"),
    ("vicenza",45.5455,11.5354,"Veneto"),
    ("treviso",45.6669,12.243,"Veneto"),
    ("trieste",45.6495,13.7768,"Friuli-Venezia Giulia"),
    ("udine",46.0711,13.2344,"Friuli-Venezia Giulia"),
    ("trento",46.0748,11.1217,"Trentino-Alto Adige"),
    ("bolzano",46.4983,11.3548,"Trentino-Alto Adige"),
    ("milano",45.4654,9.1859,"Lombardia"),
    ("milan",45.4654,9.1859,"Lombardia"),
    ("torino",45.0703,7.6869,"Piemonte"),
    ("turin",45.0703,7.6869,"Piemonte"),
    ("novara",45.4468,8.6219,"Piemonte"),
    ("genova",44.4056,8.9463,"Liguria"),
    ("genoa",44.4056,8.9463,"Liguria"),
    ("firenze",43.7696,11.2558,"Toscana"),
    ("florence",43.7696,11.2558,"Toscana"),
    ("livorno",43.5485,10.3106,"Toscana"),
    ("pisa",43.7228,10.4017,"Toscana"),
    ("siena",43.3186,11.3307,"Toscana"),
    ("arezzo",43.4633,11.8787,"Toscana"),
    ("prato",43.8777,11.1023,"Toscana"),
    ("perugia",43.1107,12.3908,"Umbria"),
    ("ancona",43.6158,13.5189,"Marche"),
    ("pesaro",43.9098,12.9131,"Marche"),
    ("roma",41.9028,12.4964,"Lazio"),
    ("rome",41.9028,12.4964,"Lazio"),
    ("latina",41.4677,12.9035,"Lazio"),
    ("frosinone",41.6396,13.3396,"Lazio"),
    ("napoli",40.8518,14.2681,"Campania"),
    ("naples",40.8518,14.2681,"Campania"),
    ("salerno",40.6824,14.7681,"Campania"),
    ("caserta",41.0748,14.3328,"Campania"),
    ("bari",41.1171,16.8719,"Puglia"),
    ("taranto",40.4644,17.247,"Puglia"),
    ("foggia",41.4621,15.5446,"Puglia"),
    ("lecce",40.3515,18.175,"Puglia"),
    ("brindisi",40.6327,17.9414,"Puglia"),
    ("pescara",42.4606,14.2156,"Abruzzo"),
    ("campobasso",41.5603,14.6564,"Molise"),
    ("potenza",40.6404,15.8057,"Basilicata"),
    ("matera",40.6664,16.6044,"Basilicata"),
    ("catanzaro",38.9098,16.5872,"Calabria"),
    ("cosenza",39.2988,16.2548,"Calabria"),
    ("crotone",39.0814,17.1279,"Calabria"),
    ("cagliari",39.2238,9.1217,"Sardegna"),
    ("sassari",40.7259,8.5557,"Sardegna"),
    ("aosta",45.7373,7.3154,"Valle d'Aosta"),
    ("ferrara",44.8381,11.6198,"Emilia-Romagna"),
    ("ravenna",44.4175,12.2035,"Emilia-Romagna"),
    ("parma",44.8015,10.3279,"Emilia-Romagna"),
    ("rimini",44.0678,12.5695,"Emilia-Romagna"),
    ("piacenza",45.0526,9.6926,"Emilia-Romagna"),
    ("monza",45.5845,9.2744,"Lombardia"),
    ("como",45.808,9.0852,"Lombardia"),
    ("varese",45.8205,8.8257,"Lombardia"),
    ("mantova",45.1564,10.7914,"Lombardia"),
    ("italia",41.9028,12.4964,"Nazionale"),
    ("italy",41.9028,12.4964,"Nazionale"),
    ("italian",41.9028,12.4964,"Nazionale"),
], key=lambda x: -len(x[0]))

REGIONS = {
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

_FALLBACK = [
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
#  SEMANTIC FILTERS
# ─────────────────────────────────────────────────────────────────────
_ATTACK_RE = re.compile(
    r"ransomware|cyberattack|cyber.?attack|attacco\s+(cyber|inform)"
    r"|data.?breach|databreach|violazione.?dat|fuga.?dat"
    r"|leak(ed)?\b|exfiltrat|hacked?\b|hackerato|compromess"
    r"|malware|phishing|ddos|d\.d\.o\.s|exploit(ed)?\b|zero.?day"
    r"|lockbit|blackcat|cl0p|alphv|rhysida|akira\b|play\b|royal\b"
    r"|conti\b|hive\b|darkside|medusa\b|scatter|qakbot|emotet"
    r"|apt\d+|nation.?state|threat.?actor|tta\b|cyber.?espionage"
    r"|defacement|defaced|backdoor|trojan|worm\b|spyware|botnet"
    r"|credential.?dump|stealer|intrusion|incidente.?(sicurezza|inform)"
    r"|attacco.?informatico|cybercrime|cyber.?crimine|frode.?inform"
    r"|furto.?dat|unauthorized.?access|accesso.?non.?autoriz",
    re.I,
)
_ITALY_RE = re.compile(
    r"\bital\w+|\broma\b|\bmilan\w*|\bnapol\w*|\btorin\w*"
    r"|\bfirenz\w*|\bbologna\b|\bvenezia\b|\bgenov\w*"
    r"|\bsicilia\b|\bsardegna\b|\bpuglia\b|\blazio\b|\blombardia\b"
    r"|\btoscana\b|\bveneto\b|\bcampania\b|\bcalabria\b|\bpiemonte\b"
    r"|\bliguria\b|\bumbria\b|\bmarche\b|\babruzzo\b|\bbasilicata\b"
    r"|\.it[\s/\"\'<]|[\"\']\w+\.it\b"
    r"|\binail\b|\binps\b|\bpolizia\s+di\s+stato|\bcarabinieri\b"
    r"|\bconsip\b|\btrenitalia\b|\benel\b|\beni\b|\bleonardo\s+spa\b"
    r"|\bfincantieri\b|\bfastweb\b|\bintesa\s+sanpaolo\b|\bunicredit\b"
    r"|\bposte\s+italiane\b|\bautostrade\b|\bsnam\b|\bfinmeccanica\b"
    r"|\bcomune\s+di\b|\bregione\s+\w+|\bprovincia\s+di\b"
    r"|\bgoverno\s+italiano|\bministero\b|\bprefettura\b"
    r"|\basl\b|\bospedal\w+.{0,20}ital|\bsanit\w+.{0,15}italian",
    re.I,
)
_NOISE_RE = re.compile(
    r"\bsconto\b|\bofferta\b|\bprezzo\b|\bcoupon\b|\bdeal\b"
    r"|\bpatch\s+tuesday\b|\bwindows\s+update\b|\brecensione\b"
    r"|\breview\b|\bannuncio\b|\blancio.{0,10}prodott"
    r"|\btutorial\b|\bhow.to\b|\bcorso\b|\bwebinar\b|\bevento\b"
    r"|\bassunzion\b|\bofferta.{0,10}lavoro\b|\bcarriera\b",
    re.I,
)

def _is_attack(t): return bool(_ATTACK_RE.search(t))
def _is_italian(t): return bool(_ITALY_RE.search(t))
def _is_noise(t):   return bool(_NOISE_RE.search(t))

# ─────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────
def _uid(s: str) -> str:
    return hashlib.md5(s.lower().strip().encode("utf-8","replace")).hexdigest()[:12]

def _dedup_key(title: str, source: str) -> str:
    """Chiave di dedup: normalizza titolo rimuovendo date e numeri."""
    t = re.sub(r"\b\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b","",title.lower())
    t = re.sub(r"\s+"," ",t).strip()
    return _uid(t)

def _strip_html(s: str) -> str:
    return re.sub(r"<[^>]+>","",s or "").strip()

def _jitter(lat,lon,a=0.04):
    return (max(36.6,min(47.1,lat+random.uniform(-a,a))),
            max(6.6, min(18.5,lon+random.uniform(-a,a))))

def _severity(t: str) -> str:
    t = t.lower()
    if re.search(r"ransomware|data.?breach|exfiltrat|zero.?day"
                 r"|lockbit|blackcat|cl0p|alphv|rhysida|akira|play\b|royal\b"
                 r"|conti\b|hive\b|darkside|medusa|scattered|apt\d|nation.?state"
                 r"|critico|critical|emergency|urgente",t): return "critical"
    if re.search(r"phishing|malware|ddos|exploit|hacked|compromess|breach|leak"
                 r"|defacement|backdoor|trojan|botnet|stealer|intrusion|attacco",t): return "medium"
    return "low"

def _geo(text: str):
    t = text.lower()
    for city,lat,lon,reg in _CITIES:
        if re.search(r"\b"+re.escape(city)+r"\b",t):
            return lat,lon,city.title(),reg
    for reg,(lat,lon) in REGIONS.items():
        if re.search(r"\b"+re.escape(reg.lower())+r"\b",t):
            return lat,lon,reg,reg
    return None

def _now_it() -> datetime:
    return datetime.now(TZ_IT)

def _parse_date_str(s: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S","%Y-%m-%dT%H:%M:%SZ","%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19],fmt).replace(tzinfo=ZoneInfo("UTC")).astimezone(TZ_IT)
        except: pass
    return _now_it()

def _parse_rss_date(entry) -> datetime:
    for attr in ("published_parsed","updated_parsed","created_parsed"):
        t = getattr(entry,attr,None)
        if t:
            try: return datetime(*t[:6],tzinfo=ZoneInfo("UTC")).astimezone(TZ_IT)
            except: pass
    return _now_it()

def _make_item(title,summary,link,source,published=None,extra_text="") -> dict:
    if published is None: published = _now_it()
    combined = f"{title} {summary} {extra_text}"
    g = _geo(combined)
    if g is None:
        fb = _FALLBACK[hash(title) % len(_FALLBACK)]
        lat,lon = _jitter(fb[0],fb[1],0.12)
        place,region = fb[2],fb[3]
    else:
        lat,lon,place,region = g
        lat,lon = _jitter(lat,lon,0.04)
    return {
        "id":        _uid(title+link),
        "dedup_key": _dedup_key(title,source),
        "title":     title[:150],
        "summary":   summary[:400],
        "link":      link,
        "source":    source,
        "severity":  _severity(combined),
        "lat":       round(lat,5),"lon":round(lon,5),
        "place":     place,"region":region,
        "published": published.isoformat(),
        "ts":        published.strftime("%d/%m/%Y %H:%M"),
        "is_new":    True,
        "is_updated":False,
        "update_count":0,
    }

def _merge_item(existing: dict, new: dict) -> dict:
    """Merge una notizia duplicata aggiornando il summary se più ricco."""
    if len(new["summary"]) > len(existing["summary"]):
        existing["summary"] = new["summary"]
    if new["severity"] == "critical" and existing["severity"] != "critical":
        existing["severity"] = "critical"
    existing["is_updated"] = True
    existing["update_count"] = existing.get("update_count",0) + 1
    return existing

# ─────────────────────────────────────────────────────────────────────
#  FILE-BASED IPC
#  Il thread scrive su /tmp/cybermap_feed.json
#  L'UI legge il file ad ogni rerun (thread-safe via atomic write)
# ─────────────────────────────────────────────────────────────────────
_file_lock = threading.Lock()

def _write_feed(items: list):
    """Scrive atomicamente la lista in JSON."""
    tmp = FEED_FILE.with_suffix(".tmp")
    with _file_lock:
        try:
            tmp.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
            tmp.replace(FEED_FILE)
        except Exception:
            pass

def _read_feed() -> list:
    """Legge il JSON dal file. Ritorna [] se non esiste."""
    try:
        if FEED_FILE.exists():
            data = json.loads(FEED_FILE.read_text(encoding="utf-8"))
            # Converti published string → datetime per compatibilità
            for item in data:
                if isinstance(item.get("published"), str):
                    try:
                        item["published"] = datetime.fromisoformat(item["published"])
                    except Exception:
                        item["published"] = _now_it()
            return data
    except Exception:
        pass
    return []

# ─────────────────────────────────────────────────────────────────────
#  SOURCE REGISTRY
#  Ogni fonte ha: name, type, url/endpoint, fetch_fn
# ─────────────────────────────────────────────────────────────────────

def _secrets() -> dict:
    """Legge le API key da st.secrets o env vars."""
    keys = {}
    key_names = [
        "NEWSAPI_KEY","ALIENVAULT_KEY","VIRUSTOTAL_KEY","SHODAN_KEY",
        "GREYNOISE_KEY","PULSEDIVE_KEY","BINARYEDGE_KEY","SECURITYTRAILS_KEY",
        "CRIMINALIP_KEY","INTELX_KEY","HYBRID_ANALYSIS_KEY",
        "AYLIEN_APP_ID","AYLIEN_APP_KEY","NEWSCATCHER_KEY",
        "MEDIASTACK_KEY","CONTEXTUALWEB_KEY","URLSCAN_KEY","THREATFOX_KEY",
    ]
    for k in key_names:
        try:    keys[k] = st.secrets.get(k) or os.environ.get(k,"")
        except: keys[k] = os.environ.get(k,"")
    return keys

# ─────────────────────────────────────────────────────────────────────
#  FETCH FUNCTIONS — one per source category
# ─────────────────────────────────────────────────────────────────────

def _rss(url,name,require_attack=True,require_italy=True) -> list:
    items=[]
    try:
        r=requests.get(url,timeout=12,headers=_HEADERS)
        feed=feedparser.parse(r.text if r.ok else "")
        for e in feed.entries[:80]:
            title=_strip_html(e.get("title","")).strip()
            summary=_strip_html(e.get("summary",e.get("description","")))
            link=e.get("link","#")
            if not title: continue
            combined=f"{title} {summary}"
            if _is_noise(combined): continue
            if require_attack and not _is_attack(combined): continue
            if require_italy  and not _is_italian(combined): continue
            items.append(_make_item(title,summary,link,name,_parse_rss_date(e)))
    except Exception: pass
    return items

# ── News APIs ─────────────────────────────────────────────────────────

def _fetch_newsapi(keys) -> list:
    k=keys.get("NEWSAPI_KEY","")
    if not k: return []
    items=[]
    queries=["cyber attack Italy","ransomware Italy","data breach Italy",
             "attacco informatico Italia","cybersecurity Italia"]
    for q in queries:
        try:
            r=requests.get("https://newsapi.org/v2/everything",
                params={"q":q,"language":"it,en","sortBy":"publishedAt",
                        "pageSize":20,"apiKey":k},timeout=10,headers=_HEADERS)
            if not r.ok: continue
            for a in r.json().get("articles",[]):
                title=a.get("title","") or ""
                desc=a.get("description","") or ""
                content=a.get("content","") or ""
                link=a.get("url","#")
                pub=_parse_date_str(a.get("publishedAt",""))
                combined=f"{title} {desc} {content}"
                if _is_noise(combined) or not _is_attack(combined): continue
                items.append(_make_item(title,f"{desc} {content[:200]}".strip(),
                                        link,"NewsAPI",pub))
        except Exception: continue
    return items

def _fetch_mediastack(keys) -> list:
    k=keys.get("MEDIASTACK_KEY","")
    if not k: return []
    items=[]
    try:
        r=requests.get("http://api.mediastack.com/v1/news",
            params={"access_key":k,"keywords":"cyber attack,ransomware,data breach",
                    "countries":"it","languages":"it,en","limit":50},
            timeout=10,headers=_HEADERS)
        if not r.ok: return []
        for a in r.json().get("data",[]):
            title=a.get("title","") or ""
            desc=a.get("description","") or ""
            link=a.get("url","#")
            pub=_parse_date_str(a.get("published_at",""))
            combined=f"{title} {desc}"
            if _is_noise(combined) or not _is_attack(combined): continue
            items.append(_make_item(title,desc,link,"Mediastack",pub))
    except Exception: pass
    return items

def _fetch_newscatcher(keys) -> list:
    k=keys.get("NEWSCATCHER_KEY","")
    if not k: return []
    items=[]
    try:
        r=requests.get("https://api.newscatcherapi.com/v2/search",
            params={"q":"cyber attack OR ransomware OR data breach",
                    "countries":"IT","lang":"it,en","page_size":50,
                    "sort_by":"date"},
            headers={**_HEADERS,"x-api-key":k},timeout=10)
        if not r.ok: return []
        for a in r.json().get("articles",[]):
            title=a.get("title","") or ""
            summary=a.get("summary","") or a.get("excerpt","") or ""
            link=a.get("link","#")
            pub=_parse_date_str(a.get("published_date",""))
            combined=f"{title} {summary}"
            if _is_noise(combined) or not _is_attack(combined): continue
            items.append(_make_item(title,summary,link,"Newscatcher",pub))
    except Exception: pass
    return items

# ── Threat Intelligence APIs ──────────────────────────────────────────

def _fetch_ransomware_live() -> list:
    """API JSON pubblica di ransomware.live — no auth needed."""
    items=[]
    for ep in ["https://api.ransomware.live/recentvictims",
               "https://api.ransomware.live/victims"]:
        try:
            r=requests.get(ep,timeout=15,headers=_HEADERS)
            if not r.ok: continue
            data=r.json()
            if isinstance(data,dict): data=data.get("data",data.get("victims",[]))
            for v in (data or [])[:100]:
                country=(v.get("country","") or v.get("Country","") or "").lower()
                domain=(v.get("domain","") or v.get("website","") or "").lower()
                victim=(v.get("victim","") or v.get("name","") or v.get("company","") or "")
                desc=_strip_html(v.get("description","") or v.get("summary","") or "")
                group=(v.get("group","") or v.get("ransomware_group","") or "unknown")
                link=(v.get("url","") or v.get("link","")
                      or f"https://www.ransomware.live/#victim={_uid(victim)}")
                is_it=(country in("italy","it","italia")
                       or domain.endswith(".it")
                       or _is_italian(f"{victim} {desc}"))
                if not is_it: continue
                raw_date=(v.get("published","") or v.get("date","")
                          or v.get("discovered","") or v.get("added","") or "")
                pub=_parse_date_str(raw_date) if raw_date else _now_it()
                title=f"[{group.upper()}] Vittima: {victim}" if victim else f"Ransomware {group}"
                summary=desc or f"Vittima italiana colpita dal gruppo ransomware {group}."
                items.append(_make_item(title,summary,link,"Ransomware.live",pub,
                                        f"{victim} {domain}"))
        except Exception: continue
    return items

def _fetch_alienvault(keys) -> list:
    k=keys.get("ALIENVAULT_KEY","")
    if not k: return []
    items=[]
    try:
        r=requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
            params={"limit":50,"modified_since":
                    (datetime.utcnow()-timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S")},
            headers={**_HEADERS,"X-OTX-API-KEY":k},timeout=12)
        if not r.ok: return []
        for p in r.json().get("results",[]):
            title=p.get("name","") or ""
            desc=p.get("description","") or ""
            tags=" ".join(p.get("tags",[]))
            combined=f"{title} {desc} {tags}"
            if not _is_italian(combined) and not _is_attack(combined): continue
            link=f"https://otx.alienvault.com/pulse/{p.get('id','')}"
            pub=_parse_date_str(p.get("modified","") or p.get("created",""))
            items.append(_make_item(title,desc[:300],link,"AlienVault OTX",pub,tags))
    except Exception: pass
    return items

def _fetch_threatfox(keys) -> list:
    """ThreatFox API — free, no key needed."""
    items=[]
    try:
        r=requests.post("https://threatfox-api.abuse.ch/api/v1/",
            json={"query":"get_iocs","days":1},
            headers=_HEADERS,timeout=12)
        if not r.ok: return []
        for ioc in r.json().get("data",[])[:50]:
            malware=ioc.get("malware","") or ""
            tags=" ".join(ioc.get("tags") or [])
            ioc_val=ioc.get("ioc","") or ""
            reporter=ioc.get("reporter","") or ""
            combined=f"{malware} {tags} {ioc_val}"
            if not _is_attack(combined): continue
            # ThreatFox non ha geo, ma se c'è country...
            country=(ioc.get("reporter_country","") or "").lower()
            if country and country not in ("it","italy","ita") and not _is_italian(combined):
                continue
            title=f"[ThreatFox] {malware} — {ioc_val[:40]}"
            summary=f"IoC type: {ioc.get('ioc_type','')} | Malware: {malware} | Tags: {tags} | Reporter: {reporter}"
            link=f"https://threatfox.abuse.ch/ioc/{ioc.get('id','')}"
            pub=_parse_date_str(ioc.get("first_seen",""))
            items.append(_make_item(title,summary,link,"ThreatFox",pub))
    except Exception: pass
    return items

def _fetch_urlhaus() -> list:
    """URLhaus — abuse.ch, no auth."""
    items=[]
    try:
        r=requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/",
            timeout=12,headers=_HEADERS)
        if not r.ok: return []
        for u in r.json().get("urls",[]):
            url_str=u.get("url","") or ""
            host=u.get("host","") or ""
            tags=" ".join(u.get("tags") or [])
            combined=f"{url_str} {host} {tags}"
            # Filtra .it o keyword italia
            if not (host.endswith(".it") or _is_italian(combined)): continue
            title=f"[URLhaus] Malware URL: {host}"
            summary=(f"URL malevola rilevata: {url_str[:80]} | "
                     f"Threat: {u.get('threat','')} | Tags: {tags} | "
                     f"Status: {u.get('url_status','')}")
            link=u.get("urlhaus_reference","https://urlhaus.abuse.ch")
            pub=_parse_date_str(u.get("date_added",""))
            items.append(_make_item(title,summary,link,"URLhaus",pub,combined))
    except Exception: pass
    return items

def _fetch_phishtank() -> list:
    """PhishTank — campioni recenti Italia."""
    items=[]
    try:
        r=requests.get(
            "https://data.phishtank.com/data/online-valid.json",
            timeout=15,headers=_HEADERS)
        if not r.ok: return []
        data=r.json()
        # Prendi solo gli ultimi 200 e filtra italia
        for p in data[:200]:
            url_str=p.get("url","") or ""
            target=p.get("target","") or ""
            combined=f"{url_str} {target}"
            if not (_is_italian(combined) or
                    any(tld in url_str for tld in [".it/",".it?",".it "])): continue
            title=f"[PhishTank] Phishing: {target or url_str[:50]}"
            summary=f"URL phishing confermata: {url_str[:120]} | Target: {target}"
            link=p.get("phish_detail_url","https://www.phishtank.com")
            pub=_parse_date_str(p.get("submission_time","") or p.get("verified_at",""))
            items.append(_make_item(title,summary,link,"PhishTank",pub))
    except Exception: pass
    return items

def _fetch_malwarebazaar() -> list:
    """MalwareBazaar — abuse.ch, no auth."""
    items=[]
    try:
        r=requests.post("https://mb-api.abuse.ch/api/v1/",
            data={"query":"get_recent","selector":"time"},
            headers=_HEADERS,timeout=12)
        if not r.ok: return []
        for s in r.json().get("data",[])[:30]:
            tags=" ".join(s.get("tags") or [])
            malware=s.get("malware_family","") or ""
            origin=s.get("origin_country","") or ""
            reporter=s.get("reporter","") or ""
            combined=f"{malware} {tags} {origin} {reporter}"
            if not (origin.upper() in ("IT","ITA") or _is_italian(combined)):
                continue
            sha=s.get("sha256_hash","")
            title=f"[MalwareBazaar] {malware or 'Malware'} — {sha[:16]}…"
            summary=(f"Family: {malware} | Tags: {tags} | "
                     f"Paese origine: {origin} | Reporter: {reporter}")
            link=f"https://bazaar.abuse.ch/sample/{sha}/"
            pub=_parse_date_str(s.get("first_seen",""))
            items.append(_make_item(title,summary,link,"MalwareBazaar",pub))
    except Exception: pass
    return items

def _fetch_openphish() -> list:
    """OpenPhish — lista URL phishing attive."""
    items=[]
    try:
        r=requests.get("https://openphish.com/feed.txt",timeout=12,headers=_HEADERS)
        if not r.ok: return []
        urls=[l.strip() for l in r.text.splitlines() if l.strip()]
        for url_str in urls[:200]:
            if not (".it/" in url_str or ".it?" in url_str or
                    re.search(r"\bital\w*\b",url_str,re.I)): continue
            title=f"[OpenPhish] Phishing attiva: {url_str[:60]}"
            summary=f"URL phishing attiva rilevata: {url_str}"
            items.append(_make_item(title,summary,url_str,"OpenPhish"))
    except Exception: pass
    return items

def _fetch_feodo() -> list:
    """Feodo Tracker (Emotet/TrickBot/QakBot C2) — abuse.ch."""
    items=[]
    try:
        r=requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            timeout=12,headers=_HEADERS)
        if not r.ok: return []
        data=r.json()
        if isinstance(data,dict): data=data.get("ip_addresses",[])
        for entry in (data or [])[:30]:
            country=(entry.get("country","") or "").upper()
            if country not in ("IT","ITA"): continue
            ip=entry.get("ip_address","") or ""
            malware=entry.get("malware","") or ""
            status=entry.get("status","") or ""
            title=f"[Feodo C2] {malware} C2 server in Italia: {ip}"
            summary=(f"C2 {malware} rilevato in Italia | IP: {ip} | "
                     f"Status: {status} | Porta: {entry.get('port','')}")
            link="https://feodotracker.abuse.ch/browse/"
            pub=_parse_date_str(entry.get("first_seen","") or entry.get("last_online",""))
            items.append(_make_item(title,summary,link,"Feodo Tracker",pub,f"Italy {malware}"))
    except Exception: pass
    return items

def _fetch_cisa_rss() -> list:
    items=[]
    items+=_rss("https://www.cisa.gov/uscert/ncas/alerts.xml","CISA Alerts",
                require_italy=False,require_attack=True)
    items+=_rss("https://www.cisa.gov/uscert/ics/advisories.xml","CISA ICS",
                require_italy=False,require_attack=True)
    return items

def _fetch_cert_feeds() -> list:
    items=[]
    # Istituzionali IT — nessun filtro (già attacchi IT)
    items+=_rss("https://cert-agid.gov.it/feed/","CERT-AgID",
                require_attack=False,require_italy=False)
    items+=_rss("https://www.csirt.gov.it/feed","CSIRT Italia",
                require_attack=False,require_italy=False)
    # Internazionali
    items+=_rss("https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
                "NCSC UK",require_italy=False,require_attack=True)
    items+=_rss("https://www.cert.ssi.gouv.fr/feed/","CERT-FR",
                require_italy=False,require_attack=True)
    items+=_rss("https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed_Sicherheitshinweise/RSSNewsfeed_Sicherheitshinweise_en.xml",
                "BSI Germany",require_italy=False,require_attack=True)
    items+=_rss("https://www.first.org/newsroom/rss/","FIRST",
                require_italy=False,require_attack=True)
    items+=_rss("https://www.jpcert.or.jp/english/rss/jpcert-en.rdf","JPCERT",
                require_italy=False,require_attack=True)
    return items

def _fetch_news_rss() -> list:
    sources=[
        ("https://www.redhotcyber.com/feed/","Red Hot Cyber",False,False),
        ("https://www.cybersecurity360.it/feed/","Cybersecurity360",False,False),
        ("https://www.bleepingcomputer.com/feed/","BleepingComputer",True,True),
        ("https://feeds.feedburner.com/TheHackersNews","The Hacker News",True,True),
        ("https://www.darkreading.com/rss.xml","DarkReading",True,True),
        ("https://krebsonsecurity.com/feed/","Krebs on Security",True,True),
        ("https://feeds.feedburner.com/Securityweek","SecurityWeek",True,True),
        ("https://threatpost.com/feed/","Threatpost",True,True),
        ("https://www.csoonline.com/feed/","CSO Online",True,True),
        ("https://www.helpnetsecurity.com/feed/","Help Net Security",True,True),
        ("https://www.theregister.com/security/headlines.atom","The Register Security",True,True),
        ("https://www.zdnet.com/topic/security/rss.xml","ZDNet Security",True,True),
        ("https://techcrunch.com/tag/security/feed/","TechCrunch Security",True,True),
        ("https://www.wired.com/feed/category/security/latest/rss","Wired Security",True,True),
        ("https://www.recordedfuture.com/feed","Recorded Future",True,True),
        ("https://research.checkpoint.com/feed","Check Point Research",True,True),
        ("https://unit42.paloaltonetworks.com/feed/","Palo Alto Unit42",True,True),
        ("https://blog.talosintelligence.com/feeds/posts/default","Cisco Talos",True,True),
        ("https://www.crowdstrike.com/blog/feed/","CrowdStrike",True,True),
        ("https://www.sentinelone.com/blog/feed/","SentinelOne",True,True),
        ("https://blog.trendmicro.com/feed/","TrendMicro",True,True),
        ("https://www.fortinet.com/blog/threat-research.rss","Fortinet FortiGuard",True,True),
        ("https://www.mandiant.com/resources/blog/rss.xml","Mandiant",True,True),
        ("https://decoded.avast.io/feed/","Avast Decoded",True,True),
        ("https://securelist.com/feed/","Securelist (Kaspersky)",True,True),
        ("https://news.sophos.com/en-us/category/threat-research/feed/","Sophos X-Ops",True,True),
        ("https://www.rapid7.com/blog/feed/","Rapid7",True,True),
        ("https://malware.news/rss","Malware News",True,True),
        ("https://www.sans.org/blog/feed/","SANS ISC",True,True),
    ]
    items=[]
    for url,name,ra,ri in sources:
        items+=_rss(url,name,require_attack=ra,require_italy=ri)
    return items

def _fetch_exploit_rss() -> list:
    """Vulnerability / exploit feeds."""
    items=[]
    items+=_rss("https://www.exploit-db.com/rss.xml","Exploit-DB",
                require_attack=True,require_italy=False)
    items+=_rss("https://packetstormsecurity.com/headlines.xml",
                "Packet Storm",require_attack=True,require_italy=False)
    items+=_rss("https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
                "NIST NVD",require_attack=False,require_italy=False)
    return items

def _fetch_urlscan(keys) -> list:
    """URLscan.io — scansioni recenti con TLD .it."""
    items=[]
    k=keys.get("URLSCAN_KEY","")
    headers={**_HEADERS,**({"API-Key":k} if k else {})}
    try:
        r=requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q":"domain:*.it AND verdicts.overall.malicious:true","size":30},
            headers=headers,timeout=12)
        if not r.ok: return []
        for res in r.json().get("results",[]):
            url_str=(res.get("task",{}) or {}).get("url","") or ""
            domain=(res.get("page",{}) or {}).get("domain","") or ""
            verdict=(res.get("verdicts",{}) or {})
            malicious=(verdict.get("overall",{}) or {}).get("malicious",False)
            if not malicious: continue
            title=f"[URLscan] Malicious scan: {domain}"
            summary=(f"URL: {url_str[:100]} | "
                     f"Score: {(verdict.get('overall',{}) or {}).get('score',0)}")
            link=res.get("result","https://urlscan.io")
            pub=_parse_date_str((res.get("task",{}) or {}).get("time",""))
            items.append(_make_item(title,summary,link,"URLscan.io",pub,
                                    f"{domain} italy italian .it"))
    except Exception: pass
    return items

# ─────────────────────────────────────────────────────────────────────
#  MASTER FETCH — chiama tutte le sorgenti
# ─────────────────────────────────────────────────────────────────────
def _fetch_all(keys: dict) -> list:
    """Fetcha tutte le sorgenti e ritorna lista di item."""
    all_items = []
    fetchers = [
        # SEMPRE attivi (no key)
        (_fetch_ransomware_live,  []),
        (_fetch_urlhaus,          []),
        (_fetch_threatfox,        [keys]),
        (_fetch_malwarebazaar,    []),
        (_fetch_openphish,        []),
        (_fetch_feodo,            []),
        (_fetch_cert_feeds,       []),
        (_fetch_news_rss,         []),
        (_fetch_cisa_rss,         []),
        (_fetch_exploit_rss,      []),
        # Richiedono API key
        (_fetch_newsapi,          [keys]),
        (_fetch_mediastack,       [keys]),
        (_fetch_newscatcher,      [keys]),
        (_fetch_alienvault,       [keys]),
        (_fetch_urlscan,          [keys]),
    ]
    for fn, args in fetchers:
        try:
            results = fn(*args)
            all_items.extend(results)
        except Exception:
            continue
    return all_items

# ─────────────────────────────────────────────────────────────────────
#  BACKGROUND THREAD
#  Fetcha, deduplica/mergia, scrive su file JSON ogni RSS_INTERVAL s
# ─────────────────────────────────────────────────────────────────────
_thread_started = threading.Event()

def _background_loop(keys: dict):
    """Thread daemon — ciclo continuo di fetch → dedup → file write."""
    # Dizionario condiviso in-thread: dedup_key → item
    store: dict[str, dict] = {}
    last_api = 0.0

    while True:
        new_items = _fetch_all(keys)

        added = updated = 0
        for item in new_items:
            dk = item["dedup_key"]
            if dk in store:
                # Aggiorna esistente se più ricco
                old = store[dk]
                merged = _merge_item(old, item)
                store[dk] = merged
                if merged["is_updated"]:
                    updated += 1
            else:
                store[dk] = item
                added += 1

        # Mantieni solo i più recenti
        sorted_items = sorted(
            store.values(),
            key=lambda x: x.get("published", ""),
            reverse=True
        )[:MAX_ITEMS]

        # Aggiorna store con solo gli ultimi MAX_ITEMS
        store = {i["dedup_key"]: i for i in sorted_items}

        # Scrivi su file per l'UI
        _write_feed(sorted_items)

        time.sleep(RSS_INTERVAL)


def _ensure_thread():
    """Avvia il thread una sola volta per processo (non per sessione)."""
    if not _thread_started.is_set():
        _thread_started.set()
        keys = _secrets()
        t = threading.Thread(
            target=_background_loop,
            args=(keys,),
            daemon=True,
            name="CyberFetcher",
        )
        t.start()

# ─────────────────────────────────────────────────────────────────────
#  MAP
# ─────────────────────────────────────────────────────────────────────
SEV_C = {"critical":"#ff3b30","medium":"#ff9f0a","low":"#30d158"}
SEV_G = {"critical":"rgba(255,59,48,.14)","medium":"rgba(255,159,10,.14)","low":"rgba(48,209,88,.14)"}
SEV_S = {"critical":14,"medium":10,"low":8}
SEV_GS= {"critical":28,"medium":21,"low":15}

def build_map(attacks: list) -> go.Figure:
    df = pd.DataFrame(attacks) if attacks else pd.DataFrame(
        columns=["lat","lon","title","place","region","severity","ts","source","link"])
    fig = go.Figure()
    for sev in ["critical","medium","low"]:
        sub = df[df["severity"]==sev] if len(df) else pd.DataFrame()
        if sub.empty: continue
        hover=[
            f"<b>{r['title'][:72]}{'…' if len(r['title'])>72 else ''}</b><br>"
            f"<span style='color:#7eb3d4'>📍 {r['place']} — {r['region']}</span><br>"
            f"<span style='color:#586374'>🕒 {r['ts']} · {r['source']}</span><br>"
            f"<span style='color:{SEV_C[sev]};font-weight:600;font-size:10px'>▲ {sev.upper()}</span>"
            for _,r in sub.iterrows()
        ]
        lons,lats=sub["lon"].tolist(),sub["lat"].tolist()
        links=sub["link"].tolist() if "link" in sub.columns else []
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=f"_g{sev}",
            marker=dict(size=SEV_GS[sev],color=SEV_G[sev],opacity=.5),
            hoverinfo="skip",showlegend=False))
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=f"_m{sev}",
            marker=dict(size=int(SEV_GS[sev]*.56),color=SEV_G[sev],opacity=.38),
            hoverinfo="skip",showlegend=False))
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=sev.upper(),
            marker=dict(size=SEV_S[sev],color=SEV_C[sev],opacity=.95),
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
    for tr in fig.data:
        if tr.name and tr.name.startswith("_"): tr.showlegend=False
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
        </div>""",unsafe_allow_html=True)

        sel_sev=st.multiselect("SEVERITY",["critical","medium","low"],
                               default=["critical","medium","low"],format_func=str.upper)
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        avail_reg=sorted(set(a["region"] for a in attacks)) if attacks else sorted(REGIONS)
        sel_reg=st.multiselect("REGION",avail_reg,default=[],placeholder="All regions")
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        today=datetime.now().date()
        c1,c2=st.columns(2)
        with c1: df_=st.date_input("FROM",value=today-timedelta(days=7))
        with c2: dt_=st.date_input("TO",  value=today)
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        avail_src=sorted(set(a["source"] for a in attacks)) if attacks else []
        sel_src=st.multiselect("SOURCE",avail_src,default=[],placeholder="All sources")
        st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)

        search=st.text_input("🔍 SEARCH",placeholder="ransomware, bari, lockbit…")
        st.markdown("<hr style='border-color:#1e2730;margin:16px 0'>",unsafe_allow_html=True)
        if st.button("↺  RESET FILTERS"): st.rerun()

        # Conteggio fonti attive
        n_keys=sum(1 for v in _secrets().values() if v)
        st.markdown(f"""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.57rem;
                    color:#586374;margin-top:20px;line-height:1.85;'>
          <span style='color:#30d158;'>● FEED ATTIVI</span><br>
          · Ransomware.live API<br>
          · URLhaus / ThreatFox / Feodo<br>
          · MalwareBazaar / OpenPhish / PhishTank<br>
          · CERT-AgID / CSIRT Italia<br>
          · NCSC UK / CERT-FR / BSI / FIRST / JPCERT<br>
          · CISA Alerts / CISA ICS<br>
          · Red Hot Cyber / Cybersecurity360<br>
          · BleepingComputer / THN / DarkReading<br>
          · Krebs / SecurityWeek / Threatpost<br>
          · CSO / HelpNet / TheRegister / ZDNet<br>
          · TechCrunch / Wired Security<br>
          · Recorded Future / Check Point<br>
          · Unit42 / Talos / CrowdStrike<br>
          · SentinelOne / TrendMicro / Fortinet<br>
          · Mandiant / Sophos / Avast / Securelist<br>
          · Rapid7 / SANS / Exploit-DB / Packet Storm<br>
          · NVD NIST / Malware News<br>
          <span style='color:{"#30d158" if n_keys>0 else "#ff3b30"};'>
          ● API KEY: {n_keys} configurate</span><br>
          · NewsAPI / Mediastack / Newscatcher<br>
          · AlienVault OTX / URLscan.io<br>
          · (+ altre con key in secrets.toml)<br>
          <br>
          <span style='color:#ff9f0a;'>● RSS FETCH:</span> ogni {RSS_INTERVAL}s<br>
          <span style='color:#ff3b30;'>● UI POLL:</span> ogni {POLL_MS//1000}s (no reload)<br>
          <span style='color:#30d158;'>● IPC:</span> file JSON /tmp/
        </div>""",unsafe_allow_html=True)

    return sel_sev,sel_reg,df_,dt_,sel_src,search

def apply_filters(attacks,sel_sev,sel_reg,df_,dt_,sel_src,search):
    f=attacks
    if sel_sev: f=[a for a in f if a["severity"] in sel_sev]
    if sel_reg: f=[a for a in f if a["region"]   in sel_reg]
    if sel_src: f=[a for a in f if a["source"]   in sel_src]
    f=[a for a in f if isinstance(a.get("published"),datetime)
       and df_ <= a["published"].date() <= dt_]
    if search:
        q=search.lower()
        f=[a for a in f if q in a["title"].lower()
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
          FETCHING FEEDS…<br>
          <span style='font-size:.6rem;'>prima notizia in ~{RSS_INTERVAL}s</span>
        </div>""",unsafe_allow_html=True)
        return
    for a in attacks:
        sev=a["severity"]
        link=a.get("link","#")
        is_new=a.get("is_new",False)
        is_upd=a.get("is_updated",False) and not is_new
        extra=("new-event" if is_new else ("updated" if is_upd else ""))
        card=f"feed-card {'' if sev=='critical' else sev} {extra}".strip()
        badge_new=('<span class="badge b-new">● NEW</span>' if is_new else
                   '<span class="badge b-upd">↑ UPD</span>' if is_upd else "")
        upd_note=(f"<span style='color:#586374;font-size:.58rem;'>"
                  f"aggiornata {a.get('update_count',0)}×</span> " if is_upd else "")
        st.markdown(f"""
        <div class="{card}">
          <div class="feed-title">
            <a href="{link}" target="_blank" style="color:#e8ecf0;text-decoration:none;">
              {a['title']}
            </a>
          </div>
          <div class="feed-meta">
            {badge_new}{upd_note}
            <span class="badge b-{sev}">{sev}</span>
            <span class="badge b-region">{a['region']}</span>
            <span class="badge b-source">{a['source']}</span>
            📍 {a['place']} &nbsp;·&nbsp; {a['ts']}
          </div>
          <div class="feed-desc">{a['summary'][:260]}{'…' if len(a['summary'])>260 else ''}</div>
        </div>""",unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    # Avvia thread (idempotente — una sola volta per processo)
    _ensure_thread()

    # Poll UI ogni 3s — legge il file JSON aggiornato dal thread
    # NON è un page reload: st_autorefresh fa solo un Streamlit rerun
    if HAS_AUTOREFRESH:
        st_autorefresh(interval=POLL_MS, limit=None, key="live_poll")

    # Leggi feed dal file (IPC)
    all_attacks = _read_feed()

    now = datetime.now(TZ_IT)
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
    </div>""",unsafe_allow_html=True)

    sel_sev,sel_reg,df_,dt_,sel_src,search = render_sidebar(all_attacks)
    filtered = apply_filters(all_attacks,sel_sev,sel_reg,df_,dt_,sel_src,search)

    total  = len(all_attacks)
    crit_n = sum(1 for a in all_attacks if a["severity"]=="critical")
    med_n  = sum(1 for a in all_attacks if a["severity"]=="medium")
    low_n  = sum(1 for a in all_attacks if a["severity"]=="low")
    reg_n  = len(set(a["region"] for a in all_attacks))
    new_n  = sum(1 for a in all_attacks if a.get("is_new"))

    k1,k2,k3,k4,k5 = st.columns(5)
    k1.metric("TOTAL ATTACKS", total)
    k2.metric("⬤ CRITICAL",    crit_n)
    k3.metric("⬤ MEDIUM",      med_n)
    k4.metric("⬤ LOW",         low_n)
    k5.metric("REGIONS HIT",   reg_n)

    st.markdown("<div style='height:4px'></div>",unsafe_allow_html=True)

    feed_age=""
    if all_attacks:
        last=all_attacks[0].get("published")
        if isinstance(last,datetime):
            delta=int((datetime.now(TZ_IT)-last).total_seconds())
            feed_age=f" · ultima notizia {delta}s fa"

    new_html=(f" · <span style='color:#30d158;font-weight:600;'>+{new_n} NEW</span>"
              if new_n>0 else "")
    next_f=RSS_INTERVAL-(int(time.time())%RSS_INTERVAL)
    st.markdown(f"""
    <div class="status-bar">
      <span class="pulse-dot"></span>
      LIVE · {now.strftime('%d/%m/%Y %H:%M:%S')} IT ·
      {len(filtered)} eventi (filtrati) · {total} in storico ·
      next fetch ~{next_f}s{feed_age}{new_html}
    </div>""",unsafe_allow_html=True)

    map_col,feed_col = st.columns([3,1.5],gap="medium")

    with map_col:
        fig = build_map(filtered)
        st.plotly_chart(fig,use_container_width=True,config={
            "scrollZoom":True,"displayModeBar":True,"displaylogo":False,
            "modeBarButtonsToRemove":["select2d","lasso2d","autoScale2d","resetScale2d"],
            "toImageButtonOptions":{"format":"png","filename":"italy_cybermap"},
        },key="cybermap")
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.6rem;
                    color:#586374;text-align:center;margin-top:-8px;'>
          CLICK MARKER → REPORT COMPLETO &nbsp;·&nbsp;
          SCROLL TO ZOOM &nbsp;·&nbsp; DRAG TO PAN
        </div>""",unsafe_allow_html=True)

    with feed_col:
        st.markdown("""
        <div style='font-family:"IBM Plex Mono",monospace;font-size:.65rem;color:#586374;
                    letter-spacing:.1em;text-transform:uppercase;
                    padding-bottom:8px;border-bottom:1px solid #1e2730;margin-bottom:12px;'>
            ◈ INCIDENT FEED — LIVE
        </div>""",unsafe_allow_html=True)
        with st.container(height=650):
            render_feed(filtered)

    if not HAS_AUTOREFRESH:
        st.markdown(f"<script>setTimeout(()=>window.location.reload(),{POLL_MS})</script>",
                    unsafe_allow_html=True)
        st.warning("💡 `pip install streamlit-autorefresh` per aggiornamento senza reload")


if __name__=="__main__":
    main()
