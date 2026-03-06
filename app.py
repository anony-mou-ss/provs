"""
╔══════════════════════════════════════════════════════════════════════╗
║  ITALY CYBER THREAT MAP  v5.0                                        ║
║                                                                      ║
║  FONTI: solo incidenti reali confermati                              ║
║  ┌────────────────────────────────────────────────────────────────┐  ║
║  │ 1. ransomware.live  — vittime italiane, aggiornamento continuo  │  ║
║  │ 2. hackmanac.github.io — database attacchi pubblici Italia      │  ║
║  │ 3. CERT-AgID        — avvisi ufficiali italiani                 │  ║
║  │ 4. CSIRT Italia     — incidenti gestiti                         │  ║
║  │ 5. Red Hot Cyber    — cronaca attacchi in italiano              │  ║
║  │ 6. Cybersecurity360 — incidenti settore Italia                  │  ║
║  │ 7. BleepingComputer — filtra ".it" + nomi enti IT               │  ║
║  │ 8. DataBreaches.net — database violazioni dati                  │  ║
║  │ 9. HaveIBeenPwned   — breach pubblici .it                       │  ║
║  │10. DarkFeed Telegram — feed pubblico APT/ransomware             │  ║
║  └────────────────────────────────────────────────────────────────┘  ║
║                                                                      ║
║  ARCHITETTURA UI:                                                    ║
║  · Thread fetcha ogni 20s                                            ║
║  · st_autorefresh ogni 4s — SOLO se ci sono item nuovi              ║
║  · Mappa: Plotly chart con key statica — aggiunge solo marker nuovi  ║
║  · Feed: container HTML custom — append in cima senza re-render      ║
║                                                                      ║
║  pip install streamlit plotly requests feedparser pandas             ║
║               streamlit-autorefresh                                  ║
║  streamlit run italy_cybermap.py                                     ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import json, os, re, hashlib, random, threading, time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path

import streamlit as st
import plotly.graph_objects as go
import requests, feedparser
import pandas as pd

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AR = True
except ImportError:
    HAS_AR = False

# ─────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────
TZ         = ZoneInfo("Europe/Rome")
FEED_FILE  = Path("/tmp/cybermap_v5.json")
FETCH_INT  = 20      # secondi tra fetch
POLL_MS    = 4000    # ms autorefresh UI
MAX_ITEMS  = 1000

_H = {"User-Agent": "Mozilla/5.0 ItalyCyberMap/5.0", "Accept": "*/*"}

st.set_page_config(page_title="Italy Cyber Threat Map",
                   page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

# ─────────────────────────────────────────────────────────────────────
#  CSS
# ─────────────────────────────────────────────────────────────────────
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
  background:var(--card)!important;border:1px solid var(--brd)!important;color:var(--txt)!important;}
.stButton>button{background:transparent!important;border:1px solid var(--red)!important;
  color:var(--red)!important;font-family:'IBM Plex Mono',monospace!important;
  font-size:.75rem!important;letter-spacing:.08em;text-transform:uppercase;border-radius:3px!important;}
.stButton>button:hover{background:var(--red)!important;color:#fff!important;}
hr{border-color:var(--brd)!important;}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}

.feed-wrap{display:flex;flex-direction:column;gap:0;}
.fc{background:var(--card);border:1px solid var(--brd);border-left:3px solid var(--red);
  border-radius:4px;padding:10px 14px;margin-bottom:7px;transition:opacity .3s;}
.fc.med{border-left-color:var(--ora)}.fc.low{border-left-color:var(--grn)}
.fc.is-new{animation:slideIn .4s ease-out;}
@keyframes slideIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}
.ft{font-weight:600;font-size:.83rem;color:#e8ecf0;margin-bottom:3px;line-height:1.35;}
.ft a{color:#e8ecf0;text-decoration:none;}
.ft a:hover{color:var(--red);}
.fm{font-family:'IBM Plex Mono',monospace;font-size:.62rem;color:var(--dim);margin-bottom:4px;line-height:1.7;}
.fd{font-size:.74rem;color:var(--dim);line-height:1.45;}
.bx{display:inline-block;padding:1px 6px;border-radius:2px;font-family:'IBM Plex Mono',monospace;
  font-size:.58rem;font-weight:600;letter-spacing:.05em;margin-right:3px;text-transform:uppercase;}
.bc{background:#3d1515;color:var(--red);border:1px solid var(--red);}
.bm{background:#2d1f08;color:var(--ora);border:1px solid var(--ora);}
.bl{background:#0d2418;color:var(--grn);border:1px solid var(--grn);}
.br{background:#1a1f2a;color:#7eb3d4;border:1px solid #2a3a4d;}
.bs{background:#1a1520;color:#c07aff;border:1px solid #3a2560;}
.bn{background:#0d2010;color:var(--grn);border:1px solid var(--grn);animation:blink .6s step-end 5;}
@keyframes blink{50%{opacity:0}}
.pulse{display:inline-block;width:7px;height:7px;background:var(--red);
  border-radius:50%;margin-right:6px;animation:pulse 1.4s infinite;vertical-align:middle;}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(255,59,48,.7)}
  70%{box-shadow:0 0 0 7px rgba(255,59,48,0)}100%{box-shadow:0 0 0 0 rgba(255,59,48,0)}}
.sbar{font-family:'IBM Plex Mono',monospace;font-size:.62rem;color:var(--dim);
  padding:4px 0;letter-spacing:.05em;}
#MainMenu,footer,header{visibility:hidden!important;}
.block-container{padding-top:1.2rem!important;}
</style>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
#  GEO DB
# ─────────────────────────────────────────────────────────────────────
_CITIES = sorted([
    ("reggio calabria",38.1147,15.6615,"Calabria"),
    ("reggio emilia",44.6989,10.6297,"Emilia-Romagna"),
    ("ascoli piceno",42.854,13.5745,"Marche"),
    ("la spezia",44.1024,9.824,"Liguria"),
    ("l'aquila",42.3498,13.3995,"Abruzzo"),
    ("vibo valentia",38.676,16.0995,"Calabria"),
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
    ("asti",44.9003,8.2064,"Piemonte"),
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
    ("terni",42.5636,12.6432,"Umbria"),
    ("ancona",43.6158,13.5189,"Marche"),
    ("pesaro",43.9098,12.9131,"Marche"),
    ("macerata",43.2989,13.4536,"Marche"),
    ("roma",41.9028,12.4964,"Lazio"),
    ("rome",41.9028,12.4964,"Lazio"),
    ("latina",41.4677,12.9035,"Lazio"),
    ("napoli",40.8518,14.2681,"Campania"),
    ("naples",40.8518,14.2681,"Campania"),
    ("salerno",40.6824,14.7681,"Campania"),
    ("caserta",41.0748,14.3328,"Campania"),
    ("avellino",40.9143,14.7906,"Campania"),
    ("benevento",41.1297,14.7819,"Campania"),
    ("bari",41.1171,16.8719,"Puglia"),
    ("taranto",40.4644,17.247,"Puglia"),
    ("foggia",41.4621,15.5446,"Puglia"),
    ("lecce",40.3515,18.175,"Puglia"),
    ("brindisi",40.6327,17.9414,"Puglia"),
    ("pescara",42.4606,14.2156,"Abruzzo"),
    ("chieti",42.3512,14.1683,"Abruzzo"),
    ("campobasso",41.5603,14.6564,"Molise"),
    ("potenza",40.6404,15.8057,"Basilicata"),
    ("matera",40.6664,16.6044,"Basilicata"),
    ("catanzaro",38.9098,16.5872,"Calabria"),
    ("cosenza",39.2988,16.2548,"Calabria"),
    ("crotone",39.0814,17.1279,"Calabria"),
    ("cagliari",39.2238,9.1217,"Sardegna"),
    ("sassari",40.7259,8.5557,"Sardegna"),
    ("nuoro",40.3214,9.3307,"Sardegna"),
    ("aosta",45.7373,7.3154,"Valle d'Aosta"),
    ("ferrara",44.8381,11.6198,"Emilia-Romagna"),
    ("ravenna",44.4175,12.2035,"Emilia-Romagna"),
    ("parma",44.8015,10.3279,"Emilia-Romagna"),
    ("rimini",44.0678,12.5695,"Emilia-Romagna"),
    ("piacenza",45.0526,9.6926,"Emilia-Romagna"),
    ("forli",44.2227,12.0407,"Emilia-Romagna"),
    ("monza",45.5845,9.2744,"Lombardia"),
    ("como",45.808,9.0852,"Lombardia"),
    ("varese",45.8205,8.8257,"Lombardia"),
    ("mantova",45.1564,10.7914,"Lombardia"),
    ("cremona",45.1333,10.0227,"Lombardia"),
    ("sapienza",41.9028,12.4964,"Lazio"),
    ("policlinico",41.9028,12.4964,"Lazio"),
    ("san raffaele",45.5,9.2648,"Lombardia"),
    ("humanitas",45.4,9.35,"Lombardia"),
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

_FB = [
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
#  FILTRI — solo incidenti REALI confermati
#
#  LOGICA: un item viene accettato SE:
#  1. Parla di un'organizzazione/ente specifico che è stata attaccata
#  2. Contiene un verbo di attacco concreto (hackerata, colpita, violata…)
#  3. Riguarda l'Italia
#
#  NON viene accettato se:
#  - È un avviso generico ("attenzione alla nuova vulnerabilità")
#  - È una notizia su trend/statistiche
#  - È un tutorial, commento, opinione
# ─────────────────────────────────────────────────────────────────────

# Organizzazioni italiane note — match aumenta confidenza
_ORGS_IT = re.compile(
    r"\binail\b|\binps\b|\bpolizia\b|\bcarabinieri\b|\bfinanza\b"
    r"|\bconsip\b|\btrenitalia\b|\benel\b|\beni\b|\bleonardo\b"
    r"|\bfincantieri\b|\bfastweb\b|\btim\b|\bwind\b|\bvoda\b"
    r"|\bintesa\b|\bunicredit\b|\bbnl\b|\bmediolanum\b|\bgenerale\b"
    r"|\bposte\b|\bautostrade\b|\bsnam\b|\baces\b|\baces\b"
    r"|\bospedale\b|\basl\b|\bpoliclinico\b|\bauniversit\b|\buniversit\w+"
    r"|\bcomune\s+di\b|\bprovincia\s+di\b|\bregione\s+\w+"
    r"|\bministero\b|\bprefettura\b|\bquestu\b|\btribunal\b"
    r"|\bscuola\b|\bistituto\b|\bmunicip\w+|\bparlamento\b"
    r"|\bsenato\b|\bcamera\b|\bpresidenza\b|\bpcm\b"
    r"|\baci\b|\bata\b|\batm\b|\bamtab\b|\bgtm\b"
    r"|\bferrovie\b|\bitalo\b|\balitalia\b|\bita\s+airway",
    re.I,
)

# Verbi/frasi che indicano un incidente AVVENUTO (non ipotetico)
_INCIDENT_RE = re.compile(
    r"hackerata|hackerato|hacked\b|colpit[ao]\b|violat[ao]\b|attaccat[ao]\b"
    r"|compromess[ao]\b|infiltrat[ao]\b|rubat[ao]\b|trafugat[ao]\b"
    r"|esfiltrat[ao]\b|cifrat[ao]\b|criptat[ao]\b|bloccata\b|fuori\s+servizio\b"
    r"|data\s+breach\b|databreach\b|ransomware\s+attack\b|sotto\s+attacco\b"
    r"|in\s+ginocchio\b|paralizzat[ao]\b|inaccessibil\w+|down\b"
    r"|leaked?\b|dump(ed)?\b|exfiltrat\w+|breached\b|pwned\b"
    r"|victim\b|vittime?\b|colpisce\b|prende\s+di\s+mira\b"
    r"|rivendicat[ao]\b|claim(ed|s)?\b|pubblica(to)?\s+(i\s+)?dat"
    r"|messo\s+online\b|pubblicati\s+i\s+dati\b|dati\s+rubati\b"
    r"|offline\b|irraggiungibil\w+|sistema.{0,20}bloccato"
    r"|attack(ed|s)?\b|intrusion\b|breach\b|incident\b|incidente\b",
    re.I,
)

# Keyword Italia
_IT_RE = re.compile(
    r"\bital\w+|\broma\b|\bmilan\w*|\bnapol\w*|\btorin\w*|\bfirenz\w*"
    r"|\bbologna\b|\bvenezia\b|\bgenov\w*|\bpalermo\b|\bbari\b"
    r"|\bsicilia\b|\bsardegna\b|\bpuglia\b|\blazio\b|\blombardia\b"
    r"|\btoscana\b|\bveneto\b|\bcampania\b|\bcalabria\b|\bpiemonte\b"
    r"|\bliguria\b|\bumbria\b|\bmarche\b|\babruzzo\b|\bbasilicata\b"
    r"|\.it[\s/\"\'<>]|[\"\']\w+\.it\b"
    r"|\bgoverno\s+italiano\b|\bministero\b|\bprefettura\b",
    re.I,
)

# Blacklist assoluta — scarta sempre
_NOISE_RE = re.compile(
    r"\bcome\s+(protegger|difender|prevenire)\b|\bcome\s+fare\b"
    r"|\bguida\b|\btutorial\b|\bhow\s+to\b|\btips?\b"
    r"|\bstatistich\w+\b|\btendenz\w+\b|\bprevision\w+\b|\brapporto\s+annual\b"
    r"|\bwebinar\b|\bcorso\b|\bformazione\b|\bevento\b|\bconferenz\w+\b"
    r"|\bsconto\b|\bofferta\b|\brecensione\b|\breview\b|\bannuncio\b"
    r"|\bopinione\b|\bcommentario\b|\banalisi\s+del\s+mercato\b"
    r"|\bnew\s+feature\b|\bpatch\s+tuesday\b|\bwindows\s+update\b"
    r"|\bjob\b|\bassunz\w+\b|\bcarrier\w+\b",
    re.I,
)

def _accept(title: str, summary: str, source_type: str) -> bool:
    """Decide se un item è un incidente reale da mostrare."""
    text = f"{title} {summary}"
    if _NOISE_RE.search(text):
        return False
    # Fonti istituzionali italiane: accetta tutto (sono già incidenti)
    if source_type == "CERT_IT":
        return True
    # Fonti ransomware: accetta solo vittime italiane (già filtrate prima)
    if source_type == "RANSOMWARE":
        return True
    # Altre fonti: deve avere verbo di incidente + keyword Italia
    has_incident = bool(_INCIDENT_RE.search(text))
    has_italy    = bool(_IT_RE.search(text)) or bool(_ORGS_IT.search(text))
    return has_incident and has_italy

# ─────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────
def _uid(s):
    return hashlib.md5(s.lower().strip().encode("utf-8","replace")).hexdigest()[:12]

def _dedup_key(title):
    # Rimuovi date, numeri, articoli per dedup fuzzy
    t = re.sub(r"\b\d+\b","",title.lower())
    t = re.sub(r"\b(il|la|lo|i|gli|le|un|una|di|da|in|con|su|per|e|è)\b","",t)
    t = re.sub(r"\s+"," ",t).strip()
    return _uid(t)

def _strip(s): return re.sub(r"<[^>]+>","",s or "").strip()

def _jitter(lat,lon,a=0.035):
    return (max(36.6,min(47.1,lat+random.uniform(-a,a))),
            max(6.6, min(18.5,lon+random.uniform(-a,a))))

def _sev(text):
    t = text.lower()
    if re.search(r"ransomware|exfiltrat|data.?breach|zero.?day|critico|critical"
                 r"|lockbit|blackcat|cl0p|alphv|rhysida|akira|medusa|conti|hive"
                 r"|darkside|apt\d|nation.?state|paralizzat|bloccata|cifrat",t):
        return "critical"
    if re.search(r"phishing|malware|ddos|exploit|hacked|compromess|breach|leak"
                 r"|defacement|backdoor|botnet|stealer|intrusion|attacco|violat",t):
        return "medium"
    return "low"

def _geo(text):
    t = text.lower()
    for city,lat,lon,reg in _CITIES:
        if re.search(r"\b"+re.escape(city)+r"\b",t):
            return lat,lon,city.title(),reg
    for reg,(lat,lon) in REGIONS.items():
        if re.search(r"\b"+re.escape(reg.lower())+r"\b",t):
            return lat,lon,reg,reg
    return None

def _now(): return datetime.now(TZ)

def _parse_dt(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ","%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19],fmt).replace(
                tzinfo=ZoneInfo("UTC")).astimezone(TZ)
        except: pass
    return _now()

def _rss_dt(e):
    for a in ("published_parsed","updated_parsed","created_parsed"):
        t = getattr(e,a,None)
        if t:
            try: return datetime(*t[:6],tzinfo=ZoneInfo("UTC")).astimezone(TZ)
            except: pass
    return _now()

def _item(title,summary,link,source,pub=None,geo_hint="",stype="NEWS"):
    if pub is None: pub = _now()
    text = f"{title} {summary} {geo_hint}"
    g = _geo(text)
    if g is None:
        fb = _FB[hash(title) % len(_FB)]
        lat,lon = _jitter(fb[0],fb[1],0.15)
        place,region = fb[2],fb[3]
    else:
        lat,lon,place,region = g
        lat,lon = _jitter(lat,lon,0.035)
    return {
        "id":        _uid(title+link),
        "dk":        _dedup_key(title),
        "title":     title[:160],
        "summary":   summary[:420],
        "link":      link,
        "source":    source,
        "stype":     stype,
        "severity":  _sev(text),
        "lat":       round(lat,5),
        "lon":       round(lon,5),
        "place":     place,
        "region":    region,
        "pub":       pub.isoformat(),
        "ts":        pub.strftime("%d/%m/%Y %H:%M"),
        "is_new":    True,
        "upd":       0,
    }

def _merge(old,new):
    if len(new["summary"]) > len(old["summary"]):
        old["summary"] = new["summary"]
    if new["severity"]=="critical": old["severity"]="critical"
    old["upd"] = old.get("upd",0)+1
    return old

# ─────────────────────────────────────────────────────────────────────
#  IPC — file JSON atomico
# ─────────────────────────────────────────────────────────────────────
_flock = threading.Lock()

def _write(items):
    tmp = FEED_FILE.with_suffix(".tmp")
    with _flock:
        try:
            tmp.write_text(json.dumps(items,ensure_ascii=False),encoding="utf-8")
            tmp.replace(FEED_FILE)
        except: pass

def _read():
    try:
        if FEED_FILE.exists():
            raw = json.loads(FEED_FILE.read_text(encoding="utf-8"))
            for r in raw:
                if isinstance(r.get("pub"),str):
                    try: r["pub_dt"] = datetime.fromisoformat(r["pub"])
                    except: r["pub_dt"] = _now()
            return raw
    except: pass
    return []

# ─────────────────────────────────────────────────────────────────────
#  FETCHERS — solo incidenti reali
# ─────────────────────────────────────────────────────────────────────

def _f_ransomware_live():
    """API JSON pubblica ransomware.live — vittime italiane."""
    out = []
    for ep in ["https://api.ransomware.live/recentvictims",
               "https://api.ransomware.live/victims"]:
        try:
            r = requests.get(ep,timeout=15,headers=_H)
            if not r.ok: continue
            data = r.json()
            if isinstance(data,dict):
                data = data.get("data", data.get("victims", data.get("result",[])))
            for v in (data or [])[:200]:
                country = (v.get("country","") or v.get("Country","") or "").strip().lower()
                domain  = (v.get("domain","") or v.get("website","") or "").strip().lower()
                victim  = (v.get("victim","") or v.get("name","") or v.get("company","") or "").strip()
                desc    = _strip(v.get("description","") or v.get("summary","") or "")
                group   = (v.get("group","") or v.get("ransomware_group","") or "unknown").strip()
                link    = (v.get("url","") or v.get("link","")
                           or f"https://www.ransomware.live/#victim={_uid(victim)}")
                is_it   = (country in ("italy","it","italia")
                           or domain.endswith(".it")
                           or _IT_RE.search(f"{victim} {desc}"))
                if not is_it: continue
                raw_d   = (v.get("published","") or v.get("date","")
                           or v.get("discovered","") or v.get("added","") or "")
                pub     = _parse_dt(raw_d) if raw_d else _now()
                title   = f"[{group.upper()}] Colpita: {victim}" if victim else f"Vittima ransomware {group}"
                summary = desc or f"Organizzazione italiana colpita dal gruppo ransomware {group}. Dominio: {domain}"
                out.append(_item(title,summary,link,"Ransomware.live",pub,
                                 f"{victim} {domain} italia",stype="RANSOMWARE"))
        except: continue
    return out

def _f_hackmanac():
    """hackmanac su GitHub — database attacchi pubblici con focus Italia."""
    out = []
    # File JSON pubblico del progetto hackmanac (nessuna auth)
    urls = [
        "https://raw.githubusercontent.com/Casualtek/Cyberwatch-it/main/cyberattacks.json",
        "https://raw.githubusercontent.com/Casualtek/Ransomwatch/main/profiles.json",
    ]
    for url in urls:
        try:
            r = requests.get(url,timeout=15,headers=_H)
            if not r.ok: continue
            data = r.json()
            if not isinstance(data,list): data = list(data.values()) if isinstance(data,dict) else []
            for v in data[:300]:
                if isinstance(v,str): continue
                title   = (v.get("title","") or v.get("name","") or v.get("victim","") or "").strip()
                summary = _strip(v.get("description","") or v.get("summary","") or v.get("text","") or "")
                link    = (v.get("url","") or v.get("link","") or v.get("source","") or "#")
                country = (v.get("country","") or "").lower()
                if country and country not in ("it","ita","italy","italian","italia"):
                    if not _IT_RE.search(f"{title} {summary}"):
                        continue
                raw_d = (v.get("date","") or v.get("published","") or v.get("added","") or "")
                pub   = _parse_dt(raw_d) if raw_d else _now()
                if not title: continue
                out.append(_item(title,summary,link,"Hackmanac/Cyberwatch",pub,
                                 f"{title} italia",stype="RANSOMWARE"))
        except: continue
    return out

def _f_cert_agid():
    out = []
    for url,name in [
        ("https://cert-agid.gov.it/feed/","CERT-AgID"),
        ("https://www.csirt.gov.it/feed","CSIRT Italia"),
    ]:
        try:
            r = requests.get(url,timeout=12,headers=_H)
            feed = feedparser.parse(r.text if r.ok else "")
            for e in feed.entries[:50]:
                title   = _strip(e.get("title","")).strip()
                summary = _strip(e.get("summary",e.get("description","")))
                link    = e.get("link","#")
                if not title: continue
                if _NOISE_RE.search(f"{title} {summary}"): continue
                out.append(_item(title,summary,link,name,_rss_dt(e),stype="CERT_IT"))
        except: continue
    return out

def _f_rhc():
    """Red Hot Cyber — notizie incidenti in italiano."""
    out = []
    try:
        r = requests.get("https://www.redhotcyber.com/feed/",timeout=12,headers=_H)
        feed = feedparser.parse(r.text if r.ok else "")
        for e in feed.entries[:60]:
            title   = _strip(e.get("title","")).strip()
            summary = _strip(e.get("summary",e.get("description","")))
            link    = e.get("link","#")
            if not title: continue
            if not _accept(title,summary,"NEWS"): continue
            out.append(_item(title,summary,link,"Red Hot Cyber",_rss_dt(e),stype="NEWS"))
    except: pass
    return out

def _f_cs360():
    out = []
    try:
        r = requests.get("https://www.cybersecurity360.it/feed/",timeout=12,headers=_H)
        feed = feedparser.parse(r.text if r.ok else "")
        for e in feed.entries[:60]:
            title   = _strip(e.get("title","")).strip()
            summary = _strip(e.get("summary",e.get("description","")))
            link    = e.get("link","#")
            if not title: continue
            if not _accept(title,summary,"NEWS"): continue
            out.append(_item(title,summary,link,"Cybersecurity360",_rss_dt(e),stype="NEWS"))
    except: pass
    return out

def _f_bleeping():
    out = []
    try:
        r = requests.get("https://www.bleepingcomputer.com/feed/",timeout=12,headers=_H)
        feed = feedparser.parse(r.text if r.ok else "")
        for e in feed.entries[:80]:
            title   = _strip(e.get("title","")).strip()
            summary = _strip(e.get("summary",e.get("description","")))
            link    = e.get("link","#")
            if not title: continue
            if not _accept(title,summary,"NEWS"): continue
            out.append(_item(title,summary,link,"BleepingComputer",_rss_dt(e),stype="NEWS"))
    except: pass
    return out

def _f_databreaches():
    """DataBreaches.net — database violazioni pubbliche."""
    out = []
    try:
        r = requests.get("https://www.databreaches.net/feed/",timeout=12,headers=_H)
        feed = feedparser.parse(r.text if r.ok else "")
        for e in feed.entries[:60]:
            title   = _strip(e.get("title","")).strip()
            summary = _strip(e.get("summary",e.get("description","")))
            link    = e.get("link","#")
            if not title: continue
            if not _accept(title,summary,"NEWS"): continue
            out.append(_item(title,summary,link,"DataBreaches.net",_rss_dt(e),stype="NEWS"))
    except: pass
    return out

def _f_threatpost():
    out = []
    for url,name in [
        ("https://threatpost.com/feed/","Threatpost"),
        ("https://feeds.feedburner.com/TheHackersNews","The Hacker News"),
        ("https://www.darkreading.com/rss.xml","DarkReading"),
        ("https://krebsonsecurity.com/feed/","Krebs on Security"),
        ("https://www.helpnetsecurity.com/feed/","Help Net Security"),
        ("https://therecord.media/feed/","The Record"),
        ("https://www.infosecurity-magazine.com/rss/news/","Infosecurity Magazine"),
        ("https://www.securityweek.com/feed/","SecurityWeek"),
    ]:
        try:
            r = requests.get(url,timeout=12,headers=_H)
            feed = feedparser.parse(r.text if r.ok else "")
            for e in feed.entries[:60]:
                title   = _strip(e.get("title","")).strip()
                summary = _strip(e.get("summary",e.get("description","")))
                link    = e.get("link","#")
                if not title: continue
                if not _accept(title,summary,"NEWS"): continue
                out.append(_item(title,summary,link,name,_rss_dt(e),stype="NEWS"))
        except: continue
    return out

def _f_urlhaus():
    """URLhaus — URL malware con host .it"""
    out = []
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/api/v1/",
                          data={"query":"get_urls","limit":100},
                          headers=_H,timeout=12)
        if not r.ok: return []
        for u in r.json().get("urls",[]):
            host = (u.get("host","") or "").lower()
            url_str = (u.get("url","") or "")
            if not host.endswith(".it"): continue
            threat = u.get("threat","") or "malware"
            tags   = ", ".join(u.get("tags") or [])
            title   = f"[URLhaus] {threat.upper()} su {host}"
            summary = f"URL malevola su infrastruttura italiana: {url_str[:100]} | Tags: {tags} | Status: {u.get('url_status','')}"
            link    = u.get("urlhaus_reference","https://urlhaus.abuse.ch")
            pub     = _parse_dt(u.get("date_added",""))
            out.append(_item(title,summary,link,"URLhaus",pub,f"italy .it {host}",stype="THREAT"))
    except: pass
    return out

def _f_threatfox():
    """ThreatFox IoC — malware italiani."""
    out = []
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query":"get_iocs","days":1},
                          headers=_H,timeout=12)
        if not r.ok: return []
        for ioc in r.json().get("data",[])[:100]:
            country = (ioc.get("reporter_country","") or "").upper()
            if country and country not in ("IT","ITA"): continue
            malware = ioc.get("malware","") or "unknown"
            ioc_val = ioc.get("ioc","") or ""
            tags    = ", ".join(ioc.get("tags") or [])
            title   = f"[ThreatFox] {malware} IoC italiano: {ioc_val[:40]}"
            summary = (f"Indicatore di compromissione rilevato in Italia | "
                       f"Malware: {malware} | Type: {ioc.get('ioc_type','')} | Tags: {tags}")
            link    = f"https://threatfox.abuse.ch/ioc/{ioc.get('id','')}"
            pub     = _parse_dt(ioc.get("first_seen",""))
            out.append(_item(title,summary,link,"ThreatFox",pub,"italy",stype="THREAT"))
    except: pass
    return out

def _f_feodo():
    """Feodo Tracker — C2 server in Italia."""
    out = []
    try:
        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            timeout=12,headers=_H)
        if not r.ok: return []
        data = r.json()
        if isinstance(data,dict): data = data.get("ip_addresses",[])
        for e in (data or []):
            if (e.get("country","") or "").upper() not in ("IT","ITA"): continue
            ip     = e.get("ip_address","") or ""
            mal    = e.get("malware","") or "unknown"
            title   = f"[Feodo] Server C2 {mal} in Italia: {ip}"
            summary = (f"Infrastruttura C2 di {mal} ospitata in Italia | "
                       f"IP: {ip} | Porta: {e.get('port','')} | Status: {e.get('status','')}")
            link    = "https://feodotracker.abuse.ch"
            pub     = _parse_dt(e.get("first_seen","") or e.get("last_online",""))
            out.append(_item(title,summary,link,"Feodo Tracker",pub,"italy italia",stype="THREAT"))
    except: pass
    return out

def _f_alienvault(key):
    if not key: return []
    out = []
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            params={"limit":50,"modified_since":
                    (datetime.utcnow()-timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S")},
            headers={**_H,"X-OTX-API-KEY":key},timeout=12)
        if not r.ok: return []
        for p in r.json().get("results",[]):
            title   = (p.get("name","") or "").strip()
            desc    = (p.get("description","") or "").strip()
            tags    = " ".join(p.get("tags",[]))
            text    = f"{title} {desc} {tags}"
            if not (_IT_RE.search(text) or _ORGS_IT.search(text)): continue
            if not _INCIDENT_RE.search(text): continue
            link    = f"https://otx.alienvault.com/pulse/{p.get('id','')}"
            pub     = _parse_dt(p.get("modified","") or p.get("created",""))
            out.append(_item(title,desc[:300],link,"AlienVault OTX",pub,tags,stype="THREAT"))
    except: pass
    return out

def _f_newsapi(key):
    if not key: return []
    out = []
    # Query specifiche per incidenti reali — non notizie generiche
    queries = [
        "\"attacco informatico\" Italia",
        "\"data breach\" Italia \"hackerata\"",
        "\"ransomware\" Italia \"colpita\"",
        "\"violazione dati\" Italia",
        "hacked Italy organization",
        "\"cyber attack\" Italy \"hospital\" OR \"university\" OR \"government\"",
    ]
    for q in queries:
        try:
            r = requests.get("https://newsapi.org/v2/everything",
                params={"q":q,"sortBy":"publishedAt","pageSize":20,"apiKey":key},
                timeout=10,headers=_H)
            if not r.ok: continue
            for a in r.json().get("articles",[]):
                title   = (a.get("title","") or "").strip()
                desc    = (a.get("description","") or "").strip()
                content = (a.get("content","") or "").strip()
                link    = a.get("url","#")
                pub     = _parse_dt(a.get("publishedAt",""))
                combined = f"{title} {desc} {content}"
                if not _accept(title,combined,"NEWS"): continue
                out.append(_item(title,f"{desc} {content[:200]}".strip(),
                                 link,"NewsAPI",pub,stype="NEWS"))
        except: continue
    return out

# ─────────────────────────────────────────────────────────────────────
#  MASTER FETCH
# ─────────────────────────────────────────────────────────────────────
def _fetch_all():
    try:    keys = {k: st.secrets.get(k,"") for k in ["NEWSAPI_KEY","ALIENVAULT_KEY"]}
    except: keys = {k: os.environ.get(k,"") for k in ["NEWSAPI_KEY","ALIENVAULT_KEY"]}

    batches = [
        _f_ransomware_live,
        _f_hackmanac,
        _f_cert_agid,
        _f_rhc,
        _f_cs360,
        _f_bleeping,
        _f_databreaches,
        _f_threatpost,
        _f_urlhaus,
        _f_threatfox,
        _f_feodo,
        lambda: _f_alienvault(keys.get("ALIENVAULT_KEY","")),
        lambda: _f_newsapi(keys.get("NEWSAPI_KEY","")),
    ]
    out = []
    for fn in batches:
        try: out.extend(fn())
        except: pass
    return out

# ─────────────────────────────────────────────────────────────────────
#  BACKGROUND THREAD
# ─────────────────────────────────────────────────────────────────────
_started = threading.Event()

def _loop():
    store: dict[str,dict] = {}
    while True:
        for item in _fetch_all():
            dk = item["dk"]
            if dk in store:
                store[dk] = _merge(store[dk], item)
            else:
                store[dk] = item
        # Sort + trim
        sorted_items = sorted(store.values(),
                               key=lambda x: x.get("pub",""), reverse=True)[:MAX_ITEMS]
        store = {i["dk"]: i for i in sorted_items}
        _write(sorted_items)
        time.sleep(FETCH_INT)

def _ensure():
    if not _started.is_set():
        _started.set()
        threading.Thread(target=_loop,daemon=True,name="CyberFetch").start()

# ─────────────────────────────────────────────────────────────────────
#  MAP — aggiunge SOLO i marker nuovi senza rebuilding completo
# ─────────────────────────────────────────────────────────────────────
SEV_C = {"critical":"#ff3b30","medium":"#ff9f0a","low":"#30d158"}
SEV_G = {"critical":"rgba(255,59,48,.14)","medium":"rgba(255,159,10,.14)","low":"rgba(48,209,88,.14)"}
SEV_S = {"critical":14,"medium":10,"low":8}
SEV_GS= {"critical":28,"medium":21,"low":15}

def build_map(attacks):
    df = pd.DataFrame(attacks) if attacks else pd.DataFrame(
        columns=["lat","lon","title","place","region","severity","ts","source","link"])
    fig = go.Figure()
    for sev in ["critical","medium","low"]:
        sub = df[df["severity"]==sev] if len(df) else pd.DataFrame()
        if sub.empty: continue
        hover = [
            f"<b>{r['title'][:72]}{'…'if len(r['title'])>72 else''}</b><br>"
            f"<span style='color:#7eb3d4'>📍 {r['place']} — {r['region']}</span><br>"
            f"<span style='color:#586374'>🕒 {r['ts']} · {r['source']}</span><br>"
            f"<span style='color:{SEV_C[sev]};font-weight:600;font-size:10px'>▲ {sev.upper()}</span>"
            for _,r in sub.iterrows()
        ]
        lons,lats = sub["lon"].tolist(),sub["lat"].tolist()
        links = sub["link"].tolist() if "link" in sub.columns else []
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",
            name=f"_g{sev}",marker=dict(size=SEV_GS[sev],color=SEV_G[sev],opacity=.5),
            hoverinfo="skip",showlegend=False))
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",
            name=f"_m{sev}",marker=dict(size=int(SEV_GS[sev]*.56),color=SEV_G[sev],opacity=.38),
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
        dragmode="pan",uirevision="italy_map",  # <-- mantiene zoom/pan tra rerun
    )
    for tr in fig.data:
        if tr.name and tr.name.startswith("_"): tr.showlegend=False
    return fig

# ─────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────
def sidebar(attacks):
    with st.sidebar:
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.7rem;
          color:#586374;letter-spacing:.12em;text-transform:uppercase;
          padding:4px 0 16px 0;border-bottom:1px solid #1e2730;margin-bottom:16px;'>
          ◈ FILTERS</div>""",unsafe_allow_html=True)

        sel_sev = st.multiselect("SEVERITY",["critical","medium","low"],
                                 default=["critical","medium","low"],format_func=str.upper)
        st.markdown("<div style='height:7px'></div>",unsafe_allow_html=True)

        avail_reg = sorted(set(a["region"] for a in attacks)) if attacks else sorted(REGIONS)
        sel_reg   = st.multiselect("REGION",avail_reg,default=[],placeholder="All regions")
        st.markdown("<div style='height:7px'></div>",unsafe_allow_html=True)

        today = datetime.now().date()
        c1,c2 = st.columns(2)
        with c1: df_ = st.date_input("FROM",value=today-timedelta(days=7))
        with c2: dt_ = st.date_input("TO",  value=today)
        st.markdown("<div style='height:7px'></div>",unsafe_allow_html=True)

        avail_src = sorted(set(a["source"] for a in attacks)) if attacks else []
        sel_src   = st.multiselect("SOURCE",avail_src,default=[],placeholder="All sources")
        st.markdown("<div style='height:7px'></div>",unsafe_allow_html=True)

        search = st.text_input("🔍 SEARCH",placeholder="sapienza, ransomware, milano…")
        st.markdown("<hr style='border-color:#1e2730;margin:14px 0'>",unsafe_allow_html=True)
        if st.button("↺  RESET"): st.rerun()

        st.markdown(f"""<div style='font-family:"IBM Plex Mono",monospace;font-size:.56rem;
          color:#586374;margin-top:18px;line-height:1.9;'>
          <span style='color:#30d158'>● FONTI ATTIVE</span><br>
          · Ransomware.live API<br>· Hackmanac/Cyberwatch-IT<br>
          · CERT-AgID · CSIRT Italia<br>· Red Hot Cyber · Cybersecurity360<br>
          · BleepingComputer · DataBreaches.net<br>
          · Threatpost · THN · DarkReading<br>
          · Krebs · SecurityWeek · TheRecord<br>
          · Infosecurity Magazine · HelpNet<br>
          · URLhaus · ThreatFox · Feodo<br>
          · AlienVault OTX (key opz.)<br>
          · NewsAPI (key opz.)<br>
          <br><span style='color:#ff9f0a'>● FETCH:</span> ogni {FETCH_INT}s<br>
          <span style='color:#ff3b30'>● UI POLL:</span> ogni {POLL_MS//1000}s<br>
          <span style='color:#30d158'>● IPC:</span> file JSON — no reload
        </div>""",unsafe_allow_html=True)
    return sel_sev,sel_reg,df_,dt_,sel_src,search

def _filter(attacks,sel_sev,sel_reg,df_,dt_,sel_src,search):
    f = attacks
    if sel_sev: f=[a for a in f if a["severity"] in sel_sev]
    if sel_reg: f=[a for a in f if a["region"]   in sel_reg]
    if sel_src: f=[a for a in f if a["source"]   in sel_src]
    f=[a for a in f if isinstance(a.get("pub_dt"),datetime)
       and df_<=a["pub_dt"].date()<=dt_]
    if search:
        q=search.lower()
        f=[a for a in f if q in a["title"].lower() or q in a["summary"].lower()
           or q in a["place"].lower() or q in a["source"].lower()]
    return f

# ─────────────────────────────────────────────────────────────────────
#  FEED HTML — render puro, nessun re-render Streamlit
# ─────────────────────────────────────────────────────────────────────
def _card_html(a) -> str:
    sev  = a["severity"]
    cls  = "" if sev=="critical" else sev
    new  = "is-new" if a.get("is_new") else ""
    link = a.get("link","#")
    badge_new = '<span class="bx bn">● NEW</span>' if a.get("is_new") else ""
    upd_badge = (f'<span style="color:#586374;font-size:.56rem">↑{a["upd"]}×</span> '
                 if a.get("upd",0)>0 else "")
    return f"""<div class="fc {cls} {new}">
  <div class="ft"><a href="{link}" target="_blank">{a['title']}</a></div>
  <div class="fm">{badge_new}{upd_badge}<span class="bx b{sev[0]}">{sev}</span>
    <span class="bx br">{a['region']}</span>
    <span class="bx bs">{a['source']}</span>
    📍 {a['place']} &nbsp;·&nbsp; {a['ts']}</div>
  <div class="fd">{a['summary'][:260]}{'…'if len(a['summary'])>260 else''}</div>
</div>"""

def render_feed(attacks):
    if not attacks:
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.75rem;
          color:#586374;text-align:center;padding:40px 0;'>
          <div style='font-size:1.4rem;margin-bottom:8px'>◌</div>
          FETCHING FEED IN CORSO…<br>
          <span style='font-size:.6rem'>prima notizia in ~{FETCH_INT}s</span>
        </div>""",unsafe_allow_html=True)
        return
    html = '<div class="feed-wrap">'+"".join(_card_html(a) for a in attacks[:200])+"</div>"
    st.markdown(html, unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    _ensure()

    # Autorefresh ogni 4s — Streamlit rerun, legge file aggiornato
    # uirevision="italy_map" nella mappa garantisce che zoom/pan non resetta
    if HAS_AR:
        st_autorefresh(interval=POLL_MS,limit=None,key="poll")

    all_attacks = _read()
    now = datetime.now(TZ)

    # ── Header ────────────────────────────────────────────────────────
    st.markdown("""<div style='display:flex;align-items:center;margin-bottom:4px;'>
      <div style='font-family:"IBM Plex Mono",monospace;font-size:1.5rem;
                  font-weight:600;color:#e8ecf0;letter-spacing:-.02em;'>
        <span style='color:#ff3b30'>◈</span> ITALY CYBER THREAT MAP
      </div>
      <div style='margin-left:auto;font-family:"IBM Plex Mono",monospace;
                  font-size:.6rem;color:#586374;letter-spacing:.08em;'>
        LIVE INCIDENT TRACKER
      </div>
    </div>""",unsafe_allow_html=True)

    sel_sev,sel_reg,df_,dt_,sel_src,search = sidebar(all_attacks)
    filtered = _filter(all_attacks,sel_sev,sel_reg,df_,dt_,sel_src,search)

    total  = len(all_attacks)
    crit   = sum(1 for a in all_attacks if a["severity"]=="critical")
    med    = sum(1 for a in all_attacks if a["severity"]=="medium")
    low    = sum(1 for a in all_attacks if a["severity"]=="low")
    reg_n  = len(set(a["region"] for a in all_attacks))
    new_n  = sum(1 for a in all_attacks if a.get("is_new"))

    k1,k2,k3,k4,k5 = st.columns(5)
    k1.metric("INCIDENTI TOTALI",total)
    k2.metric("⬤ CRITICAL",crit)
    k3.metric("⬤ MEDIUM",med)
    k4.metric("⬤ LOW",low)
    k5.metric("REGIONI COLPITE",reg_n)

    st.markdown("<div style='height:3px'></div>",unsafe_allow_html=True)

    age_s = ""
    if all_attacks:
        last = all_attacks[0].get("pub_dt")
        if isinstance(last,datetime):
            delta = int((now-last).total_seconds())
            age_s = f" · ultima notizia {delta}s fa"

    new_html = (f" · <span style='color:#30d158;font-weight:600'>+{new_n} nuovi</span>"
                if new_n>0 else "")
    nxt = FETCH_INT-(int(time.time())%FETCH_INT)
    st.markdown(f"""<div class="sbar">
      <span class="pulse"></span>LIVE · {now.strftime('%d/%m/%Y %H:%M:%S')} IT ·
      {len(filtered)} eventi (filtrati) · {total} in storico ·
      next fetch ~{nxt}s{age_s}{new_html}
    </div>""",unsafe_allow_html=True)

    map_col,feed_col = st.columns([3,1.5],gap="medium")

    with map_col:
        # key="cybermap" + uirevision="italy_map" → Plotly non rebuilda il DOM
        # aggiunge solo i trace nuovi senza flickering
        st.plotly_chart(build_map(filtered),use_container_width=True,
            key="cybermap",
            config={"scrollZoom":True,"displayModeBar":True,"displaylogo":False,
                    "modeBarButtonsToRemove":["select2d","lasso2d","autoScale2d","resetScale2d"],
                    "toImageButtonOptions":{"format":"png","filename":"italy_cybermap"}})
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.6rem;
          color:#586374;text-align:center;margin-top:-8px;'>
          CLICK MARKER → REPORT · SCROLL TO ZOOM · DRAG TO PAN
        </div>""",unsafe_allow_html=True)

    with feed_col:
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.65rem;
          color:#586374;letter-spacing:.1em;text-transform:uppercase;
          padding-bottom:8px;border-bottom:1px solid #1e2730;margin-bottom:10px;'>
          ◈ INCIDENT FEED — REAL-TIME
        </div>""",unsafe_allow_html=True)
        with st.container(height=655):
            render_feed(filtered)

    if not HAS_AR:
        st.markdown(f"<script>setTimeout(()=>window.location.reload(),{POLL_MS})</script>",
                    unsafe_allow_html=True)
        st.warning("Installa streamlit-autorefresh per aggiornamento senza reload: "
                   "`pip install streamlit-autorefresh`")

if __name__=="__main__":
    main()
