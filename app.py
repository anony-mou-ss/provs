"""
ITALY CYBER THREAT MAP  v6.0
Architettura semplice e affidabile:
  - st.cache_data(ttl=30) per fetch con cache nativa Streamlit
  - st_autorefresh ogni 30s triggera rerun → cache scaduta → nuovo fetch
  - Nessun thread, nessun file IPC, nessun loop infinito
  - Funziona su Streamlit Cloud, localmente, ovunque

pip install streamlit plotly requests feedparser pandas streamlit-autorefresh
streamlit run italy_cybermap.py
"""

import re, hashlib, random, time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import streamlit as st
import plotly.graph_objects as go
import requests, feedparser
import pandas as pd

# ── autorefresh opzionale ─────────────────────────────────────────────
try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AR = True
except ImportError:
    HAS_AR = False

# ─────────────────────────────────────────────────────────────────────
#  PAGE CONFIG  — deve essere la prima chiamata st.*
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
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600&display=swap');
:root{--bg:#0a0c0f;--card:#141920;--brd:#1e2730;
      --red:#ff3b30;--ora:#ff9f0a;--grn:#30d158;--dim:#586374;}
html,body,[class*="css"]{background:var(--bg)!important;color:#c8d0dc!important;
  font-family:'IBM Plex Sans',sans-serif!important;}
[data-testid="stSidebar"]{background:#0f1318!important;border-right:1px solid var(--brd)!important;}
[data-testid="stSidebar"] *{color:#c8d0dc!important;}
[data-testid="metric-container"]{background:var(--card)!important;border:1px solid var(--brd)!important;
  border-radius:6px!important;padding:12px 16px!important;}
[data-testid="metric-container"] label{color:var(--dim)!important;font-family:'IBM Plex Mono',monospace!important;
  font-size:.65rem!important;text-transform:uppercase;letter-spacing:.1em;}
[data-testid="metric-container"] [data-testid="stMetricValue"]{font-family:'IBM Plex Mono',monospace!important;
  font-size:1.5rem!important;color:var(--red)!important;}
.stMultiSelect>div>div,.stTextInput>div>div,.stDateInput>div>div{
  background:var(--card)!important;border:1px solid var(--brd)!important;color:#c8d0dc!important;}
.stButton>button{background:transparent!important;border:1px solid var(--red)!important;
  color:var(--red)!important;font-family:'IBM Plex Mono',monospace!important;
  font-size:.7rem!important;border-radius:3px!important;}
hr{border-color:var(--brd)!important;}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}

.fc{background:var(--card);border:1px solid var(--brd);border-left:3px solid var(--red);
  border-radius:4px;padding:10px 14px;margin-bottom:7px;}
.fc.med{border-left-color:var(--ora)}.fc.low{border-left-color:var(--grn)}
.fc.nw{animation:sld .5s ease-out}
@keyframes sld{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.ft{font-weight:600;font-size:.83rem;color:#e8ecf0;margin-bottom:3px;line-height:1.4;}
.ft a{color:#e8ecf0;text-decoration:none}.ft a:hover{color:var(--red)}
.fm{font-family:'IBM Plex Mono',monospace;font-size:.61rem;color:var(--dim);margin-bottom:4px;line-height:1.7;}
.fd{font-size:.74rem;color:var(--dim);line-height:1.45;}
.bx{display:inline-block;padding:1px 6px;border-radius:2px;font-family:'IBM Plex Mono',monospace;
  font-size:.57rem;font-weight:600;letter-spacing:.05em;margin-right:3px;text-transform:uppercase;}
.bc{background:#3d1515;color:var(--red);border:1px solid var(--red);}
.bm{background:#2d1f08;color:var(--ora);border:1px solid var(--ora);}
.bl{background:#0d2418;color:var(--grn);border:1px solid var(--grn);}
.br{background:#1a1f2a;color:#7eb3d4;border:1px solid #2a3a4d;}
.bs{background:#1a1520;color:#c07aff;border:1px solid #3a2560;}
.bn{background:#0d2010;color:var(--grn);border:1px solid var(--grn);animation:blk .6s step-end 5;}
@keyframes blk{50%{opacity:0}}
.pulse{display:inline-block;width:7px;height:7px;background:var(--red);
  border-radius:50%;margin-right:6px;animation:pls 1.4s infinite;vertical-align:middle;}
@keyframes pls{0%{box-shadow:0 0 0 0 rgba(255,59,48,.7)}70%{box-shadow:0 0 0 7px rgba(255,59,48,0)}100%{box-shadow:0 0 0 0 rgba(255,59,48,0)}}
.sbar{font-family:'IBM Plex Mono',monospace;font-size:.61rem;color:var(--dim);padding:4px 0;}
#MainMenu,footer,header{visibility:hidden!important;}
.block-container{padding-top:1.2rem!important;}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────
#  GEO DB
# ─────────────────────────────────────────────────────────────────────
_CITIES = sorted([
    ("reggio calabria",38.1147,15.6615,"Calabria"),
    ("reggio emilia",44.6989,10.6297,"Emilia-Romagna"),
    ("ascoli piceno",42.854,13.5745,"Marche"),
    ("vibo valentia",38.676,16.0995,"Calabria"),
    ("la spezia",44.1024,9.824,"Liguria"),
    ("l'aquila",42.3498,13.3995,"Abruzzo"),
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
    ("frosinone",41.6396,13.3396,"Lazio"),
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
    ("pavia",45.1847,9.1582,"Lombardia"),
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
ALL_REGIONS = sorted(REGIONS)

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
#  FILTRI
# ─────────────────────────────────────────────────────────────────────
_INCIDENT = re.compile(
    r"hackerata?|hacked\b|colpit[ao]\b|violat[ao]\b|attaccat[ao]\b"
    r"|compromess[ao]\b|infiltrat[ao]\b|rubat[ao]\b|trafugat[ao]\b"
    r"|esfiltrat\w*|cifrat[ao]\b|criptat[ao]\b|bloccata?\b|paralizzat[ao]\b"
    r"|data\s*breach|databreach|ransomware\s+attack|sotto\s+attacco"
    r"|fuori\s+servizio|inaccessibil\w+|offline\b|down\b"
    r"|leak(ed)?\b|dump(ed)?\b|breached?\b|pwned\b"
    r"|victim\b|vittime?\b|rivendicat[ao]\b|claim(ed|s)?\b"
    r"|dati\s+rubati|dati\s+pubblicati|sistema\b.{0,25}bloccat"
    r"|attack(ed|s)?\b|intrusion\b|breach\b|incidente\b",
    re.I,
)
_ITALY = re.compile(
    r"\bital\w+|\broma\b|\bmilan\w*|\bnapol\w*|\btorin\w*|\bfirenz\w*"
    r"|\bbologna\b|\bvenezia\b|\bgenov\w*|\bpalermo\b|\bbari\b"
    r"|\bsicilia\b|\bsardegna\b|\bpuglia\b|\blazio\b|\blombardia\b"
    r"|\btoscana\b|\bveneto\b|\bcampania\b|\bcalabria\b|\bpiemonte\b"
    r"|\bliguria\b|\bumbria\b|\bmarche\b|\babruzzo\b|\bbasilicata\b"
    r"|\.it[\s/\"\'<>]"
    r"|\binail\b|\binps\b|\bpolizia\b|\bcarabinieri\b|\bconsip\b"
    r"|\btrenitalia\b|\benel\b|\beni\b|\bleonardo\b|\bfincantieri\b"
    r"|\bfastweb\b|\btim\b|\bintesa\b|\bunicredit\b|\bbnl\b"
    r"|\bposte\s+italian\w*|\bautostrade\b|\bsnam\b"
    r"|\bospedale\b|\basl\b|\buniversit\w+|\bcomune\s+di\b"
    r"|\bministero\b|\bprefettura\b|\bparlamento\b|\bsenato\b",
    re.I,
)
_NOISE = re.compile(
    r"\bcome\s+(protegger|difender|prevenire)\b|\bguida\b|\btutorial\b|\bhow\s+to\b"
    r"|\bstatistich\w+\b|\btendenz\w+\b|\brapporto\s+annual\w*\b"
    r"|\bwebinar\b|\bcorso\b|\bformazione\b|\bconferenz\w+\b"
    r"|\bsconto\b|\bofferta\b|\brecensione\b|\breview\b"
    r"|\bnew\s+feature\b|\bpatch\s+tuesday\b|\bwindows\s+update\b"
    r"|\bjob\b|\bassunz\w+\b",
    re.I,
)

def _ok(title, summary, cert=False):
    t = f"{title} {summary}"
    if _NOISE.search(t): return False
    if cert: return True
    return bool(_INCIDENT.search(t)) and bool(_ITALY.search(t))

# ─────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────
_H = {"User-Agent": "Mozilla/5.0 ItalyCyberMap/6.0", "Accept": "*/*"}

def _uid(s):
    return hashlib.md5(s.lower().strip().encode("utf-8","replace")).hexdigest()[:12]

def _strip(s):
    return re.sub(r"<[^>]+>", "", s or "").strip()

def _jitter(lat, lon, a=0.04):
    return (max(36.6, min(47.1, lat + random.uniform(-a, a))),
            max(6.6,  min(18.5, lon + random.uniform(-a, a))))

def _sev(t):
    t = t.lower()
    if re.search(r"ransomware|data.?breach|exfiltrat|zero.?day|critico|critical"
                 r"|lockbit|blackcat|cl0p|alphv|rhysida|akira|medusa|conti|hive"
                 r"|darkside|apt\d|paralizzat|cifrat|criptat", t): return "critical"
    if re.search(r"phishing|malware|ddos|exploit|hacked|compromess|breach|leak"
                 r"|defacement|backdoor|botnet|stealer|intrusion|attacco|violat", t): return "medium"
    return "low"

def _geo(text):
    t = text.lower()
    for city, lat, lon, reg in _CITIES:
        if re.search(r"\b" + re.escape(city) + r"\b", t):
            return lat, lon, city.title(), reg
    for reg, (lat, lon) in REGIONS.items():
        if re.search(r"\b" + re.escape(reg.lower()) + r"\b", t):
            return lat, lon, reg, reg
    return None

def _now():
    return datetime.now(ZoneInfo("Europe/Rome"))

def _pdt(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt).replace(
                tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("Europe/Rome"))
        except: pass
    return _now()

def _rdt(e):
    for a in ("published_parsed", "updated_parsed"):
        t = getattr(e, a, None)
        if t:
            try: return datetime(*t[:6], tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("Europe/Rome"))
            except: pass
    return _now()

def _mk(title, summary, link, source, pub=None, hint=""):
    if not pub: pub = _now()
    text = f"{title} {summary} {hint}"
    g = _geo(text)
    if g:
        lat, lon, place, region = g
        lat, lon = _jitter(lat, lon, 0.035)
    else:
        fb = _FB[hash(title) % len(_FB)]
        lat, lon = _jitter(fb[0], fb[1], 0.12)
        place, region = fb[2], fb[3]
    return {
        "id":      _uid(title + link),
        "title":   title[:160],
        "summary": summary[:400],
        "link":    link,
        "source":  source,
        "sev":     _sev(text),
        "lat":     round(lat, 5),
        "lon":     round(lon, 5),
        "place":   place,
        "region":  region,
        "pub":     pub,
        "ts":      pub.strftime("%d/%m/%Y %H:%M"),
    }

# ─────────────────────────────────────────────────────────────────────
#  FETCH FUNCTIONS — cached 30s con st.cache_data
# ─────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=30, show_spinner=False)
def fetch_ransomware_live():
    items = []
    for ep in [
        "https://api.ransomware.live/recentvictims",
        "https://api.ransomware.live/victims",
    ]:
        try:
            r = requests.get(ep, timeout=15, headers=_H)
            if not r.ok: continue
            data = r.json()
            if isinstance(data, dict):
                data = data.get("data", data.get("victims", data.get("result", [])))
            for v in (data or [])[:300]:
                country = (v.get("country","") or v.get("Country","") or "").strip().lower()
                domain  = (v.get("domain","")  or v.get("website","") or "").strip().lower()
                victim  = (v.get("victim","")  or v.get("name","")    or v.get("company","") or "").strip()
                desc    = _strip(v.get("description","") or v.get("summary","") or "")
                group   = (v.get("group","")   or v.get("ransomware_group","") or "unknown").strip()
                link    = (v.get("url","")     or v.get("link","")
                           or f"https://www.ransomware.live/#victim={_uid(victim)}")
                is_it   = (country in ("italy","it","italia")
                           or domain.endswith(".it")
                           or bool(_ITALY.search(f"{victim} {desc}")))
                if not is_it: continue
                raw_d = (v.get("published","") or v.get("date","")
                         or v.get("discovered","") or v.get("added","") or "")
                pub   = _pdt(raw_d) if raw_d else _now()
                title = f"[{group.upper()}] Colpita: {victim}" if victim else f"Ransomware {group} — vittima italiana"
                summ  = desc or f"Organizzazione italiana colpita dal gruppo ransomware {group}. Dominio: {domain}"
                items.append(_mk(title, summ, link, "Ransomware.live", pub, f"{victim} {domain} italia"))
        except: continue
    return items


@st.cache_data(ttl=30, show_spinner=False)
def fetch_cyberwatch():
    """Cyberwatch-IT: database attacchi italiani documentati su GitHub."""
    items = []
    urls = [
        "https://raw.githubusercontent.com/Casualtek/Cyberwatch-it/main/cyberattacks.json",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=15, headers=_H)
            if not r.ok: continue
            data = r.json()
            if not isinstance(data, list):
                data = list(data.values()) if isinstance(data, dict) else []
            for v in data[:500]:
                if not isinstance(v, dict): continue
                title   = (v.get("title","") or v.get("name","") or v.get("victim","") or "").strip()
                summary = _strip(v.get("description","") or v.get("summary","") or v.get("text","") or "")
                link    = (v.get("url","") or v.get("link","") or v.get("source","") or "#")
                raw_d   = (v.get("date","") or v.get("published","") or v.get("added","") or "")
                pub     = _pdt(raw_d) if raw_d else _now()
                if not title: continue
                items.append(_mk(title, summary, link, "Cyberwatch-IT", pub, "italia"))
        except: continue
    return items


@st.cache_data(ttl=30, show_spinner=False)
def fetch_rss_sources():
    """Tutti gli RSS — un'unica funzione cachata."""
    sources = [
        # Istituzionali IT (cert=True: accetta tutto)
        ("https://cert-agid.gov.it/feed/",            "CERT-AgID",          True),
        ("https://www.csirt.gov.it/feed",              "CSIRT Italia",       True),
        # Media italiani (filtro incidente+italy)
        ("https://www.redhotcyber.com/feed/",          "Red Hot Cyber",      False),
        ("https://www.cybersecurity360.it/feed/",      "Cybersecurity360",   False),
        # Internazionali (filtro incidente+italy)
        ("https://www.bleepingcomputer.com/feed/",     "BleepingComputer",   False),
        ("https://feeds.feedburner.com/TheHackersNews","The Hacker News",    False),
        ("https://www.darkreading.com/rss.xml",        "DarkReading",        False),
        ("https://krebsonsecurity.com/feed/",          "Krebs on Security",  False),
        ("https://www.databreaches.net/feed/",         "DataBreaches.net",   False),
        ("https://therecord.media/feed/",              "The Record",         False),
        ("https://www.infosecurity-magazine.com/rss/news/","Infosecurity",   False),
        ("https://www.securityweek.com/feed/",         "SecurityWeek",       False),
        ("https://www.helpnetsecurity.com/feed/",      "HelpNet Security",   False),
        ("https://threatpost.com/feed/",               "Threatpost",         False),
    ]
    items = []
    seen  = set()
    for url, name, cert in sources:
        try:
            r    = requests.get(url, timeout=10, headers=_H)
            feed = feedparser.parse(r.text if r.ok else "")
            for e in feed.entries[:80]:
                title   = _strip(e.get("title","")).strip()
                summary = _strip(e.get("summary", e.get("description","")))
                link    = e.get("link","#")
                if not title or title in seen: continue
                if not _ok(title, summary, cert=cert): continue
                seen.add(title)
                items.append(_mk(title, summary, link, name, _rdt(e)))
        except: continue
    return items


@st.cache_data(ttl=60, show_spinner=False)
def fetch_abuse_ch():
    """URLhaus + ThreatFox + Feodo — abuse.ch — infrastruttura italiana."""
    items = []

    # URLhaus — URL malware su host .it
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/api/v1/",
                          data={"query":"get_urls","limit":200}, headers=_H, timeout=12)
        if r.ok:
            for u in r.json().get("urls",[]):
                host = (u.get("host","") or "").lower()
                if not host.endswith(".it"): continue
                url_str = u.get("url","") or ""
                threat  = u.get("threat","") or "malware"
                tags    = ", ".join(u.get("tags") or [])
                title   = f"[URLhaus] {threat.upper()} su {host}"
                summ    = f"URL malevola su infrastruttura italiana: {url_str[:100]} | Tags: {tags}"
                link    = u.get("urlhaus_reference","https://urlhaus.abuse.ch")
                pub     = _pdt(u.get("date_added",""))
                items.append(_mk(title, summ, link, "URLhaus", pub, f"italy .it {host}"))
    except: pass

    # ThreatFox — IoC con paese Italia
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query":"get_iocs","days":1}, headers=_H, timeout=12)
        if r.ok:
            for ioc in r.json().get("data",[])[:100]:
                country = (ioc.get("reporter_country","") or "").upper()
                if country and country not in ("IT","ITA"): continue
                malware = ioc.get("malware","") or "unknown"
                ioc_val = ioc.get("ioc","") or ""
                tags    = ", ".join(ioc.get("tags") or [])
                title   = f"[ThreatFox] {malware} — IoC italiano: {ioc_val[:40]}"
                summ    = f"Indicatore di compromissione in Italia | Malware: {malware} | Tags: {tags}"
                link    = f"https://threatfox.abuse.ch/ioc/{ioc.get('id','')}"
                pub     = _pdt(ioc.get("first_seen",""))
                items.append(_mk(title, summ, link, "ThreatFox", pub, "italy"))
    except: pass

    # Feodo — C2 server in Italia
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
                         timeout=12, headers=_H)
        if r.ok:
            data = r.json()
            if isinstance(data, dict): data = data.get("ip_addresses",[])
            for e in (data or []):
                if (e.get("country","") or "").upper() not in ("IT","ITA"): continue
                ip  = e.get("ip_address","") or ""
                mal = e.get("malware","") or "unknown"
                title = f"[Feodo] Server C2 {mal} in Italia: {ip}"
                summ  = f"C2 ospitato in Italia | IP: {ip} | Malware: {mal} | Porta: {e.get('port','')}"
                items.append(_mk(title, summ, "https://feodotracker.abuse.ch",
                                 "Feodo Tracker", _pdt(e.get("first_seen","")), "italy italia"))
    except: pass

    return items


def _all_items():
    """Raccoglie da tutte le fonti, deduplica, ordina."""
    raw = []
    for fn in [fetch_ransomware_live, fetch_cyberwatch,
               fetch_rss_sources, fetch_abuse_ch]:
        try: raw.extend(fn())
        except: pass

    # Dedup per id
    seen, out = set(), []
    for item in raw:
        if item["id"] not in seen:
            seen.add(item["id"])
            out.append(item)

    # Ordina per data decrescente
    out.sort(key=lambda x: x.get("pub", _now()), reverse=True)
    return out[:500]

# ─────────────────────────────────────────────────────────────────────
#  MAP
# ─────────────────────────────────────────────────────────────────────
SC = {"critical":"#ff3b30","medium":"#ff9f0a","low":"#30d158"}
SG = {"critical":"rgba(255,59,48,.14)","medium":"rgba(255,159,10,.14)","low":"rgba(48,209,88,.14)"}
SS = {"critical":14,"medium":10,"low":8}
SGS= {"critical":28,"medium":21,"low":15}

@st.cache_data(ttl=30, show_spinner=False)
def build_map(attack_tuples):
    """attack_tuples è una lista di tuple (hashable) per compatibilità cache."""
    attacks = [dict(zip(
        ["id","title","summary","link","source","sev","lat","lon","place","region","pub","ts"],
        t)) for t in attack_tuples]

    fig = go.Figure()
    df  = pd.DataFrame(attacks) if attacks else pd.DataFrame()

    for sev in ["critical","medium","low"]:
        sub = df[df["sev"]==sev] if len(df) else pd.DataFrame()
        if sub.empty: continue
        hover = [
            f"<b>{r['title'][:70]}{'…'if len(r['title'])>70 else''}</b><br>"
            f"<span style='color:#7eb3d4'>📍 {r['place']} — {r['region']}</span><br>"
            f"<span style='color:#586374'>🕒 {r['ts']} · {r['source']}</span><br>"
            f"<span style='color:{SC[sev]};font-weight:600'>▲ {sev.upper()}</span>"
            for _, r in sub.iterrows()
        ]
        lons, lats = sub["lon"].tolist(), sub["lat"].tolist()
        links = sub["link"].tolist()
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=f"_g{sev}",
            marker=dict(size=SGS[sev],color=SG[sev],opacity=.5),hoverinfo="skip",showlegend=False))
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=f"_m{sev}",
            marker=dict(size=int(SGS[sev]*.55),color=SG[sev],opacity=.35),hoverinfo="skip",showlegend=False))
        fig.add_trace(go.Scattermapbox(lon=lons,lat=lats,mode="markers",name=sev.upper(),
            marker=dict(size=SS[sev],color=SC[sev],opacity=.95),
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
        dragmode="pan",
        uirevision="italy_map",   # zoom/pan persistente tra rerun
    )
    for tr in fig.data:
        if tr.name and tr.name.startswith("_"): tr.showlegend = False
    return fig

# ─────────────────────────────────────────────────────────────────────
#  FEED HTML
# ─────────────────────────────────────────────────────────────────────
def _card(a, is_new=False):
    sev  = a["sev"]
    cls  = "" if sev=="critical" else sev
    nw   = "nw" if is_new else ""
    link = a.get("link","#")
    bn   = '<span class="bx bn">● NEW</span> ' if is_new else ""
    bc   = {"critical":"bc","medium":"bm","low":"bl"}[sev]
    return (
        f'<div class="fc {cls} {nw}">'
        f'<div class="ft"><a href="{link}" target="_blank">{a["title"]}</a></div>'
        f'<div class="fm">{bn}<span class="bx {bc}">{sev}</span>'
        f'<span class="bx br">{a["region"]}</span>'
        f'<span class="bx bs">{a["source"]}</span>'
        f'📍 {a["place"]} &nbsp;·&nbsp; {a["ts"]}</div>'
        f'<div class="fd">{a["summary"][:260]}{"…"if len(a["summary"])>260 else""}</div>'
        f'</div>'
    )

# ─────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    # ── Autorefresh ogni 30s — triggera rerun → cache scaduta → nuovo fetch
    # Messo DOPO set_page_config e CSS, prima del contenuto
    if HAS_AR:
        st_autorefresh(interval=30_000, limit=None, key="ar")

    # ── Fetch dati ────────────────────────────────────────────────────
    attacks = _all_items()

    # ── Traccia nuovi (vs sessione precedente) ────────────────────────
    prev_ids = st.session_state.get("prev_ids", set())
    new_ids  = {a["id"] for a in attacks} - prev_ids
    st.session_state["prev_ids"] = {a["id"] for a in attacks}

    # ── Header ────────────────────────────────────────────────────────
    now = datetime.now(ZoneInfo("Europe/Rome"))
    st.markdown(
        f"""<div style='display:flex;align-items:center;margin-bottom:4px;'>
          <div style='font-family:"IBM Plex Mono",monospace;font-size:1.45rem;
                      font-weight:600;color:#e8ecf0;letter-spacing:-.02em;'>
            <span style='color:#ff3b30'>◈</span> ITALY CYBER THREAT MAP
          </div>
          <div style='margin-left:auto;font-family:"IBM Plex Mono",monospace;
                      font-size:.6rem;color:#586374;'>LIVE INCIDENT TRACKER</div>
        </div>""", unsafe_allow_html=True)

    # ── Sidebar ───────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.7rem;
          color:#586374;letter-spacing:.12em;text-transform:uppercase;
          padding:4px 0 14px;border-bottom:1px solid #1e2730;margin-bottom:14px;'>
          ◈ FILTERS</div>""", unsafe_allow_html=True)

        sel_sev = st.multiselect("SEVERITY", ["critical","medium","low"],
                                 default=["critical","medium","low"], format_func=str.upper)
        avail_reg = sorted(set(a["region"] for a in attacks)) if attacks else ALL_REGIONS
        sel_reg   = st.multiselect("REGION", avail_reg, default=[], placeholder="All regions")

        today = datetime.now().date()
        c1,c2 = st.columns(2)
        with c1: d_from = st.date_input("FROM", value=today-timedelta(days=30))
        with c2: d_to   = st.date_input("TO",   value=today)

        avail_src = sorted(set(a["source"] for a in attacks)) if attacks else []
        sel_src   = st.multiselect("SOURCE", avail_src, default=[], placeholder="All sources")
        search    = st.text_input("🔍 SEARCH", placeholder="sapienza, lockbit, napoli…")

        st.markdown("<hr style='border-color:#1e2730;margin:12px 0'>", unsafe_allow_html=True)
        if st.button("↺  RESET"): st.rerun()

        n_new = len(new_ids)
        st.markdown(f"""<div style='font-family:"IBM Plex Mono",monospace;font-size:.56rem;
          color:#586374;margin-top:16px;line-height:1.9;'>
          <span style='color:#30d158'>● {n_new} nuovi eventi</span><br>
          FONTI:<br>
          · Ransomware.live API<br>· Cyberwatch-IT (GitHub)<br>
          · CERT-AgID · CSIRT Italia<br>· Red Hot Cyber · Cybersecurity360<br>
          · BleepingComputer · DataBreaches.net<br>
          · The Hacker News · DarkReading<br>
          · Krebs · SecurityWeek · TheRecord<br>
          · Infosecurity · HelpNet · Threatpost<br>
          · URLhaus · ThreatFox · Feodo Tracker<br>
          <br>
          <span style='color:#ff9f0a'>CACHE TTL:</span> 30s<br>
          <span style='color:#ff3b30'>AUTOREFRESH:</span> {"30s" if HAS_AR else "manuale"}
        </div>""", unsafe_allow_html=True)

    # ── Filtro ────────────────────────────────────────────────────────
    filtered = attacks
    if sel_sev: filtered = [a for a in filtered if a["sev"] in sel_sev]
    if sel_reg: filtered = [a for a in filtered if a["region"] in sel_reg]
    if sel_src: filtered = [a for a in filtered if a["source"] in sel_src]
    filtered = [a for a in filtered
                if d_from <= a["pub"].date() <= d_to]
    if search:
        q = search.lower()
        filtered = [a for a in filtered
                    if q in a["title"].lower() or q in a["summary"].lower()
                    or q in a["place"].lower() or q in a["source"].lower()]

    # ── KPI ──────────────────────────────────────────────────────────
    tot   = len(attacks)
    crit  = sum(1 for a in attacks if a["sev"]=="critical")
    med   = sum(1 for a in attacks if a["sev"]=="medium")
    low   = sum(1 for a in attacks if a["sev"]=="low")
    regs  = len(set(a["region"] for a in attacks))

    k1,k2,k3,k4,k5 = st.columns(5)
    k1.metric("INCIDENTI", tot)
    k2.metric("⬤ CRITICAL", crit)
    k3.metric("⬤ MEDIUM", med)
    k4.metric("⬤ LOW", low)
    k5.metric("REGIONI", regs)

    # ── Status bar ────────────────────────────────────────────────────
    last_ts = attacks[0]["ts"] if attacks else "—"
    nxt = 30 - (int(time.time()) % 30)
    new_html = (f' · <span style="color:#30d158;font-weight:600">+{len(new_ids)} nuovi</span>'
                if new_ids else "")
    st.markdown(
        f"""<div class="sbar"><span class="pulse"></span>
        LIVE · {now.strftime('%d/%m/%Y %H:%M:%S')} IT ·
        {len(filtered)} eventi (filtrati) · {tot} totali ·
        ultimo: {last_ts} · refresh ~{nxt}s{new_html}</div>""",
        unsafe_allow_html=True)

    # ── Layout ────────────────────────────────────────────────────────
    map_col, feed_col = st.columns([3, 1.5], gap="medium")

    with map_col:
        # Converti in tuple per hash → compatibile con st.cache_data
        tups = tuple(
            (a["id"],a["title"],a["summary"],a["link"],a["source"],
             a["sev"],a["lat"],a["lon"],a["place"],a["region"],a["pub"],a["ts"])
            for a in filtered
        )
        fig = build_map(tups)
        st.plotly_chart(fig, use_container_width=True,
                        config={"scrollZoom":True,"displayModeBar":True,"displaylogo":False,
                                "modeBarButtonsToRemove":["select2d","lasso2d"],
                                "toImageButtonOptions":{"format":"png","filename":"italy_cybermap"}})
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.6rem;
          color:#586374;text-align:center;margin-top:-8px;'>
          CLICK MARKER → REPORT · SCROLL TO ZOOM · DRAG TO PAN</div>""",
                    unsafe_allow_html=True)

    with feed_col:
        st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.63rem;
          color:#586374;letter-spacing:.1em;text-transform:uppercase;
          padding-bottom:8px;border-bottom:1px solid #1e2730;margin-bottom:10px;'>
          ◈ INCIDENT FEED</div>""", unsafe_allow_html=True)

        if not filtered:
            st.markdown("""<div style='font-family:"IBM Plex Mono",monospace;font-size:.75rem;
              color:#586374;text-align:center;padding:40px 0;'>
              <div style='font-size:1.4rem;margin-bottom:8px'>◌</div>
              CARICAMENTO IN CORSO…</div>""", unsafe_allow_html=True)
        else:
            html = "".join(_card(a, is_new=(a["id"] in new_ids)) for a in filtered[:150])
            with st.container(height=655):
                st.markdown(html, unsafe_allow_html=True)

    # ── Avviso se no autorefresh ──────────────────────────────────────
    if not HAS_AR:
        st.warning(
            "streamlit-autorefresh non trovato — aggiungi 'streamlit-autorefresh' "
            "a requirements.txt e riavvia l'app per aggiornamento automatico."
        )


main()
