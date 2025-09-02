from __future__ import print_function

import os
import re
import ssl
import json
import html
import time
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS, cross_origin

# SQLAlchemy (modo síncrono)
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter, Retry
from service.ux import crux_site, axe_scan, heuristics_ux
from service.malware import scan_site_malware

load_dotenv()


db_url = os.environ.get("DATABASE_URL", "").strip()
if not db_url:

    db_url = "sqlite:///app.db"

if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)


engine = create_engine(
    db_url, 
    pool_pre_ping=True,
    pool_size=5,          
    max_overflow=10,       
    pool_recycle=3600     
)


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Site(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(512), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    site_id = Column(Integer, ForeignKey("sites.id"), nullable=False)
    score = Column(Integer, nullable=False, default=0)
    report_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


app = Flask(__name__)


ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://analisis.ideidev.com"
]

CORS(
    app,
    resources={r"/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=False, 
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    expose_headers=["Content-Disposition"],
    max_age=86400,  
)

UA = {"User-Agent": "IDEI-Auditor/1.0 (+contacto@idei.example)"}
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"
]


# Timeouts más conservadores (reduce bloqueos en plataformas PaaS)
CONNECT_TIMEOUT = 2
READ_TIMEOUT = 5
REQ_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)

def make_session():
    s = requests.Session()
    retries = Retry(
        total=1,              
        connect=1,
        read=1,
        backoff_factor=0.3,    
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"])
    )
    adapter = HTTPAdapter(
        pool_connections=6,  
        pool_maxsize=6,      
        max_retries=retries
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update(UA)
    return s

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def norm_url(u):
    return u if u.startswith("http") else "https://" + u

def security_headers_missing(headers):
    miss = []
    keys = [k.lower() for k in headers.keys()]
    for h in SECURITY_HEADERS:
        if h.lower() not in keys:
            miss.append(h)
    return miss

def cookie_flag_issues(resp):
    issues = []
    raw = resp.headers.get("Set-Cookie") or ""
    if not raw:
        return issues
    cookies = [raw] if "\n" not in raw else raw.split("\n")
    for ck in cookies:
        l = ck.lower()
        if resp.url.startswith("https://") and "secure" not in l:
            issues.append("Cookie sin Secure")
        if "httponly" not in l:
            issues.append("Cookie sin HttpOnly")
        if "samesite" not in l:
            issues.append("Cookie sin SameSite")
    return sorted(set(issues))

def detect_mixed_content(html_text):
    return sorted(set(re.findall(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)', html_text, re.I)))[:200]

def tls_basic(hostname):
    out = {"ok": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                out["ok"] = True
                out["protocol"] = ssock.version()
                cert = ssock.getpeercert()
                na = cert.get("notAfter")
                if na:
                    exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                    out["days_to_expiry"] = (exp - datetime.utcnow()).days
    except Exception as e:
        out["error"] = str(e)
    return out


def fingerprint_server(headers):
    fp = {"vendor": None, "version": None}
    server = (headers.get("Server") or "").lower()
    if not server:
        return fp
    vendors = ["nginx", "apache", "litespeed", "iis", "cloudflare", "openresty"]
    for v in vendors:
        if v in server:
            fp["vendor"] = v
            m = re.search(r"%s/([\\w\\.\\-]+)" % re.escape(v), server)
            if m:
                fp["version"] = m.group(1)
            break
    return fp

def host_info(netloc):
    info = {"ip": None, "rdns": None}
    try:
        ip = socket.gethostbyname(netloc)
        info["ip"] = ip
        try:
            info["rdns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    except Exception:
        pass
    return info

def detect_waf_cdn(headers):
    w = {"cdn": None, "waf": None}
    h = {k.lower(): v for k, v in headers.items()}
    if "cf-ray" in h or "cf-cache-status" in h or ("server" in h and "cloudflare" in (h["server"] or "").lower()):
        w["cdn"] = "Cloudflare"; w["waf"] = "Cloudflare"
    for k in h.keys():
        if k.startswith("x-sucuri-"):
            w["waf"] = "Sucuri"; break
        if k.startswith("x-wf"):
            w["waf"] = w["waf"] or "Wordfence"
    if "server-timing" in h and isinstance(h["server-timing"], str) and "ak_pv" in h["server-timing"]:
        w["cdn"] = w["cdn"] or "Akamai"
    return w

def try_get(url, path, session, allow_404_ok=False):
    try:
        r = session.get(urljoin(url, path), headers=UA, timeout=10, allow_redirects=True)
        if r.status_code == 200:
            return r.text
        if allow_404_ok and r.status_code in (403, 401):
            return "HTTP %d" % r.status_code
    except Exception:
        pass
    return None

def check_exposed(url, session):
    out = {"robots_txt": None, "sitemap_xml": False, "env_exposed": False, "git_exposed": False, "wp_config_leak": False}


    rob = try_get(url, "/robots.txt", session)
    if rob is not None:
        out["robots_txt"] = "\n".join(rob.splitlines()[:50])


    if try_get(url, "/sitemap.xml", session):
        out["sitemap_xml"] = True


    env_txt = try_get(url, "/.env", session)
    if env_txt:
        low = env_txt.lower()
        if ("app_key=" in low) or ("db_host=" in low) or ("db_name=" in low):
            out["env_exposed"] = True


    git_head = try_get(url, "/.git/HEAD", session)
    if git_head:
        if git_head.strip().startswith("ref: refs/heads/"):
            out["git_exposed"] = True


    wp_copies = ["/wp-config.php~", "/wp-config.php.bak", "/wp-config.php.save", "/wp-config.old", "/wp-config.backup"]
    for p in wp_copies:
        txt = try_get(url, p, session)
        if txt:
            low = txt.lower()
            if "define('db_name'" in low or "define(\"db_name\"" in low or "db_name" in low:
                out["wp_config_leak"] = True
                break

    return out


def wp_enumerate_users(url, session, limit=5):
    authors = []
    for i in range(1, limit+1):
        try:
            r = session.get(url, headers=UA, params={"author": str(i)}, timeout=10, allow_redirects=True)
            if r.history and len(r.history) and "/author/" in r.url:
                slug = r.url.rstrip("/").split("/author/")[-1]
                if slug and slug not in authors:
                    authors.append(slug)
        except Exception:
            pass
    return {"authors": authors}

def rest_details(url, session):
    out = {"users_endpoint_open": None, "routes_count": None}
    try:
        r = session.get(urljoin(url, "/wp-json/"), headers=UA, timeout=10)
        if r.status_code == 200:
            data = r.json()
            routes = data.get("routes", {})
            out["routes_count"] = len(routes) if isinstance(routes, dict) else None
            u = session.get(urljoin(url, "/wp-json/wp/v2/users"), headers=UA, timeout=10)
            out["users_endpoint_open"] = True if u.status_code == 200 else (False if u.status_code in (401,403) else None)
    except Exception:
        pass
    return out

def performance_check(url, session):
    out = {"gzip_br": None, "ttfb_ms": None, "html_size_kb": None, "cache_control": None}
    try:
        t0 = time.perf_counter()
        r = session.get(url, headers=UA, timeout=12, stream=True)
        out["ttfb_ms"] = round((time.perf_counter() - t0) * 1000.0, 1)
        enc = (r.headers.get("Content-Encoding") or "").lower()
        out["gzip_br"] = "br" if "br" in enc else ("gzip" if "gzip" in enc else None)
        out["cache_control"] = r.headers.get("Cache-Control")
        content = r.content[:300000]
        out["html_size_kb"] = round(len(content)/1024.0, 1)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        out["error"] = "Timeout o error de conexión"
    except Exception as e:
        out["error"] = str(e)
    return out


# ============== Seguridad / Reputación externas ==============

def gsb_check(url):
    """
    Google Safe Browsing v4: amenaza si hay matches.
    """
    api_key = os.getenv("GSB_API_KEY")
  
    body = {
        "client": {"clientId": "idei-auditor", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=body, headers=UA, timeout=REQ_TIMEOUT
        )
        data = r.json() if r.ok else {}
        return {"enabled": True, "unsafe": bool(data.get("matches")), "raw": data}
    except Exception as e:
        return {"enabled": True, "unsafe": None, "error": str(e), "raw": None}


def vt_check(url):
    """
    VirusTotal URL analysis (v3). Gratis ~4/min, 500/día.
    Resultado sintético: conteo de 'malicious' y 'suspicious'.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"enabled": False, "malicious": None, "suspicious": None, "raw": None}
    headers = {"x-apikey": api_key, **UA}
    try:
        # 1) enviar análisis (cola)
        post = requests.post("https://www.virustotal.com/api/v3/urls",
                             data={"url": url}, headers=headers, timeout=REQ_TIMEOUT)
        post.raise_for_status()
        analysis_id = (post.json().get("data") or {}).get("id")
        # 2) leer resultado del análisis
        if not analysis_id:
            return {"enabled": True, "malicious": None, "suspicious": None, "raw": post.json()}
        res = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers, timeout=REQ_TIMEOUT
        )
        js = res.json() if res.ok else {}
        stats = (((js.get("data") or {}).get("attributes") or {}).get("stats") or {})
        return {
            "enabled": True,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "raw": js
        }
    except Exception as e:
        return {"enabled": True, "malicious": None, "suspicious": None, "error": str(e), "raw": None}


def urlhaus_check(url):
    """
    URLHaus (sin API key). Revisa si el host tiene URLs maliciosas reportadas.
    """
    try:
        host = urlparse(url).hostname or ""
        r = requests.get(f"https://urlhaus.abuse.ch/api/host/{host}/",
                         headers=UA, timeout=REQ_TIMEOUT)
        js = r.json() if r.ok else {}
        return {"listed": bool(js.get("urls")), "raw": js}
    except Exception:
        return {"listed": None, "raw": None}


def phishtank_check(url):
    """
    PhishTank simple (sin key): solo marca 'desconocido' (puedes integrar su feed con token si quieres).
    """
    try:
        host = urlparse(url).hostname or ""
        return {"host": host, "listed": None}
    except Exception:
        return {"host": None, "listed": None}


# ============== PageSpeed / Core Web Vitals ==============

def pagespeed_fetch(url, strategy="mobile"):
    """
    Google PageSpeed v5. Extrae LCP/CLS/INP + performance score.
    """
    key = os.getenv("PAGESPEED_API_KEY")
    params = {"url": url, "strategy": strategy}
    if key:
        params["key"] = key
    try:
        r = requests.get("https://www.googleapis.com/pagespeedonline/v5/runPagespeed",
                         params=params, headers=UA, timeout=(6, 25))
        js = r.json() if r.ok else {}
        lh = js.get("lighthouseResult") or {}
        audits = lh.get("audits") or {}
        metrics = {
            "lcp": (audits.get("largest-contentful-paint") or {}).get("numericValue"),
            "cls": (audits.get("cumulative-layout-shift") or {}).get("numericValue"),
            "inp": (audits.get("experimental-interaction-to-next-paint") or {}).get("numericValue"),
            "perf_score": (lh.get("categories") or {}).get("performance", {}).get("score"),
        }
        return {"strategy": strategy, "metrics": metrics, "raw": js}
    except Exception as e:
        return {"strategy": strategy, "metrics": {}, "error": str(e), "raw": None}



def privacy_scan(html_text):
    out = {"third_party_scripts": [], "tracking": {"ga": False, "gtm": False, "fbp": False}, "mailto_found": False}
    try:
        domains = re.findall(r'src=["\']https?://([^/"\']+)', html_text, re.I)
        out["third_party_scripts"] = sorted(set(domains))[:30]
        text = html_text.lower()
        out["tracking"]["ga"]  = ("googletag" in text) or ("gtag(" in text) or ("google-analytics" in text)
        out["tracking"]["gtm"] = ("gtm.js" in text) or ("googletagmanager.com" in text)
        out["tracking"]["fbp"] = ("connect.facebook.net" in text) or ("fbq(" in text)
        out["mailto_found"] = ("mailto:" in text)
    except Exception:
        pass
    return out

def seo_extract(html_text):
    out = {"title": None, "meta_description": None, "robots_meta": None}
    try:
        mt = re.search(r'<title[^>]*>(.*?)</title>', html_text, re.I|re.S)
        if mt:
            out["title"] = re.sub(r'\s+', ' ', mt.group(1)).strip()
        md = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', html_text, re.I)
        if md:
            out["meta_description"] = md.group(1).strip()
        rb = re.search(r'<meta[^>]+name=["\']robots["\'][^>]+content=["\']([^"\']+)["\']', html_text, re.I)
        if rb:
            out["robots_meta"] = rb.group(1).strip().lower()
    except Exception:
        pass
    return out

def compute_score_with_details(report):
    score = 100
    reasons = []

    missing = set((report.get("security_headers_missing") or []))
    high = set(["Content-Security-Policy","Strict-Transport-Security"])

    for h in sorted(missing.intersection(high)): reasons.append(("Falta %s" % h, -6))
    for h in sorted(missing - high): reasons.append(("Falta %s" % h, -3))

    if report.get("cookies_flags_issues"): reasons.append(("Cookies sin flags seguros", -5))

    ex = report.get("exposed") or {}
    # penalizaciones críticas solo si hay firma confirmada
    if ex.get("env_exposed"): reasons.append((".env expuesto (confirmado)", -40))
    if ex.get("git_exposed"): reasons.append((".git expuesto (confirmado)", -25))
    if ex.get("wp_config_leak"): reasons.append(("Copias de wp-config expuestas (confirmado)", -40))

    wp = report.get("wp") or {}
    if wp.get("readme_exposed"): reasons.append(("/readme.html expuesto", -5))
    if wp.get("xmlrpc_accessible"): reasons.append(("/xmlrpc.php accesible", -5))

    rest = report.get("rest") or {}
    if rest.get("users_endpoint_open") is True: reasons.append(("/wp/v2/users abierto", -10))

    mc = report.get("mixed_content") or []
    if mc: reasons.append(("Contenido mixto (http en https)", -min(15, len(mc))))

    tls = report.get("tls") or {}
    if not tls.get("ok"): reasons.append(("Problema TLS/Certificado", -10))

    perf = report.get("performance") or {}
    if perf.get("ttfb_ms") and perf["ttfb_ms"] > 800: reasons.append(("TTFB alto (>800ms)", -3))

    for _, delta in reasons: score += int(delta)

    # piso suave si NO hay exposiciones confirmadas
    critical = any([(report.get("exposed") or {}).get(k) for k in ("env_exposed","git_exposed","wp_config_leak")])
    if not critical:
        score = max(score, 10)

    score = max(0, min(100, int(score)))

    if score >= 90: grade, risk = "A", "Low"
    elif score >= 75: grade, risk = "B", "Moderate"
    elif score >= 60: grade, risk = "C", "Elevated"
    elif score >= 45: grade, risk = "D", "High"
    else: grade, risk = "F", "Critical"

    details = [{"reason": r, "penalty": p} for (r, p) in reasons]
    return score, grade, risk, details


def wp_heuristics(html_text):
    data = {
        "is_wordpress": False,
        "version": None,
        "theme_candidates": [],
        "plugins": {},
        "readme_exposed": False,
        "xmlrpc_accessible": None,
        "wp_login_exposed": None,
        "rest_api": None,
    }
    if not data["is_wordpress"]:
        if re.search(r'rel=["\']https://api\.w\.org/["\']', html_text, re.I):
            data["is_wordpress"] = True
            
    mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html_text, re.I)
    if mg and "wordpress" in mg.group(1).lower():
        data["is_wordpress"] = True
        mv = re.search(r"wordpress\s*([\d\.]+)", mg.group(1), re.I)
        if mv:
            data["version"] = mv.group(1)
    for m in re.finditer(r'/wp-content/themes/([a-zA-Z0-9_\-]+)/', html_text):
        name = m.group(1)
        if name not in data["theme_candidates"]:
            data["theme_candidates"].append(name)
    for m in re.finditer(r'/wp-content/plugins/([a-zA-Z0-9_\-]+)/', html_text):
        slug = m.group(1)
        if slug not in data["plugins"]:
            data["plugins"][slug] = []
    return data

def wp_probes(base_url, session):
    tests = ["/wp-login.php","/wp-admin/","/wp-includes/","/wp-json/"]
    out = []
    for t in tests:
        try:
            r = session.get(urljoin(base_url, t), headers=UA, timeout=8, allow_redirects=True)
            if r.status_code in (200,401,403):
                out.append((t, r.status_code))
        except Exception:
            pass
    return out

def check_wp_endpoints(base_url, session, wp_block):
    try:
        r = session.get(urljoin(base_url, "/readme.html"), headers=UA, timeout=10)
        wp_block["readme_exposed"] = (r.status_code == 200 and "wordpress" in r.text.lower())
    except Exception:
        pass
    try:
        r = session.get(urljoin(base_url, "/xmlrpc.php"), headers=UA, timeout=10)
        wp_block["xmlrpc_accessible"] = True if r.status_code in (200,405) else (False if r.status_code in (401,403) else None)
    except Exception:
        pass
    try:
        r = session.get(urljoin(base_url, "/wp-login.php"), headers=UA, timeout=10)
        wp_block["wp_login_exposed"] = (r.status_code in (200,401,403))
    except Exception:
        pass
    try:
        r = session.get(urljoin(base_url, "/wp-json/"), headers=UA, timeout=10)
        if r.status_code == 200:
            wp_block["rest_api"] = True
        elif r.status_code in (401,403):
            wp_block["rest_api"] = False
        else:
            wp_block["rest_api"] = None
    except Exception:
        pass


def check_wp_cron(url, session):
    try:
        r = session.get(urljoin(url, "/wp-cron.php"), headers=UA, timeout=8, allow_redirects=True)
        return r.status_code in (200, 403)
    except Exception:
        return None


def check_oembed(url, session):
    try:
        r = session.get(urljoin(url, "/oembed/1.0/embed"), params={"url": url}, headers=UA, timeout=8)
        return r.status_code == 200
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        return None
    except Exception:
        return None


def check_jwt_endpoint(url, session):
    try:
        r = session.get(urljoin(url, "/wp-json/jwt-auth/v1/token"), headers=UA, timeout=8)
        return r.status_code in (200,401,403)
    except Exception:
        return None


def check_graphql(url, session):
    try:
        r = session.get(urljoin(url, "/graphql"), headers=UA, timeout=8)
        return r.status_code in (200, 400)
    except Exception:
        return None


def check_wc_rest(url, session):
    try:
        r = session.get(urljoin(url, "/wp-json/wc/v3"), headers=UA, timeout=8)
        return True if r.status_code == 200 else (False if r.status_code == 401 else None)
    except Exception:
        return None


def check_acf_rest(url, session):
    try:
        r = session.get(urljoin(url, "/wp-json/acf/v3"), headers=UA, timeout=8)
        return r.status_code in (200, 401, 403)
    except Exception:
        return None


def detect_jquery_version(html_text):
    m = re.search(r'jquery(?:\.min)?\.js(?:\?ver=|.*?-ver[-_])([0-9]+\.[0-9]+(?:\.[0-9]+)?)', html_text, re.I)
    if m: return m.group(1)
    return None


def check_vendor_nodes_map(url, session):
    hints = []
    for p in ["/vendor/", "/node_modules/"]:
        try:
            r = session.get(urljoin(url, p), headers=UA, timeout=8)
            if r.status_code == 200 and ("Index of" in r.text or "<title>Index of" in r.text):
                hints.append(p)
        except Exception:
            pass
    try:
        r = session.get(url, headers=UA, timeout=8)
        maps = re.findall(r'["\']([^"\']+\.map)["\']', r.text, re.I)
        if maps:
            hints.extend(sorted(set(maps[:10])))
    except Exception:
        pass
    return sorted(set(hints))


def robots_sensitive(robots_text):
    if not robots_text:
        return []
    suspicious = []
    for line in robots_text.splitlines():
        l = line.strip().lower()
        if l.startswith("disallow:"):
            if any(w in l for w in ["backup","backups","old","temp","tmp","private",".git","dump","db","sql"]):
                suspicious.append(line.strip())
    return suspicious


def wp_latest_version(session):
    try:
        r = session.get("https://api.wordpress.org/core/version-check/1.7/", headers=UA, timeout=8)
        js = r.json()
        offers = js.get("offers") or []
        if offers:
            return offers[0].get("current")
    except Exception:
        return None
    return None


WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN")
WPSCAN_BASE = "https://wpscan.com/api/v3"

def _wpscan_headers():
    return {"Authorization": "Token token=%s" % WPSCAN_API_TOKEN, "Accept": "application/json"}

def wpscan_api_get(path, params=None, timeout=10):
    if not WPSCAN_API_TOKEN:
        return None
    try:
        resp = requests.get(WPSCAN_BASE + path, headers=_wpscan_headers(), params=params or {}, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None

_VERSION_RE = re.compile(r'[\?&]ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)|\bver[-_]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)

def extract_version_from_html_for_slug(html_text, slug, is_plugin=True):
    try:
        folder = "plugins" if is_plugin else "themes"
        block_re = re.compile(r'/wp-content/%s/%s/[^"\']+' % (folder, re.escape(slug)), re.I)
        candidates = block_re.findall(html_text)
        for c in candidates:
            m = _VERSION_RE.search(c)
            if m:
                return (m.group(1) or m.group(2) or "").strip()
    except Exception:
        pass
    return None

def wpscan_core_vulns(core_version):
    if not core_version:
        return None
    data = wpscan_api_get("/wordpresses/%s" % core_version)
    if not data:
        return None
    vulns = data.get("vulnerabilities") or []
    return {"version": core_version, "count": len(vulns), "items": vulns}

def wpscan_plugin_vulns(slug, version=None):
    data = wpscan_api_get("/plugins/%s" % slug)
    if not data:
        return None
    vulns = data.get("vulnerabilities") or []
    return {"slug": slug, "version": version, "count": len(vulns), "items": vulns}

def wpscan_theme_vulns(slug, version=None):
    data = wpscan_api_get("/themes/%s" % slug)
    if not data:
        return None
    vulns = data.get("vulnerabilities") or []
    return {"slug": slug, "version": version, "count": len(vulns), "items": vulns}

def enrich_with_wpscan(html_text, wp_block):
    out = {"core": None, "plugins": {}, "themes": {}}
    core_ver = (wp_block.get("version") or "").strip()
    out["core"] = wpscan_core_vulns(core_ver) if core_ver else None
    plugins = wp_block.get("plugins") or {}
    for slug in list(plugins.keys()):
        ver = extract_version_from_html_for_slug(html_text, slug, is_plugin=True)
        out["plugins"][slug] = wpscan_plugin_vulns(slug, ver)
    themes = wp_block.get("theme_candidates") or []
    for slug in themes:
        ver = extract_version_from_html_for_slug(html_text, slug, is_plugin=False)
        out["themes"][slug] = wpscan_theme_vulns(slug, ver)
    return out

# ------------------ ANALYZE ------------------
def check_exposed_backups(url, session):
    """
    Escaneo ligero de posibles backups expuestos.
    Optimizaciones:
      - HEAD primero (barato). Si 200 y Content-Length grande, confirmar con GET ligero con stream y early close.
      - Lista reducida de rutas comunes.
      - Límite de 4 segundos de presupuesto local.
      - Max 3 hallazgos para cortar temprano.
    """
    start = time.perf_counter()
    budget_seconds = 4.0
    exposed = []
    backup_files = [
        "/backup.zip", "/backup.sql", "/db.sql", "/website.zip", "/db_backup.sql",
        "/database.sql", "/backup.tar.gz"
    ]
    for path in backup_files:
        if (time.perf_counter() - start) > budget_seconds:
            break
        if len(exposed) >= 3:
            break
        try:
            head = session.head(urljoin(url, path), headers=UA, timeout=REQ_TIMEOUT, allow_redirects=True)
            if head.status_code == 200:
                size = int(head.headers.get("Content-Length", "0") or 0)
                if size and size > 1000000:  # >1MB sospechoso
                    # confirmar con GET stream y cerrar pronto
                    try:
                        g = session.get(urljoin(url, path), headers=UA, timeout=REQ_TIMEOUT, stream=True)
                        g.close()
                        if g.status_code == 200:
                            exposed.append(path)
                    except Exception:
                        pass
        except Exception:
            pass
    return exposed

def check_directory_listing(url, session):
    # Busca si hay indexación de directorios en rutas comunes
    open_dirs = []
    common_dirs = ["/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/", "/uploads/", "/files/", "/backup/", "/backups/", "/tmp/", "/temp/"]
    for path in common_dirs:
        try:
            r = session.get(urljoin(url, path), headers=UA, timeout=8, allow_redirects=True)
            if r.status_code == 200 and ("Index of" in r.text or "<title>Index of" in r.text):
                open_dirs.append(path)
        except Exception:
            pass
    return open_dirs

def check_admin_ajax(url, session):
    """
    Checks if /wp-admin/admin-ajax.php is accessible (status 200 or 400 is considered open).
    """
    try:
        r = session.get(urljoin(url, "/wp-admin/admin-ajax.php"), headers=UA, timeout=8, allow_redirects=True)
        return r.status_code in (200, 400)
    except Exception:
        return None




try:
    from bs4 import BeautifulSoup  # opcional
    _HAS_BS4 = True
except Exception:
    _HAS_BS4 = False

_HEADING_RE = re.compile(r'<h([1-6])\b[^>]*>', re.I)
_P_RE = re.compile(r'<p\b[^>]*>', re.I)
_UL_RE = re.compile(r'<ul\b[^>]*>', re.I)
_OL_RE = re.compile(r'<ol\b[^>]*>', re.I)
_A_RE  = re.compile(r'<a\b[^>]*>', re.I)
_IMG_RE = re.compile(r'<img\b[^>]*>', re.I)

def seo_structure_from_html(html_text: str) -> dict:

    counts = {"h1":0,"h2":0,"h3":0,"h4":0,"p":0,"ul":0,"ol":0,"a":0,"img":0}
    issues = []

    if _HAS_BS4:
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            counts["h1"] = len(soup.find_all("h1"))
            counts["h2"] = len(soup.find_all("h2"))
            counts["h3"] = len(soup.find_all("h3"))
            counts["h4"] = len(soup.find_all("h4"))
            counts["p"]  = len(soup.find_all("p"))
            counts["ul"] = len(soup.find_all("ul"))
            counts["ol"] = len(soup.find_all("ol"))
            counts["a"]  = len(soup.find_all("a"))
            counts["img"]= len(soup.find_all("img"))
        except Exception:
            # fallback a regex si bs4 falla en tiempo de ejecución
            text = html_text or ""
            counts["p"]  = len(_P_RE.findall(text))
            counts["ul"] = len(_UL_RE.findall(text))
            counts["ol"] = len(_OL_RE.findall(text))
            counts["a"]  = len(_A_RE.findall(text))
            counts["img"]= len(_IMG_RE.findall(text))
            for m in _HEADING_RE.finditer(text):
                level = m.group(1)
                if level in ("1","2","3","4"):
                    counts["h"+level] += 1
    else:

        text = html_text or ""
        counts["p"]  = len(_P_RE.findall(text))
        counts["ul"] = len(_UL_RE.findall(text))
        counts["ol"] = len(_OL_RE.findall(text))
        counts["a"]  = len(_A_RE.findall(text))
        counts["img"]= len(_IMG_RE.findall(text))
        for m in _HEADING_RE.finditer(text):
            level = m.group(1)
            if level in ("1","2","3","4"):
                counts["h"+level] += 1

  
    if counts["h1"] == 0:
        issues.append("No hay H1 en la página (debe existir exactamente 1).")
    elif counts["h1"] > 1:
        issues.append("Hay múltiples H1 (%d). Debe existir solo 1." % counts["h1"])
    if (counts["h1"] + counts["h2"] + counts["h3"] + counts["h4"]) == 0:
        issues.append("No hay headings (H1–H4).")
    if counts["h2"] == 0:
        issues.append("No hay H2. Se recomienda estructurar secciones con H2.")

    return {**counts, "issues": issues}





def analyze(url):
    overall_start = time.perf_counter()
    # Presupuesto total por defecto más bajo para evitar 524 del proxy
    overall_budget = float(os.getenv("ANALYZE_BUDGET_SECONDS", "30"))
    # Flags para habilitar checks pesados opcionalmente
    enable_psi = os.getenv("ENABLE_PSI", "0") == "1"
    enable_ux  = os.getenv("ENABLE_UX", "0") == "1"
    enable_mal = os.getenv("ENABLE_MALWARE_SCAN", "0") == "1"
    url = norm_url(url.strip())
    session = make_session()
    
    try:
        r = session.get(url, timeout=REQ_TIMEOUT, allow_redirects=True)
        session.headers.update(UA)
    except Exception as e:
       
        return {
            "url": url,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "error": f"Error de conexión: {str(e)}",
            "wp": {"is_wordpress": False},
            "is_wordpress": False,
            "score": 0,
            "grade": "F",
            "risk_level": "Critical"
        }

    report = {
        "url": url,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "server": None,
        "x_powered_by": None,
        "security_headers_missing": [],
        "cookies_flags_issues": [],
        "mixed_content": [],
        "tls": {},
        "wp": {},
        "warnings": [],
        "server_fingerprint": {},
        "host": {},
        "waf_cdn": {},
        "exposed": {},
        "wp_users": {},
        "rest": {},
        "performance": {},
        "privacy": {},
        "seo": {},
                "admin_ajax_open": None,
                "open_directories": [],
                "exposed_backups": [],
                "oembed_enabled": None,
                "wp_cron_accessible": None,
                "jwt_endpoint": None,
                "graphql_endpoint": None,
                "wc_rest_exposed": None,
                "acf_rest": None,
                "jquery_version": None,
                "robots_sensitive_hints": [],
                "staging_suspected": False,
                "license_exposed": False,
                "wp_config_exposed": False,
                "vulns": None,
        "score": 100
    }


    # Corte temprano si ya no hay presupuesto
    if (time.perf_counter() - overall_start) > overall_budget:
        return {"url": url, "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), "error": "Tiempo agotado al iniciar", "wp": {"is_wordpress": False}, "is_wordpress": False, "score": 0, "grade": "F", "risk_level": "Critical"}

    r = session.get(url, headers=UA, timeout=REQ_TIMEOUT, allow_redirects=True)
    
    # Seguridad / malware (reputación externa)
    report["security_reputation"] = {
        "gsb": gsb_check(url),
        "virustotal": vt_check(url),
        "urlhaus": urlhaus_check(url),
        "phishtank": phishtank_check(url),
    }

    
    report["server"] = r.headers.get("Server")
    report["x_powered_by"] = r.headers.get("X-Powered-By")
    report["security_headers_missing"] = security_headers_missing(r.headers)
    report["cookies_flags_issues"] = cookie_flag_issues(r)
    report["mixed_content"] = detect_mixed_content(r.text)

    host = urlparse(r.url).hostname or urlparse(url).hostname
    if host:
        report["tls"] = tls_basic(host)


    wpdata = wp_heuristics(r.text)
    report["wp"] = wpdata


    if not report["wp"]["is_wordpress"]:
        ps = wp_probes(url, session)
        if ps:
            report["wp"]["is_wordpress"] = True
            report["warnings"].append("Huellas WP detectadas en: " + ", ".join([p for p,_ in ps]))


    check_wp_endpoints(url, session, report["wp"])

    try:
        latest = wp_latest_version(session)
        if latest:
            report["wp"]["latest_version"] = latest
            cur = (report["wp"].get("version") or "").strip()
            if cur and cur != latest:
                report["wp"]["outdated_core"] = True
            else:
                report["wp"]["outdated_core"] = False
    except Exception:
        pass


    report["server_fingerprint"] = fingerprint_server(r.headers)
    report["waf_cdn"] = detect_waf_cdn(r.headers)
    if host:
        report["host"] = host_info(host)
    # Bloques con checks de presupuesto
    if (time.perf_counter() - overall_start) < (overall_budget - 5):
        report["exposed"] = check_exposed(url, session)
    else:
        report["exposed"] = {}

    if (time.perf_counter() - overall_start) < (overall_budget - 5):
        report["wp_users"] = wp_enumerate_users(url, session)
    else:
        report["wp_users"] = {"authors": []}

    if (time.perf_counter() - overall_start) < (overall_budget - 5):
        report["rest"] = rest_details(url, session)
    else:
        report["rest"] = {}

    report["performance"] = performance_check(r.url, session)
    
    # PageSpeed (core web vitals) opcional
    if enable_psi and (time.perf_counter() - overall_start) < (overall_budget - 15):
        _psi_m = pagespeed_fetch(r.url, "mobile")
        _psi_d = pagespeed_fetch(r.url, "desktop")
        report["pagespeed"] = {"mobile": _psi_m, "desktop": _psi_d}
    else:
        report["pagespeed"] = {"mobile": {"error": "disabled"}, "desktop": {"error": "disabled"}}

    # mete C WV resumidas en performance para que tu UI/impresión lo tenga fácil
    psi_all = report.get("pagespeed") or {}
    pm = ((psi_all.get("mobile") or {}).get("metrics") or {})
    pd = ((psi_all.get("desktop") or {}).get("metrics") or {})
    report["performance"]["lcp"] = pm.get("lcp") or pd.get("lcp")
    report["performance"]["cls"] = pm.get("cls") or pd.get("cls")
    report["performance"]["inp"] = pm.get("inp") or pd.get("inp")
    report["performance"]["psi_score_mobile"] = pm.get("perf_score")
    report["performance"]["psi_score_desktop"] = pd.get("perf_score")

    # ===== Malware crawling + DOM render (opcional) =====
    if enable_mal and (time.perf_counter() - overall_start) < (overall_budget - 12):
        try:
            mal = scan_site_malware(r.url, max_pages=50, per_url_budget=0.6)
        except Exception as _e:
            mal = {"infected": None, "urls": [], "summary": {}, "error": str(_e)}
        report["malware_scan"] = mal
        sus = (mal.get("summary") or {}).get("suspected_urls") or []
        sus = [u for u in sus if u != r.url][:10]
        if sus and os.getenv("GSB_API_KEY") and (time.perf_counter() - overall_start) < (overall_budget - 6):
            body = {
                "client": {"clientId": "idei-auditor", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in sus],
                },
            }
            try:
                multi = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={os.getenv('GSB_API_KEY','')}",
                    json=body, headers=UA, timeout=REQ_TIMEOUT
                )
                report.setdefault("security_reputation", {})["gsb_suspects"] = multi.json() if multi.ok else {}
            except Exception as _e:
                report.setdefault("security_reputation", {})["gsb_suspects_error"] = str(_e)
    else:
        report["malware_scan"] = {"enabled": False}


    report["ux"] = {}

    axe = {"enabled": False, "violations": []}
    if enable_ux and (time.perf_counter() - overall_start) < (overall_budget - 20):
        try:
            axe = axe_scan(r.url)
        except Exception as _e:
            axe = {"enabled": True, "violations": [], "error": str(_e)}
    report["ux"]["accessibility"] = {
        "violations_count": len(axe.get("violations") or []),
        "violations": axe.get("violations") or [],
        "passes": axe.get("passes"),
        "incomplete": axe.get("incomplete"),
    }


    crux = {"enabled": False}
    if enable_ux and (time.perf_counter() - overall_start) < (overall_budget - 10):
        try:
            crux = crux_site(r.url)
        except Exception as _e:
            crux = {"enabled": False, "error": str(_e)}
    report["ux"]["crux"] = crux  
    try:
        heu = heuristics_ux(r.text, r.url)
    except Exception as _e:
        heu = {"issues": ["No fue posible analizar heurísticas."], "tips": [], "error": str(_e), "counts": {}}
    report["ux"]["heuristics"] = heu
    recommend = []

    ax = report["ux"]["accessibility"]
    if ax.get("violations"):
        v_by_rule = {}
        for v in ax["violations"]:
            key = f"{v.get('id')}: {v.get('help')}"
            v_by_rule.setdefault(key, 0)
            v_by_rule[key] += len(v.get("nodes") or [])
        top3 = sorted(v_by_rule.items(), key=lambda x: x[1], reverse=True)[:3]
        for k, n in top3:
            recommend.append(f"Accesibilidad · {k} · {n} elementos afectados. Corrige estas reglas WCAG primero.")

    p75 = (crux.get("p75") or {})
    if p75.get("lcp_ms") and p75["lcp_ms"] > 4000:
        recommend.append(f"LCP p75 = {p75['lcp_ms']} ms (lento). Optimiza hero image (AVIF/WebP, preload) y reduce TTFB.")
    if p75.get("inp_ms") and p75["inp_ms"] > 200:
        recommend.append(f"INP p75 = {p75['inp_ms']} ms (alta latencia). Divide JS, prioriza input responsiveness, quita listeners pesados.")
    if p75.get("cls") and p75["cls"] > 0.1:
        recommend.append(f"CLS p75 = {p75['cls']} (inestable). Reserva dimensiones, evita banners que empujan contenido.")

    for issue in (heu.get("issues") or []):
        recommend.append(f"UX: {issue}")
    for tip in (heu.get("tips") or [])[:5]:
        recommend.append(f"Sugerencia: {tip}")

    report["ux"]["recommendations"] = recommend

    
    report["privacy"] = privacy_scan(r.text)
    report["seo"] = seo_extract(r.text)
    report["seo_structure"] = seo_structure_from_html(r.text)
    
    report["jquery_version"] = detect_jquery_version(r.text)
    # Checks de integraciones sujetos a presupuesto
    maybe = lambda margin: (time.perf_counter() - overall_start) < (overall_budget - margin)
    report["acf_rest"] = check_acf_rest(url, session) if maybe(5) else None
    report["wc_rest_exposed"] = check_wc_rest(url, session) if maybe(5) else None
    report["graphql_endpoint"] = check_graphql(url, session) if maybe(5) else None
    report["jwt_endpoint"] = check_jwt_endpoint(url, session) if maybe(5) else None
    report["wp_cron_accessible"] = check_wp_cron(url, session) if maybe(5) else None
    report["oembed_enabled"] = check_oembed(url, session) if maybe(5) else None
    report["exposed_backups"] = check_exposed_backups(url, session) if maybe(5) else []
    report["open_directories"] = check_directory_listing(url, session) if maybe(5) else []
    report["admin_ajax_open"] = check_admin_ajax(url, session) if maybe(5) else None


    if WPSCAN_API_TOKEN:
        try:
            report["vulns"] = enrich_with_wpscan(r.text, report["wp"])
        except Exception:
            report["vulns"] = None


    score, grade, risk, details = compute_score_with_details(report)
    report["score"] = score
    report["grade"] = grade
    report["risk_level"] = risk
    report["score_details"] = details


    report["is_wordpress"] = report.get("wp", {}).get("is_wordpress", False)

    return report

@app.route('/<path:filename>')
def serve_file(filename):
    return send_from_directory(os.path.dirname(__file__), filename)

# ------------------ ENDPOINTS ------------------
@app.route("/health", methods=["GET"])
def health_check():
    """Endpoint simple para health checks de Koyeb"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url") or ""
    if not url:
        return jsonify({"detail": "Falta 'url'"}), 400
    rep = analyze(url)
    if not rep.get("wp",{}).get("is_wordpress"):
        return jsonify({"detail": "El sitio no parece ser WordPress (heurística)."}), 400
    # Asegurar que el reporte tenga is_wordpress al nivel raíz
    rep["is_wordpress"] = rep.get("wp", {}).get("is_wordpress", False)
    return jsonify(rep)

@app.route("/scan-save", methods=["POST"])
@cross_origin(
  origins=["https://analisis.ideidev.com"],
  methods=["POST", "OPTIONS"],
  allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
  max_age=86400,
)
def scan_save():
    data = request.get_json(silent=True) or {}
    url = data.get("url") or ""
    if not url:
        return jsonify({"detail":"Falta 'url'"}), 400
    
    try:
        rep = analyze(url)
        if not rep.get("wp",{}).get("is_wordpress"):
            return jsonify({"detail": "El sitio no parece ser WordPress (heurística)."}), 400
    except Exception as e:
        return jsonify({"detail": f"Error durante el análisis: {str(e)}"}), 500

    db = SessionLocal()
    try:
        # upsert site
        site = db.query(Site).filter(Site.url == url).one_or_none()
        if not site:
            site = Site(url=url)
            db.add(site)
            db.flush()
        r = Report(site_id=site.id, score=int(rep.get("score") or 0), report_json=json.dumps(rep, ensure_ascii=False))
        db.add(r)
        db.commit()
        # Asegurar que el reporte devuelto tenga is_wordpress al nivel raíz
        rep["is_wordpress"] = rep.get("wp", {}).get("is_wordpress", False)
        return jsonify({"id": r.id, "site_id": site.id, "url": site.url, "score": r.score, "created_at": r.created_at.isoformat(), "report": rep})
    finally:
        db.close()

@app.route("/reports", methods=["GET"])
def list_reports():
    limit = int(request.args.get("limit", 100))
    db = SessionLocal()
    try:
        rows = db.query(Report, Site).join(Site, Report.site_id==Site.id).order_by(Report.id.desc()).limit(limit).all()
        out = []
        for rep, site in rows:
            out.append({"id": rep.id, "site_id": site.id, "url": site.url, "score": rep.score, "created_at": rep.created_at.isoformat()})
        return jsonify(out)
    finally:
        db.close()

@app.route("/reports/<int:rid>", methods=["GET"])
def get_report(rid):
    db = SessionLocal()
    try:
        row = db.query(Report, Site).join(Site, Report.site_id==Site.id).filter(Report.id==rid).one_or_none()
        if not row:
            return jsonify({"detail":"Reporte no encontrado"}), 404
        rep_obj, site = row
        rep = json.loads(rep_obj.report_json or "{}")
        # Agregar is_wordpress al nivel raíz para consistencia con el frontend
        rep["is_wordpress"] = rep.get("wp", {}).get("is_wordpress", False)
        return jsonify({"id": rep_obj.id, "site_id": site.id, "url": site.url, "score": rep_obj.score, "created_at": rep_obj.created_at.isoformat(), "report": rep})
    finally:
        db.close()

@app.route("/reports/<int:rid>", methods=["DELETE"])
def delete_report(rid):
    db = SessionLocal()
    try:
        r = db.query(Report).get(rid)
        if not r:
            return jsonify({"detail":"Reporte no encontradop"}), 404
        db.delete(r)
        db.commit()
        return Response(status=204)
    finally:
        db.close()

@app.route("/reports/<int:rid>/print", methods=["GET"])

def print_report(rid):
    db = SessionLocal()
    try:
        row = db.query(Report, Site).join(Site, Report.site_id==Site.id).filter(Report.id==rid).one_or_none()
        if not row:
            return jsonify({"detail":"Reporte no encontradoo"}), 404

        rep_obj, site = row
        rep = json.loads(rep_obj.report_json or "{}")
        url = site.url

        def esc(x):
            try: return html.escape(str(x))
            except Exception: return ""

        wp = rep.get("wp") or {}
        is_wp = bool(wp.get("is_wordpress") or rep.get("is_wordpress"))
        tls = rep.get("tls") or {}
        headers_missing = rep.get("security_headers_missing") or []
        cookies_issues = rep.get("cookies_flags_issues") or []
        mixed = rep.get("mixed_content") or []
        server_fp = rep.get("server_fingerprint") or {}
        waf_cdn = rep.get("waf_cdn") or {}
        host = rep.get("host") or {}
        rest = rep.get("rest") or {}
        perf = rep.get("performance") or {}
        privacy = rep.get("privacy") or {}
        seo = rep.get("seo") or {}
        seo_struct = rep.get("seo_structure") or {}
        exposed = rep.get("exposed") or {}
        robots_hints = rep.get("robots_sensitive_hints") or []
        staging = rep.get("staging_suspected")
        admin_ajax_open = rep.get("admin_ajax_open")
        open_dirs = rep.get("open_directories") or []
        exposed_backups = rep.get("exposed_backups") or []
        oembed_enabled = rep.get("oembed_enabled")
        wp_cron_accessible = rep.get("wp_cron_accessible")
        jwt_endpoint = rep.get("jwt_endpoint")
        graphql_endpoint = rep.get("graphql_endpoint")
        wc_rest_exposed = rep.get("wc_rest_exposed")
        acf_rest = rep.get("acf_rest")
        jquery_version = rep.get("jquery_version")
        license_exposed = rep.get("license_exposed")
        wp_config_exposed = rep.get("wp_config_exposed")
        vulns = rep.get("vulns") or {}

        wp_version = wp.get("version") or "n/d"
        wp_latest = wp.get("latest_version") or "n/d"
        wp_outdated = wp.get("outdated_core")

        theme_candidates = wp.get("theme_candidates") or []
        plugins_map = wp.get("plugins") or {}
        plugins_list = list(plugins_map.keys())

        core_v = vulns.get("core") or {}
        core_count = int(core_v.get("count") or 0)
        plug_v = vulns.get("plugins") or {}
        theme_v = vulns.get("themes") or {}

        def li(items): return "".join("<li>%s</li>" % esc(i) for i in items if i)

        def list_vuln_items(vlist, max_items=10):
            if not vlist:
                return "<li>—</li>"
            items = []
            for v in vlist[:max_items]:
                title = v.get("title") or "Vulnerabilidad"
                cve = (v.get("cve") or [""])[0] if isinstance(v.get("cve"), list) else (v.get("cve") or "")
                cvss_raw = v.get("cvss")
         
                if isinstance(cvss_raw, dict):
                    cvss = cvss_raw.get("score") or cvss_raw.get("vectorString") or ""
                else:
                    cvss = cvss_raw or ""
                badge = (" <span class='chip chip-warn'>CVE %s</span>" % esc(cve)) if cve else ""
                score = (" <span class='muted'>(CVSS %s)</span>" % esc(cvss)) if cvss else ""
                items.append("<li>%s%s%s</li>" % (esc(title), badge, score))
            if len(vlist) > max_items:
                items.append("<li>… y %d más</li>" % (len(vlist)-max_items))
            return "".join(items)


        if mixed:
            rows = "".join("<tr><td>%s</td></tr>" % esc(u) for u in mixed[:20])
            more = "<tr><td>… y %d más</td></tr>" % (len(mixed)-20) if len(mixed) > 20 else ""
            mixed_html = "<div class='muted'>⚠ Recursos http referenciados en https:</div><table class='table'><tbody>%s%s</tbody></table>" % (rows, more)
        else:
            mixed_html = "<span class='ok'>✔ Sin contenido mixto</span>"

        headers_html = "<span class='ok'>✔ Sin ausencias críticas</span>" if not headers_missing else "<ul class='list'>%s</ul>" % li(headers_missing)
        cookies_html = "<span class='ok'>✔ Cookies OK</span>" if not cookies_issues else "<ul class='list'>%s</ul>" % li(cookies_issues)
        robots_html = "<span class='ok'>✔ Nada sospechoso</span>" if not robots_hints else "<ul class='list'>%s</ul>" % li(robots_hints)
        open_dirs_html = "<span class='ok'>✔ No</span>" if not open_dirs else "<ul class='list'>%s</ul>" % li(open_dirs)
        backups_html = "<span class='ok'>✔ No</span>" if not exposed_backups else "<ul class='list'>%s</ul>" % li(exposed_backups)

        plugins_str = " · ".join(plugins_list) if plugins_list else "—"
        themes_str = ", ".join(theme_candidates) if theme_candidates else "—"

        def yn(val, ok="Sí", no="No", dash="—"):
            return ok if val is True else (no if val is False else dash)

        acciones = []
        if headers_missing:
            acciones.append("Configurar cabeceras: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.")
        if cookies_issues:
            acciones.append("Añadir flags Secure, HttpOnly y SameSite a cookies.")
        if exposed.get("robots_txt") and robots_hints:
            acciones.append("Revisar reglas de robots.txt que revelan rutas sensibles o de backups.")
        if exposed.get("env_exposed"): acciones.append("Remover `/.env` del webroot y rotar credenciales.")
        if exposed.get("git_exposed"): acciones.append("Bloquear `/.git/` y despliegue sin metadatos VCS.")
        if exposed.get("wp_config_leak") or wp_config_exposed:
            acciones.append("Eliminar copias y bloquear acceso a `wp-config.php` y derivados.")
        if license_exposed:
            acciones.append("Bloquear `license.txt` si no es necesario públicamente.")
        if open_dirs:
            acciones.append("Deshabilitar listados de directorios (Apache: Options -Indexes / Nginx: autoindex off).")
        if exposed_backups:
            acciones.append("Eliminar/aislar backups y logs del webroot; mover a almacenamiento seguro.")
        if mixed:
            acciones.append("Corregir URLs http→https en tema/plugins y base de datos.")
        if rest.get("users_endpoint_open") is True:
            acciones.append("Restringir `/wp-json/wp/v2/users` a usuarios autenticados.")
        if rest.get("cors_unsafe") is True:
            acciones.append("Restringir CORS (evitar `Access-Control-Allow-Origin: *`).")
        if admin_ajax_open:
            acciones.append("Auditar acciones públicas (wp_ajax_nopriv_*) y aplicar `check_ajax_referer` + capacidades.")
        if wp_cron_accessible:
            acciones.append("Restringir acceso directo a `wp-cron.php` o mover cron al sistema.")
        if jwt_endpoint:
            acciones.append("Endurecer `/wp-json/jwt-auth/v1/token` (rate limit, bloqueo IP, rotación, HTTPS).")
        if graphql_endpoint:
            acciones.append("Endurecer `/graphql` (auth, rate limit, desactivar introspección en prod si aplica).")
        if wc_rest_exposed is True:
            acciones.append("Revisar permisos de WooCommerce REST (datos públicos).")
        if acf_rest in (True, 200, 401, 403):
            acciones.append("Validar campos ACF expuestos vía REST según permisos.")
        if wp_outdated is True:
            acciones.append("Actualizar **núcleo de WordPress** a %s." % esc(wp_latest))
        if jquery_version and str(jquery_version).split(".")[0].isdigit():
            try:
                mj = int(str(jquery_version).split(".")[0])
                if mj < 3: acciones.append("Actualizar jQuery a rama 3.x o superior.")
            except Exception: pass

        acciones_html = "<span class='ok'>✔ Sin acciones críticas pendientes</span>" if not acciones else "<ul class='list'>%s</ul>" % li(acciones)


        plugins_block = ""
        for slug, data in plug_v.items():
            if not data: continue
            cnt = int(data.get("count") or 0)
            ver = data.get("version") or "n/d"
            plugins_block += "<div class='kv'><b>%s</b> v%s · %d vulns</div><ul class='list'>%s</ul>" % (esc(slug), esc(ver), cnt, list_vuln_items(data.get("items") or []))
        if not plugins_block: plugins_block = "<div class='kv'>—</div>"

        themes_block = ""
        for slug, data in theme_v.items():
            if not data: continue
            cnt = int(data.get("count") or 0)
            ver = data.get("version") or "n/d"
            themes_block += "<div class='kv'><b>%s</b> v%s · %d vulns</div><ul class='list'>%s</ul>" % (esc(slug), esc(ver), cnt, list_vuln_items(data.get("items") or []))
        if not themes_block: themes_block = "<div class='kv'>—</div>"

        score_val = int(rep_obj.score or 0)
        score_val = max(0, min(100, score_val))
        grade = rep.get("grade") or "—"
        risk  = rep.get("risk_level") or "—"

        # Tabla estructura SEO
        def row(label, value):
            return "<tr><td>%s</td><td style='text-align:right'><b>%s</b></td></tr>" % (esc(label), esc(value))
        seo_struct_rows = [
            row("H1", seo_struct.get("h1", "—")),
            row("H2", seo_struct.get("h2", "—")),
            row("H3", seo_struct.get("h3", "—")),
            row("H4", seo_struct.get("h4", "—")),
            row("Párrafos (p)", seo_struct.get("p", "—")),
            row("Listas (ul)", seo_struct.get("ul", "—")),
            row("Listas (ol)", seo_struct.get("ol", "—")),
            row("Enlaces (a)", seo_struct.get("a", "—")),
            row("Imágenes (img)", seo_struct.get("img", "—")),
        ]
        seo_struct_table = "<table class='table zebra'><tbody>%s</tbody></table>" % "".join(seo_struct_rows)
        seo_struct_issues = seo_struct.get("issues") or []
        seo_struct_issues_html = ("<ul class='list'>%s</ul>" % "".join("<li>%s</li>" % esc(i) for i in seo_struct_issues)) if seo_struct_issues else "<span class='ok'>✔ Sin observaciones</span>"

        # ===== Resumen Seguridad / Malware (labels bonitos) =====
        sec_rep = rep.get("security_reputation") or {}
        _gsb = (sec_rep.get("gsb") or {})
        _vt  = (sec_rep.get("virustotal") or {})
        _uh  = (sec_rep.get("urlhaus") or {})
        _pt  = (sec_rep.get("phishtank") or {})

        gsb_label = ("Inseguro" if _gsb.get("unsafe") is True else ("Seguro" if _gsb.get("unsafe") is False else ("—" if _gsb.get("enabled") else "No config")))
        vt_mal = str(_vt.get("malicious") if _vt.get("malicious") is not None else "—")
        vt_susp = str(_vt.get("suspicious") if _vt.get("suspicious") is not None else "—")
        uh_label = ("Listado" if _uh.get("listed") is True else ("No" if _uh.get("listed") is False else "—"))
        pt_label = ("Sí" if _pt.get("listed") is True else ("No" if _pt.get("listed") is False else "—"))

        # ===== Resumen PageSpeed (CWV) =====
        psi = rep.get("pagespeed") or {}
        pm  = (psi.get("mobile") or {}).get("metrics") or {}
        pd  = (psi.get("desktop") or {}).get("metrics") or {}

        lcp_ms = (pm.get("lcp") or pd.get("lcp") or "—")
        cls    = (pm.get("cls") or pd.get("cls") or "—")
        inp_ms = (pm.get("inp") or pd.get("inp") or "—")
        psi_score_mobile  = pm.get("perf_score") if pm.get("perf_score") is not None else "—"
        psi_score_desktop = pd.get("perf_score") if pd.get("perf_score") is not None else "—"
        # ===== UX / UI para impresión =====
        ux = rep.get("ux") or {}
        ax = ux.get("accessibility") or {}
        cx = (ux.get("crux") or {}).get("p75") or {}
        heu = ux.get("heuristics") or {}
        recs = ux.get("recommendations") or []

        viol_count = str(ax.get("violations_count") or len(ax.get("violations") or []))
        lcp_p75 = str(cx.get("lcp_ms") or "—")
        inp_p75 = str(cx.get("inp_ms") or "—")
        cls_p75 = str(cx.get("cls") or "—")

        heur_list_html = "<ul class='list'>" + "".join(f"<li>{esc(i)}</li>" for i in (heu.get('issues') or [])) + "</ul>"
        recs_html = "<ol class='list'>" + "".join(f"<li>{esc(i)}</li>" for i in recs) + "</ol>"

       # ===== Malware: variables para impresión =====
        mal = rep.get("malware_scan") or {}
        infected_label = "Sí" if mal.get("infected") else ("No" if mal.get("infected") is False else "—")

        sus_urls = (mal.get("summary") or {}).get("suspected_urls") or []
        urls_html = "<ul class='list'>" + "".join(f"<li>{esc(u)}</li>" for u in sus_urls[:20]) + \
                    ("<li>…</li>" if len(sus_urls) > 20 else "") + "</ul>"

        snips = []
        for e in (mal.get("urls") or [])[:10]:
            if e.get("snippets"):
                for s in e["snippets"][:2]:
                    snips.append(f"<div><b>{esc(e.get('url',''))}</b><pre>{esc(s[:1200])}</pre></div>")
        evid_html = "".join(snips) or "<span class='ok'>✔ Sin evidencias capturadas</span>"

        # ===== Alerta crítica (roja) cuando hay infección o reputación mala =====
        sec_rep = rep.get("security_reputation") or {}
        _gsb_unsafe = ((sec_rep.get("gsb") or {}).get("unsafe") is True)
        _vt_mal = sec_rep.get("virustotal", {}).get("malicious")
        try:
            _vt_mal = int(_vt_mal) if _vt_mal is not None else 0
        except Exception:
            _vt_mal = 0

        sev = (mal or {}).get("severity")
        _mal_infected = (mal or {}).get("infected") is True

        is_critical = _mal_infected or _gsb_unsafe or (_vt_mal >= 1) or (sev in ("high", "critical"))
        if is_critical:
            alert_html = (
                "<div class='alert-bad no-break'>"
                "<div class='alert-title'>ALERTA CRÍTICA · Posible infección activa</div>"
                "<div>Se detectaron indicadores de malware/SEO spam o reputación negativa. "
                "Prioriza limpieza del sitio, revoca accesos, actualiza núcleo/temas/plugins y endurece WAF.</div>"
                "</div>"
            )
        else:
            alert_html = ""


        html_out = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;700;900&display=swap" rel="stylesheet">
<title>Escáner de seguridad WordPress · Reporte #%d</title>
<style>
  :root{
    
    --bg:#f5f7fb; --paper:#ffffff; --ink:#0b1220; --muted:#6a768c;
    --line:#e6eaf2; --brand:#0a5bb7; --brand2:#0fa878; --accent:#111827;
    --ok:#16a34a; --warn:#b45309; --bad:#b91c1c;
  }
  @page{ margin:20mm }
  *{ box-sizing:border-box }
  html,body{ margin:0; padding:0; color:var(--ink);
    font:14px/1.6;
     font-family:'Outfit', system-ui, Avenir, Helvetica, Arial, sans-serif;
    -webkit-print-color-adjust: exact; print-color-adjust: exact;
  }
  body{ background:var(--bg) }
  .wrap{ max-width:960px; margin:0 auto; padding:0 8mm }
  .page{ page-break-after:always; }
  
.page .cover .page .no-break {
  page-break-inside: avoid;
  display: flex;
  flex-direction: column;
  justify-content: center;  
  align-items: center;     
  text-align: center;       
}
@media print {
  .page .cover .no-break {
    min-height: 100%%;       
  }
}
  .hrow{ height:8mm }
    img{
        width:250px;
    }
  /* Portada */
  .cover{ background:var(--paper); border:1px solid var(--line); margin:15mm auto; padding:22mm 18mm; }
  .cover .kicker{ color:#1f2937; font-weight:700; letter-spacing:.08em; text-transform:uppercase; font-size:12px }
  .cover h1{ font-size:44px; line-height:1.1; margin:8mm 0 2mm 0; font-weight:900; color:var(--brand) }
  .cover h2{ font-size:20px; margin:0 0 16mm; color:#1f2937; font-weight:700 }
  .cover .band{ height:12mm; background:var(--brand); color:#fff; display:flex; align-items:center; padding:0 8mm; font-weight:700; border-radius:7mm;}
  .cover .meta{ margin-top:12mm; color:var(--muted) }
  .cover .meta div{ margin:2mm 0 }

  /* Índice */
  .toc{ background:var(--paper); border:1px solid var(--line); padding:10mm 10mm; }
  .toc h2{ font-size:22px; margin:0 0 6mm; font-weight:800 }
  .toc ol{ list-style:none; padding:0; margin:0 }
  .toc li{ display:flex; justify-content:space-between; border-bottom:1px solid var(--line); padding:3mm 0; }
  .toc li b{ color:#0f172a }

  /* Secciones / Tarjetas */
  .section{ background:var(--paper); border:1px solid var(--line); margin:7mm 0; padding: 15px;}
  .section .title{
    background:var(--brand); color:#fff; font-weight:800; letter-spacing:.02em;
    border-radius:7mm;
    padding:3mm 8mm; font-size:16px; display:flex; align-items:center; justify-content:space-between; margin-bottom:2mm;
  }
  pre{
      white-space: pre-wrap;
      overflow-wrap: break-word;
  padding: 10px;
  }
  .section .body{ padding:6mm 8mm; max-width: 100%% !important;}
    .list li {
        max-width: 100%% !important;
    }
  .grid{ display:grid; gap:5mm }
  .cols-2{ grid-template-columns:1fr 1fr }
  .cols-3{ grid-template-columns:repeat(3, 1fr) }

  .kv{ display:inline-block; background:#eef4ff; border:1px solid var(--line); padding:2mm 4mm; margin:1mm; border-radius:6px; }
  .chip{ display:inline-block; background:#eef4ff; border:1px solid var(--line); padding:1mm 4mm; border-radius:999px; font-size:12px; }
  .chip-warn{ background:#fff4ea; border-color:#ffe0c2 }
  .ok{ color:var(--ok) } .warn{ color:var(--warn) } .bad{ color:var(--bad) }
  .muted{ color:var(--muted) }

  .table{ width:100%%; border-collapse:collapse; font-size:13px }
  .table td,.table th{ border-top:1px solid var(--line); padding:3mm 0; word-break:break-word }
  .table.zebra tr:nth-child(even) td{ background:#f9fbff }

  .list{ padding-left:6mm; margin:2mm 0 }
  .list li{ margin:1.5mm 0 }

  /* Barra de score (plana, sin RGBA) */
  .scorebar{ height:8px; background:#e6eaf2; border-radius:999px; overflow:hidden }
  .scorefill{ height:100%%; width:%d%%%%; background:linear-gradient(90deg, var(--brand), var(--brand2)) }

  /* Footer con numeración */
  .footer{ text-align:center; color:var(--muted); font-size:12px; margin:6mm 0 10mm }
  .pnum:after{ counter-increment: page; content: counter(page) }
  
  .alert-bad{
  background: linear-gradient(90deg, #fee2e2, #fecaca);
  border: 1px solid #fecaca;
  color: #7f1d1d;
  padding: 10px 14px;
  border-radius: 12px;
  margin: 8mm 0;
  font-weight: 700;
    }
    .alert-title{ font-size: 15px; margin-bottom: 2mm }

</style>
</head>
<body>

  <div class="wrap">
    <!-- PORTADA -->
    <div class="page cover no-break">
      <div class="kicker">IDEI Auditor</div>
      <div style="text-align:center; margin-bottom:20mm;">
       <img src="/ideidev.png" alt="Logo" />
      </div>
      <h1>Escáner de seguridad WordPress</h1>
      <h2>Resumen ejecutivo del Sitio Analizado</h2>
      <div class="band">Reporte #%d</div>
      <div class="meta">
        <div><b>Sitio:</b> %s</div>
        <div><b>Fecha:</b> %s</div>
        <div><b>Puntaje:</b> %d · <b>Grade:</b> %s · <b>Riesgo:</b> %s</div>
      </div>
    </div>

    <!-- INDICE -->
    <div class="page toc">
      <h2>Índice</h2>
      <ol>
        <li><span>Resumen técnico</span><b>3</b></li>
        <li><span>Servidor / CDN / WAF</span><b>4</b></li>
        <li><span>Host</span><b>4</b></li>
        <li><span>REST & Enumeración</span><b>4</b></li>
        <li><span>Cabeceras y Cookies</span><b>5</b></li>
        <li><span>WordPress</span><b>5</b></li>
        <li><span>Contenido Mixto</span><b>6</b></li>
        <li><span>Archivos/Directorios</span><b>6</b></li>
        <li><span>Performance</span><b>7</b></li>
        <li><span>Privacidad</span><b>7</b></li>
        <li><span>SEO</span><b>8</b></li>
        <li><span>APIs/Integraciones</span><b>9</b></li>
        <li><span>Vulnerabilidades (WPScan)</span><b>10</b></li>
        <li><span>Acciones sugeridas</span><b>11</b></li>
        <li><span>Anexo</span><b>12</b></li>
      </ol>
    </div>

    <!-- RESUMEN -->
    <div class="section no-break">
      <div class="title">Resumen técnico</div>
      <div class="body">
        <div class="grid cols-3">
          <div>
            <div class="kv"><b>WordPress:</b> %s</div>
            <div class="kv"><b>Versión:</b> %s</div>
            <div class="kv"><b>Última:</b> %s</div>
            <div class="kv"><b>Core desactualizado:</b> %s</div>
          </div>
          <div>
            <div class="kv"><b>Servidor:</b> %s</div>
            <div class="kv"><b>Powered-By:</b> %s</div>
            <div class="kv"><b>CDN:</b> %s</div>
            <div class="kv"><b>WAF:</b> %s</div>
          </div>
          <div>
            <div class="kv"><b>TLS:</b> %s</div>
            <div class="kv"><b>Expira (días):</b> %s</div>
            <div class="kv"><b>Puntaje:</b> %d</div>
            <div class="scorebar no-break" style="margin-top:6px"><div class="scorefill"></div></div>
          </div>
        </div>
      </div>
    </div>

   
    %s  

    <!-- BLOQUES TECNICOS -->
    <div class="grid cols-3">
      <div class="section">
        <div class="title">Servidor / CDN / WAF</div>
        <div class="body">
          <div class="kv"><b>Vendor:</b> %s</div>
          <div class="kv"><b>Version:</b> %s</div>
          <div class="kv"><b>CDN:</b> %s</div>
          <div class="kv"><b>WAF:</b> %s</div>
        </div>
      </div>

      <div class="section">
        <div class="title">Host</div>
        <div class="body">
          <div class="kv"><b>IP:</b> %s</div>
          <div class="kv"><b>rDNS:</b> %s</div>
          <div class="kv"><b>Staging:</b> %s</div>
        </div>
      </div>

      <div class="section">
        <div class="title">REST & Enumeración</div>
        <div class="body">
          <div class="kv"><b>Rutas:</b> %s</div>
          <div class="kv"><b>/wp/v2/users:</b> %s</div>
          <div class="kv"><b>CORS:</b> %s</div>
          <div class="kv"><b>/?author=</b> Enumeración probada</div>
        </div>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="section">
        <div class="title">Cabeceras de seguridad</div>
        <div class="body">%s</div>
      </div>
      <div class="section">
        <div class="title">Cookies</div>
        <div class="body">%s</div>
      </div>

      <div class="section">
        <div class="title">WordPress</div>
        <div class="body">
          <ul class="list">
            %s
            %s
            %s
            %s
            <li><b>Temas:</b> %s</li>
            <li><b>Plugins:</b> %s</li>
          </ul>
        </div>
      </div>

      <div class="section">
        <div class="title">Contenido mixto</div>
        <div class="body">%s</div>
      </div>

      <div class="section">
        <div class="title">Archivos/Directorios</div>
        <div class="body">
          <div class="kv"><b>Listados activos:</b></div>%s
          <div class="kv" style="margin-top:3mm"><b>Backups/Logs expuestos:</b></div>%s
          <div class="kv" style="display:block;margin-top:3mm"><b>license.txt expuesto:</b> %s</div>
          <div class="kv" style="display:block;margin-top:2mm"><b>wp-config.php expuesto:</b> %s</div>
        </div>
      </div>

      <div class="section">
        <div class="title">Performance</div>
        <div class="body">
          <div class="kv"><b>TTFB:</b> %s ms</div>
          <div class="kv"><b>Compresión:</b> %s</div>
          <div class="kv"><b>Tamaño HTML:</b> %s KB</div>
          <div class="kv"><b>Cache-Control:</b> %s</div>
        </div>
      </div>

      <div class="section">
        <div class="title">Privacidad</div>
        <div class="body">
          <div class="kv"><b>GA:</b> %s</div>
          <div class="kv"><b>GTM:</b> %s</div>
          <div class="kv"><b>Facebook Pixel:</b> %s</div>
          <div class="kv"><b>mailto:</b> %s</div>
        </div>
      </div>

      <div class="section">
        <div class="title">SEO básico</div>
        <div class="body">
          <div class="kv" style="display:block"><b>Title:</b> %s</div>
          <div class="kv" style="display:block;margin-top:2mm"><b>Description:</b> %s</div>
          <div class="kv" style="display:block;margin-top:2mm"><b>Robots meta:</b> %s</div>
          <div class="kv" style="display:block;margin-top:2mm"><b>robots.txt (pistas sensibles):</b></div>
          %s
        </div>
      </div>

      <div class="section">
        <div class="title">Estructura SEO de la Página</div>
        <div class="body">
          %s
          <div style="margin-top:3mm"><b>Observaciones:</b> %s</div>
        </div>
      </div>

      <div class="section">
        <div class="title">APIs/Integraciones</div>
        <div class="body">
          <div class="kv"><b>admin-ajax:</b> %s</div>
          <div class="kv"><b>wp-cron.php:</b> %s</div>
          <div class="kv"><b>oEmbed:</b> %s</div>
          <div class="kv"><b>JWT:</b> %s</div>
          <div class="kv"><b>GraphQL:</b> %s</div>
          <div class="kv"><b>Woo REST:</b> %s</div>
          <div class="kv"><b>ACF REST:</b> %s</div>
          <div class="kv"><b>jQuery:</b> %s</div>
        </div>
      </div>
    </div>

    <div class="section no-break">
      <div class="title">Vulnerabilidades (WPScan)</div>
      <div class="body">
        <div class="kv"><b>Núcleo:</b> %s vulnerabilidades</div>
        <h3 style="margin:6mm 0 2mm 0;font-size:14px">Plugins</h3>
        %s
        <h3 style="margin:6mm 0 2mm 0;font-size:14px">Temas</h3>
        %s
      </div>
    </div>


    <div class="section no-break">
      <div class="title">Seguridad / Malware</div>
      <div class="body">
        <div class="kv"><b>Google Safe Browsing:</b> %s</div>
        <div class="kv"><b>VirusTotal:</b> Maliciosos %s · Sospechosos %s</div>
        <div class="kv"><b>URLHaus:</b> %s</div>
        <div class="kv"><b>PhishTank:</b> %s</div>
      </div>
    </div>

    <div class="section no-break">
      <div class="title">Core Web Vitals (PageSpeed)</div>
      <div class="body">
        <div class="kv"><b>LCP:</b> %s ms</div>
        <div class="kv"><b>CLS:</b> %s</div>
        <div class="kv"><b>INP:</b> %s ms</div>
        <div class="kv"><b>Score (mobile):</b> %s</div>
        <div class="kv"><b>Score (desktop):</b> %s</div>
      </div>
    </div>

    <div class="section no-break">
      <div class="title">UX/UI y Accesibilidad</div>
      <div class="body">
        <div class="kv"><b>Violaciones WCAG (axe):</b> %s</div>
        <div class="kv"><b>CrUX p75 LCP:</b> %s ms</div>
        <div class="kv"><b>CrUX p75 INP:</b> %s ms</div>
        <div class="kv"><b>CrUX p75 CLS:</b> %s</div>
        <h3 style="margin:6mm 0 2mm 0;font-size:14px">Heurísticas UX detectadas</h3>
        %s
        <h3 style="margin:6mm 0 2mm 0;font-size:14px">Recomendaciones</h3>
        %s
      </div>
    </div>

<div class="section no-break">
  <div class="title">Detección de Malware (crawling + DOM)</div>
  <div class="body">
    <div class="kv"><b>Infección detectada:</b> %s</div>
    <h3 style="margin:6mm 0 2mm 0;font-size:14px">URLs sospechosas</h3>
    %s
    <h3 style="margin:6mm 0 2mm 0;font-size:14px">Evidencias (snippets)</h3>
    %s
  </div>
</div>



    <div class="section no-break">
      <div class="title">Acciones sugeridas</div>
      <div class="body">%s</div>
    </div>

    <div class="section page">
      <div class="title">Anexo · JSON completo</div>
      <div class="body"><pre>%s</pre></div>
    </div>

    <div class="footer">IDEI Auditor · %s · <span class="pnum"></span></div>
  </div>

  <script>
    (function autoPrint() {
      function go() {
        setTimeout(function () { 
          window.print();
        }, 50);
      }
      if (document.readyState === 'complete') go();
      else window.addEventListener('load', go, { once: true });

      window.addEventListener('afterprint', function () {
        // puedes cerrar o redirigir si quieres
        // window.close();
      }, { once: true });
    })();
  </script>
</body>
</html>
""" % (
            # portada + scorebar width
            rep_obj.id, 
            score_val,

            # portada meta
            rep_obj.id,
            esc(url),
            rep_obj.created_at.isoformat(),
            score_val, esc(rep.get("grade") or "—"), esc(rep.get("risk_level") or "—"),

            # resumen técnico
            ("Sí" if is_wp else "No"),
            esc(wp_version),
            esc(wp_latest),
            ("Sí" if wp_outdated else ("No" if wp_outdated is False else "—")),
            esc(rep.get("server","—")),
            esc(rep.get("x_powered_by","—")),
            esc(waf_cdn.get("cdn") or "—"),
            esc(waf_cdn.get("waf") or "—"),
            esc(tls.get("protocol") or "—"),
            esc(str(tls.get("days_to_expiry")) if tls.get("days_to_expiry") is not None else "—"),
            score_val,

alert_html,
            # bloques técnicos
            esc(server_fp.get("vendor") or "—"),
            esc(server_fp.get("version") or "—"),
            esc(waf_cdn.get("cdn") or "—"),
            esc(waf_cdn.get("waf") or "—"),

            esc(host.get("ip") or "—"),
            esc(host.get("rdns") or "—"),
            ("Sí" if staging else "No"),

            esc(rest.get("routes_count") or "—"),
            ("Abierto" if rest.get("users_endpoint_open") is True else ("Restringido" if rest.get("users_endpoint_open") is False else "—")),
            ("Inseguro (*)" if rest.get("cors_unsafe") is True else ("OK" if rest.get("cors_unsafe") is False else "—")),

            # cabeceras / cookies
            headers_html,
            cookies_html,

            # wordpress
            ("<li>/readme.html expuesto</li>" if wp.get("readme_exposed") else ""),
            ("<li>/xmlrpc.php accesible</li>" if wp.get("xmlrpc_accessible") else ""),
            ("<li>/wp-login.php expuesto</li>" if wp.get("wp_login_exposed") else ""),
            ("<li>/wp-json/ disponible</li>" if wp.get("rest_api") else ""),
            esc(themes_str),
            esc(plugins_str),

            # contenido mixto
            mixed_html,

            # archivos/dirs
            open_dirs_html,
            backups_html,
            ("Sí" if license_exposed else "No"),
            ("Sí" if wp_config_exposed else "No"),

            # performance
            esc(str(perf.get("ttfb_ms") or "—")),
            esc(str(perf.get("gzip_br") or "—")),
            esc(str(perf.get("html_size_kb") or "—")),
            esc(str(perf.get("cache_control") or "—")),

            # privacidad
            ("Sí" if ((privacy.get("tracking") or {}).get("ga")) else "No"),
            ("Sí" if ((privacy.get("tracking") or {}).get("gtm")) else "No"),
            ("Sí" if ((privacy.get("tracking") or {}).get("fbp")) else "No"),
            ("Sí" if privacy.get("mailto_found") else "No"),

            # SEO básico + robots
            esc(seo.get("title") or "—"),
            esc(seo.get("meta_description") or "—"),
            esc(seo.get("robots_meta") or "—"),
            robots_html,

            # Estructura SEO
            seo_struct_table, (("<span class='ok'>✔ Sin observaciones</span>") if not seo_struct_issues else ("<ul class='list'>%s</ul>" % "".join("<li>%s</li>" % esc(i) for i in seo_struct_issues))),

            # APIs/Integraciones
            yn(admin_ajax_open),
            yn(wp_cron_accessible),
            yn(oembed_enabled),
            yn(jwt_endpoint),
            yn(graphql_endpoint),
            ("Expuesto" if wc_rest_exposed is True else ("OK" if wc_rest_exposed is False else "—")),
            yn(acf_rest in (True, 200, 401, 403)),
            esc(jquery_version or "—"),

            # WPScan
            str(core_count),
            plugins_block,
            themes_block,

            # Seguridad / Malware (labels y nums)
            gsb_label,
            vt_mal,
            vt_susp,
            uh_label,
            pt_label,

            # PageSpeed (CWV)
            str(lcp_ms),
            str(cls),
            str(inp_ms),
            (str(psi_score_mobile) if psi_score_mobile != "—" else "—"),
            (str(psi_score_desktop) if psi_score_desktop != "—" else "—"),

            # UX/UI y Accesibilidad
            viol_count,
            lcp_p75,
            inp_p75,
            cls_p75,
            heur_list_html,
            recs_html,

             # Malware (3 placeholders NUEVOS en el HTML)
            infected_label,
            urls_html,
            evid_html,
            
            # Acciones
            acciones_html,
            
            # Anexo + footer
            html.escape(json.dumps(rep, ensure_ascii=False, indent=2)),
            esc(url)
        )

        return Response(html_out, mimetype="text/html; charset=utf-8")
    finally:
        db.close()




# Para WSGI
application = app
