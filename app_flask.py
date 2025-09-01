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
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

# SQLAlchemy (modo síncrono)
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
load_dotenv()

# ==================== BASE DE DATOS (Postgres en Neon) ====================

# Lee la URL completa desde env (p.ej. en Koyeb)
# Ejemplo para Koyeb:
# DATABASE_URL=postgresql+psycopg://USER:PASS@HOST/DB?sslmode=require
db_url = os.environ.get("DATABASE_URL", "").strip()
if not db_url:
    # Fallback solo para pruebas locales: SQLite en archivo
    db_url = "sqlite:///app.db"

# Si viene como "postgresql://", cámbialo a "postgresql+psycopg://"
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

# Crea el engine (pool_pre_ping reconecta si se corta)
engine = create_engine(db_url, pool_pre_ping=True)

# Sesiones y Base declarativa
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


# Crea tablas si no usas migraciones (seguro para el primer despliegue)
Base.metadata.create_all(bind=engine)

# ==================== Flask ====================
app = Flask(__name__)

# Permite solo tu frontend de Plesk
CORS(app, resources={r"/api/*": {"origins": "https://analisis.ideidev.com"}})
# (Opcional para dev local)
# CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "https://analisis.ideidev.com"]}})

UA = {"User-Agent": "IDEI-Auditor/1.0 (+contacto@idei.example)"}
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"
]

# Utilidad para obtener/cerrar sesión por petición si la usas en tus rutas:
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ...tus rutas aquí...
# @app.get("/api/hello")
# def hello():
#     return {"ok": True}


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

# ---- Extras plug-and-play ----
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

    # robots.txt (se muestra preview igual que antes)
    rob = try_get(url, "/robots.txt", session)
    if rob is not None:
        out["robots_txt"] = "\n".join(rob.splitlines()[:50])

    # sitemap.xml (200 basta)
    if try_get(url, "/sitemap.xml", session):
        out["sitemap_xml"] = True

    # .env: exigir firmas típicas
    env_txt = try_get(url, "/.env", session)
    if env_txt:
        low = env_txt.lower()
        if ("app_key=" in low) or ("db_host=" in low) or ("db_name=" in low):
            out["env_exposed"] = True

    # .git/HEAD: contenido debería comenzar con "ref: refs/heads/"
    git_head = try_get(url, "/.git/HEAD", session)
    if git_head:
        if git_head.strip().startswith("ref: refs/heads/"):
            out["git_exposed"] = True

    # copias wp-config: exigir que el contenido parezca un wp-config real
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
    except Exception:
        pass
    return out

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



# ---- WordPress ----
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
    # Busca archivos de backup comunes expuestos en la raíz
    exposed = []
    backup_files = [
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/website.zip",
        "/site-backup.zip", "/backup.tar", "/backup.gz", "/backup.bak", "/backup.rar",
        "/db_backup.sql", "/database.sql", "/backup.old", "/backup.copy", "/backup.7z"
    ]
    for path in backup_files:
        try:
            r = session.get(urljoin(url, path), headers=UA, timeout=8, allow_redirects=True)
            if r.status_code == 200 and int(r.headers.get("Content-Length", "0")) > 10000:
                exposed.append(path)
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
    """
    Devuelve:
    {
      "h1": int, "h2": int, "h3": int, "h4": int,
      "p": int, "ul": int, "ol": int, "a": int, "img": int,
      "issues": [str, ...]
    }
    Reglas básicas:
      - Debe existir 1 único H1 (0 o >1 = issue).
      - Recomendable tener H2 (si 0 = issue leve).
      - Si no hay headings (h1-h4) = issue.
    """
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
        # Sin BeautifulSoup (regex básico)
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

    # Validaciones
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
    url = norm_url(url.strip())
    session = requests.Session()
    session.headers.update(UA)

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
        # Nuevos bloques
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

    # 1) Home
    r = session.get(url, headers=UA, timeout=12, allow_redirects=True)
    report["server"] = r.headers.get("Server")
    report["x_powered_by"] = r.headers.get("X-Powered-By")
    report["security_headers_missing"] = security_headers_missing(r.headers)
    report["cookies_flags_issues"] = cookie_flag_issues(r)
    report["mixed_content"] = detect_mixed_content(r.text)

    host = urlparse(r.url).hostname or urlparse(url).hostname
    if host:
        report["tls"] = tls_basic(host)

    # 2) WordPress heuristics
    wpdata = wp_heuristics(r.text)
    report["wp"] = wpdata

    # 3) Probes si aún no es WP
    if not report["wp"]["is_wordpress"]:
        ps = wp_probes(url, session)
        if ps:
            report["wp"]["is_wordpress"] = True
            report["warnings"].append("Huellas WP detectadas en: " + ", ".join([p for p,_ in ps]))

    # 4) Endpoints WP
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

    # 5) Extras
    report["server_fingerprint"] = fingerprint_server(r.headers)
    report["waf_cdn"] = detect_waf_cdn(r.headers)
    if host:
        report["host"] = host_info(host)
    report["exposed"] = check_exposed(url, session)
    report["wp_users"] = wp_enumerate_users(url, session)
    report["rest"] = rest_details(url, session)
    report["performance"] = performance_check(r.url, session)
    report["privacy"] = privacy_scan(r.text)
    report["seo"] = seo_extract(r.text)
    report["seo_structure"] = seo_structure_from_html(r.text)
    
    report["jquery_version"] = detect_jquery_version(r.text)
    report["acf_rest"] = check_acf_rest(url, session)
    report["wc_rest_exposed"] = check_wc_rest(url, session)
    report["graphql_endpoint"] = check_graphql(url, session)
    report["jwt_endpoint"] = check_jwt_endpoint(url, session)
    report["wp_cron_accessible"] = check_wp_cron(url, session)
    report["oembed_enabled"] = check_oembed(url, session)
    report["exposed_backups"] = check_exposed_backups(url, session)
    report["open_directories"] = check_directory_listing(url, session)
    report["admin_ajax_open"] = check_admin_ajax(url, session)

    # 6) Vulnerabilidades (WPScan)
    if WPSCAN_API_TOKEN:
        try:
            report["vulns"] = enrich_with_wpscan(r.text, report["wp"])
        except Exception:
            report["vulns"] = None

    # 7) Score
    score, grade, risk, details = compute_score_with_details(report)
    report["score"] = score
    report["grade"] = grade
    report["risk_level"] = risk
    report["score_details"] = details

    # 8) Agregar is_wordpress al nivel raíz para consistencia con el frontend
    report["is_wordpress"] = report.get("wp", {}).get("is_wordpress", False)

    return report



# ------------------ ENDPOINTS ------------------
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
def scan_save():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url") or ""
    if not url:
        return jsonify({"detail":"Falta 'url'"}), 400
    rep = analyze(url)
    if not rep.get("wp",{}).get("is_wordpress"):
        return jsonify({"detail": "El sitio no parece ser WordPress (heurística)."}), 400

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
            return jsonify({"detail":"Reporte no encontrado"}), 404
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
            return jsonify({"detail":"Reporte no encontrado"}), 404

        rep_obj, site = row
        rep = json.loads(rep_obj.report_json or "{}")
        url = site.url

        def esc(x):
            try:
                return html.escape(str(x))
            except Exception:
                return ""

        # Bloques comunes del JSON
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
        
        # Tabla de estructura SEO
        def row(label, value):
            return "<tr><td>%s</td><td style='text-align:right'><b>%s</b></td></tr>" % (esc(label), esc(value))

        seo_struct_rows = []
        seo_struct_rows.append(row("H1", seo_struct.get("h1", "—")))
        seo_struct_rows.append(row("H2", seo_struct.get("h2", "—")))
        seo_struct_rows.append(row("H3", seo_struct.get("h3", "—")))
        seo_struct_rows.append(row("H4", seo_struct.get("h4", "—")))
        seo_struct_rows.append(row("Párrafos (p)", seo_struct.get("p", "—")))
        seo_struct_rows.append(row("Listas (ul)", seo_struct.get("ul", "—")))
        seo_struct_rows.append(row("Listas (ol)", seo_struct.get("ol", "—")))
        seo_struct_rows.append(row("Enlaces (a)", seo_struct.get("a", "—")))
        seo_struct_rows.append(row("Imágenes (img)", seo_struct.get("img", "—")))
        seo_struct_table = "<table class='table'><tbody>%s</tbody></table>" % "".join(seo_struct_rows)

        seo_struct_issues = seo_struct.get("issues") or []
        seo_struct_issues_html = ("<ul class='list'>%s</ul>" % "".join("<li>%s</li>" % esc(i) for i in seo_struct_issues)) if seo_struct_issues else "<span class='ok'>✔ Sin observaciones</span>"
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

        # WP core latest / outdated
        wp_version = wp.get("version") or "n/d"
        wp_latest = wp.get("latest_version") or "n/d"
        wp_outdated = wp.get("outdated_core")

        # WP temas/plugins (heurística)
        theme_candidates = wp.get("theme_candidates") or []
        plugins_map = wp.get("plugins") or {}
        plugins_list = list(plugins_map.keys())

        # WPScan (detalles)
        core_v = vulns.get("core") or {}
        core_count = int(core_v.get("count") or 0)
        plug_v = vulns.get("plugins") or {}
        theme_v = vulns.get("themes") or {}

        def li(items):
            return "".join("<li>%s</li>" % esc(i) for i in items if i)

        def list_vuln_items(vlist, max_items=10):
            if not vlist:
                return "<li>—</li>"
            items = []
            for v in vlist[:max_items]:
                title = v.get("title") or "Vulnerabilidad"
                cve = (v.get("cve") or [""])[0] if isinstance(v.get("cve"), list) else (v.get("cve") or "")
                cvss = v.get("cvss") or ""
                badge = (" <span class='pill pill-warn'>CVE %s</span>" % esc(cve)) if cve else ""
                score = (" <span class='muted'>(CVSS %s)</span>" % esc(cvss)) if cvss else ""
                items.append("<li>%s%s%s</li>" % (esc(title), badge, score))
            if len(vlist) > max_items:
                items.append("<li>… y %d más</li>" % (len(vlist)-max_items))
            return "".join(items)

        # Mixed content pretty
        if mixed:
            rows = "".join("<tr><td>%s</td></tr>" % esc(u) for u in mixed[:20])
            more = "<tr><td>… y %d más</td></tr>" % (len(mixed)-20) if len(mixed) > 20 else ""
            mixed_html = "<div class='muted'>⚠ Recursos http referenciados en https:</div><table class='table'><tbody>%s%s</tbody></table>" % (rows, more)
        else:
            mixed_html = "<span class='ok'>✔ Sin contenido mixto</span>"

        # Cookies / Headers pretty
        headers_html = "<span class='ok'>✔ Sin ausencias críticas</span>" if not headers_missing else "<ul class='list'>%s</ul>" % li(headers_missing)
        cookies_html = "<span class='ok'>✔ Cookies OK</span>" if not cookies_issues else "<ul class='list'>%s</ul>" % li(cookies_issues)

        # Robots hints pretty
        robots_html = "<span class='ok'>✔ Nada sospechoso</span>" if not robots_hints else "<ul class='list'>%s</ul>" % li(robots_hints)

        # Directorios/backups pretty
        open_dirs_html = "<span class='ok'>✔ No</span>" if not open_dirs else "<ul class='list'>%s</ul>" % li(open_dirs)
        backups_html = "<span class='ok'>✔ No</span>" if not exposed_backups else "<ul class='list'>%s</ul>" % li(exposed_backups)

        # Plugins & temas (string corto)
        plugins_str = " · ".join(plugins_list) if plugins_list else "—"
        themes_str = ", ".join(theme_candidates) if theme_candidates else "—"

        # Woo/GraphQL/JWT/ACF pretty
        def yn(val, ok="Sí", no="No", dash="—"):
            return ok if val is True else (no if val is False else dash)

        # Acciones sugeridas (dinámicas)
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
                if mj < 3:  # heurística simple
                    acciones.append("Actualizar jQuery del tema/plantillas a rama 3.x o superior.")
            except Exception:
                pass

        acciones_html = "<span class='ok'>✔ Sin acciones críticas pendientes</span>" if not acciones else "<ul class='list'>%s</ul>" % li(acciones)

        # WPScan breakdown blocks
        plugins_block = ""
        for slug, data in plug_v.items():
            if not data: 
                continue
            cnt = int(data.get("count") or 0)
            ver = data.get("version") or "n/d"
            plugins_block += "<div class='kv'><b>%s</b> v%s · %d vulns</div><ul class='list'>%s</ul>" % (
                esc(slug), esc(ver), cnt, list_vuln_items(data.get("items") or [])
            )
        if not plugins_block:
            plugins_block = "<div class='kv'>—</div>"

        themes_block = ""
        for slug, data in theme_v.items():
            if not data:
                continue
            cnt = int(data.get("count") or 0)
            ver = data.get("version") or "n/d"
            themes_block += "<div class='kv'><b>%s</b> v%s · %d vulns</div><ul class='list'>%s</ul>" % (
                esc(slug), esc(ver), cnt, list_vuln_items(data.get("items") or [])
            )
        if not themes_block:
            themes_block = "<div class='kv'>—</div>"

        score_val = int(rep_obj.score or 0)
        if score_val < 0: score_val = 0
        if score_val > 100: score_val = 100
        grade = rep.get("grade") or "—"
        risk  = rep.get("risk_level") or "—"
        
                # Desglose de puntaje (score_details)
        score_details = rep.get("score_details") or []
        if score_details:
            # tabla con motivo y penalización
            rows = "".join(
                "<tr><td>%s</td><td style='text-align:right'>%s</td></tr>" %
                (esc(str(item.get("reason", ""))), esc(str(item.get("penalty", ""))))
                for item in score_details
            )
            # suma de penalizaciones (si son numéricas)
            total_pen = 0
            for item in score_details:
                try:
                    p = item.get("penalty", 0)
                    if isinstance(p, (int, float)):
                        total_pen += p
                    else:
                        total_pen += float(p)
                except Exception:
                    pass
            score_details_html = (
                "<table class='table'>"
                "<thead><tr><th>Motivo</th><th>Penalización</th></tr></thead>"
                "<tbody>%s</tbody>"
                "</table>"
                "<div class='muted'>Penalización total aplicada: %s</div>"
            ) % (rows, esc(total_pen))
        else:
            score_details_html = "<span class='ok'>✔ Sin penalizaciones registradas</span>"

        
        
        # Render
        html_out = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Reporte #%d · %s</title>
<style>
  :root {
    --ink:#0c1222; --muted:#62708a; --line:#e7ecf4; --paper:#ffffff; --bg:#f5f7fb;
    --brand:#243b8a; --ok:#2e7d32; --warn:#b26a00; --bad:#b00020;
    --chip:#eef2ff;
  }
  *{box-sizing:border-box}
  html,body{margin:0;padding:0;background:var(--bg);color:var(--ink);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Inter,Roboto,Arial}
  .wrap{max-width:1100px;margin:28px auto;padding:0 18px}
  header{display:flex;align-items:center;gap:12px;margin-bottom:16px}
  .brand{display:flex;align-items:center;gap:10px}
  .brand .logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#2748c7,#0bb9a9)}
  .brand .title{font-weight:800;font-size:20px;letter-spacing:.2px}
  .meta{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);margin-bottom:10px}
  .grid{display:grid;gap:14px}
  @media(min-width:900px){ .cols-2{grid-template-columns:1fr 1fr} .cols-3{grid-template-columns:1fr 1fr 1fr} }
  .card{background:var(--paper);border:1px solid var(--line);border-radius:14px;padding:16px}
  h2.section{font-size:15px;margin:0 0 10px 0;letter-spacing:.3px}
  .list{padding-left:18px;margin:6px 0}
  .list li{margin:4px 0}
  .kv{border:1px solid var(--line);border-radius:10px;padding:6px 10px;background:#fafcff;display:inline-block;margin:4px 6px 0 0}
  .pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line);background:var(--chip);margin-left:6px}
  .pill-warn{background:#fff7e6;border-color:#ffd699}
  .ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
  .scorebox{display:flex;align-items:center;gap:12px;margin:12px 0 4px}
  .scorebar{flex:1;height:10px;background:#edf1f7;border-radius:999px;overflow:hidden}
  .scorefill{height:100%%;width:%d%%;background:linear-gradient(90deg,#7c9aff,#29d3a3)}
  .table{width:100%%;border-collapse:collapse}
  .table td{border-top:1px solid var(--line);padding:6px 0;word-break:break-all}
  footer.note{margin:20px 0 8px;color:var(--muted);font-size:12px;text-align:center}
  @media print { body{background:#fff} .card{break-inside:avoid} .wrap{margin:0 auto} header{margin-bottom:8px} }
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <div class="logo"></div>
        <div class="title">IDEI Auditor · Reporte de Seguridad WordPress</div>
      </div>
    </header>

    <div class="meta">
      <div><b>Sitio:</b> %s</div>
      <div><b>ID:</b> %d</div>
      <div><b>Fecha:</b> %s</div>
    </div>

    <div class="card">
      <h2 class="section">Resumen</h2>
      <div>
        <span class="kv"><b>WordPress:</b> %s</span>
        <span class="kv"><b>Versión:</b> %s</span>
        <span class="kv"><b>Última:</b> %s</span>
        <span class="kv"><b>Core desactualizado:</b> %s</span>
        <span class="kv"><b>Servidor:</b> %s</span>
        <span class="kv"><b>Powered-By:</b> %s</span>
        <span class="kv"><b>Puntaje:</b> %d</span>
        <span class="kv"><b>Grade:</b> %s</span>
        <span class="kv"><b>Riesgo:</b> %s</span>
      </div>
      <div class="scorebox">
        <div class="scorebar"><div class="scorefill"></div></div>
      </div>
    </div>

    <div class="grid cols-3" style="margin-top:14px">
      <div class="card">
        <h2 class="section">Servidor / CDN / WAF</h2>
        <div class="kv"><b>Vendor:</b> %s</div>
        <div class="kv"><b>Version:</b> %s</div>
        <div class="kv"><b>CDN:</b> %s</div>
        <div class="kv"><b>WAF:</b> %s</div>
        <div class="kv"><b>TLS:</b> %s</div>
        <div class="kv"><b>Expira (días):</b> %s</div>
      </div>

      <div class="card">
        <h2 class="section">Host</h2>
        <div class="kv"><b>IP:</b> %s</div>
        <div class="kv"><b>rDNS:</b> %s</div>
        <div class="kv"><b>Staging:</b> %s</div>
      </div>

      <div class="card">
        <h2 class="section">REST & Enumeración</h2>
        <div class="kv"><b>Rutas:</b> %s</div>
        <div class="kv"><b>/wp/v2/users:</b> %s</div>
        <div class="kv"><b>CORS:</b> %s</div>
        <div class="kv"><b>/?author=</b> Enumeración probada</div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:14px">
      <div class="card">
        <h2 class="section">Cabeceras de seguridad</h2>
        %s
      </div>

      <div class="card">
        <h2 class="section">Cookies</h2>
        %s
      </div>

      <div class="card">
        <h2 class="section">WordPress</h2>
        <ul class="list">
          %s
          %s
          %s
          %s
          <li>Temas: %s</li>
          <li>Plugins: %s</li>
        </ul>
      </div>

      <div class="card">
        <h2 class="section">Contenido mixto</h2>
        %s
      </div>

      <div class="card">
        <h2 class="section">Archivos/Directorios</h2>
        <div class="kv"><b>Listados activos:</b></div>
        %s
        <div class="kv"><b>Backups/Logs expuestos:</b></div>
        %s
        <div class="kv"><b>license.txt expuesto:</b> %s</div>
        <div class="kv"><b>wp-config.php expuesto:</b> %s</div>
      </div>

      <div class="card">
        <h2 class="section">Performance</h2>
        <div class="kv"><b>TTFB:</b> %s ms</div>
        <div class="kv"><b>Compresión:</b> %s</div>
        <div class="kv"><b>Tamaño HTML:</b> %s KB</div>
        <div class="kv"><b>Cache-Control:</b> %s</div>
      </div>

      <div class="card">
        <h2 class="section">Privacidad</h2>
        <div class="kv"><b>GA:</b> %s</div>
        <div class="kv"><b>GTM:</b> %s</div>
        <div class="kv"><b>Facebook Pixel:</b> %s</div>
        <div class="kv"><b>mailto:</b> %s</div>
      </div>

      <div class="card">
        <h2 class="section">SEO básico</h2>
        <div class="kv"><b>Title:</b> %s</div>
        <div class="kv"><b>Description:</b> %s</div>
        <div class="kv"><b>Robots meta:</b> %s</div>
        <div class="kv"><b>robots.txt (pistas sensibles):</b></div>
        %s
      </div>
    <div class="card">
  <h2 class="section">Estructura SEO de la Página</h2>
  %s
  <div style="margin-top:8px">
    <div class="kv"><b>Observaciones:</b></div>
    %s
  </div>
</div>

      <div class="card">
        <h2 class="section">APIs/Integraciones</h2>
        <div class="kv"><b>admin-ajax:</b> %s</div>
        <div class="kv"><b>wp-cron.php:</b> %s</div>
        <div class="kv"><b>oEmbed:</b> %s</div>
        <div class="kv"><b>JWT:</b> %s</div>
        <div class="kv"><b>GraphQL:</b> %s</div>
        <div class="kv"><b>Woo REST:</b> %s</div>
        <div class="kv"><b>ACF REST:</b> %s</div>
        <div class="kv"><b>jQuery:</b> %s</div>
      </div>

      <div class="card" style="grid-column: 1/-1">
        <h2 class="section">Vulnerabilidades (WPScan)</h2>
        <div class="kv"><b>Núcleo:</b> %s vulnerabilidades</div>
        <div style="margin-top:8px">
          <h3 style="font-size:13px;margin:10px 0 6px 0">Plugins</h3>
          %s
          <h3 style="font-size:13px;margin:14px 0 6px 0">Temas</h3>
          %s
        </div>
      </div>

      <div class="card" style="grid-column: 1/-1">
        <h2 class="section">Desglose de Puntaje</h2>
        %s
      </div>


      <div class="card" style="grid-column: 1/-1">
        <h2 class="section">Acciones sugeridas</h2>
        %s
      </div>
    </div>

    <div class="card" style="margin-top:14px">
      <h2 class="section">Anexo · JSON completo</h2>
      <pre>%s</pre>
    </div>

    <footer class="note">Generado por IDEI Auditor · %s</footer>
  </div>

  <script>window.print()</script>
</body>
</html>
""" % (
            rep_obj.id, esc(url),
            score_val,
            esc(url), rep_obj.id, rep_obj.created_at.isoformat(),
            ("Sí" if is_wp else "No"),
            esc(wp_version),
            esc(wp_latest),
            ("Sí" if wp_outdated else ("No" if wp_outdated is False else "—")),
            esc(rep.get("server","—")),
            esc(rep.get("x_powered_by","—")),
            score_val,
            grade,
            risk,
            esc(server_fp.get("vendor") or "—"),
            esc(server_fp.get("version") or "—"),
            esc(waf_cdn.get("cdn") or "—"),
            esc(waf_cdn.get("waf") or "—"),
            esc(tls.get("protocol") or "—"),
            esc(str(tls.get("days_to_expiry")) if tls.get("days_to_expiry") is not None else "—"),
            esc(host.get("ip") or "—"),
            esc(host.get("rdns") or "—"),
            ("Sí" if staging else "No"),
            esc(rest.get("routes_count") or "—"),
            ("Abierto" if rest.get("users_endpoint_open") is True else ("Restringido" if rest.get("users_endpoint_open") is False else "—")),
            ("Inseguro (*)" if rest.get("cors_unsafe") is True else ("OK" if rest.get("cors_unsafe") is False else "—")),
            headers_html,
            cookies_html,
            ("<li>/readme.html expuesto</li>" if wp.get("readme_exposed") else ""),
            ("<li>/xmlrpc.php accesible</li>" if wp.get("xmlrpc_accessible") else ""),
            ("<li>/wp-login.php expuesto</li>" if wp.get("wp_login_exposed") else ""),
            ("<li>/wp-json/ disponible</li>" if wp.get("rest_api") else ""),
            esc(themes_str),
            esc(plugins_str),
            mixed_html,
            open_dirs_html,
            backups_html,
            ("Sí" if license_exposed else "No"),
            ("Sí" if wp_config_exposed else "No"),
            esc(str(perf.get("ttfb_ms") or "—")),
            esc(str(perf.get("gzip_br") or "—")),
            esc(str(perf.get("html_size_kb") or "—")),
            esc(str(perf.get("cache_control") or "—")),
            ("Sí" if ((privacy.get("tracking") or {}).get("ga")) else "No"),
            ("Sí" if ((privacy.get("tracking") or {}).get("gtm")) else "No"),
            ("Sí" if ((privacy.get("tracking") or {}).get("fbp")) else "No"),
            ("Sí" if privacy.get("mailto_found") else "No"),
            esc(seo.get("title") or "—"),
            esc(seo.get("meta_description") or "—"),
            esc(seo.get("robots_meta") or "—"),
            robots_html,
            seo_struct_table, seo_struct_issues_html,
            yn(admin_ajax_open),
            yn(wp_cron_accessible),
            yn(oembed_enabled),
            yn(jwt_endpoint),
            yn(graphql_endpoint),
            ("Expuesto" if wc_rest_exposed is True else ("OK" if wc_rest_exposed is False else "—")),
            yn(acf_rest in (True, 200, 401, 403)),
            esc(jquery_version or "—"),
            str(core_count),
            plugins_block,
            themes_block,
            score_details_html,
            acciones_html,
            html.escape(json.dumps(rep, ensure_ascii=False, indent=2)),
            esc(url)
        )

        return Response(html_out, mimetype="text/html; charset=utf-8")
    finally:
        db.close()


# Para WSGI
application = app
