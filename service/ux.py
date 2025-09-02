# services/ux.py
import os, json, re, math, requests, textstat
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

UA = {"User-Agent": "IDEI-Auditor/1.0"}
TIMEOUT = (6, 25)

# ---------- 3.1 CrUX: datos de campo de usuarios Chrome ----------
def crux_site(url: str):
    """
    Devuelve métricas de campo (LCP, INP, CLS) para 'url' o 'origin'.
    """
    key = os.getenv("PAGESPEED_API_KEY")
    if not key:
        return {"enabled": False}
    endpoint = "https://chromeuxreport.googleapis.com/v1/records:query"
    body = {"url": url}
    try:
        r = requests.post(f"{endpoint}?key={key}", headers=UA, json=body, timeout=TIMEOUT)
        js = r.json() if r.ok else {}
    except Exception:
        js = {}

    def _p75(metric):
        try:
            return js["record"]["metrics"][metric]["percentiles"]["p75"]
        except Exception:
            return None

    return {
        "enabled": True,
        "p75": {
            "lcp_ms": _p75("largest_contentful_paint"),
            "inp_ms": _p75("interaction_to_next_paint"),
            "cls":    _p75("cumulative_layout_shift"),
        },
        "raw": js
    }

# ---------- 3.2 Accesibilidad con axe-core en Chromium ----------
AXE_JS_URL = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.8.2/axe.min.js"

def axe_scan(url: str):
    """
    Abre la página en Chromium (headless), inyecta axe y retorna violaciones WCAG.
    """
    res = {"enabled": True, "violations": [], "passes": 0, "incomplete": 0, "inapplicable": 0}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(ignore_https_errors=True, user_agent=UA["User-Agent"])
            page = ctx.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            # Inyectar axe
            page.add_script_tag(url=AXE_JS_URL)
            axe_result = page.evaluate("""async () => {
                return await axe.run(document, {
                  runOnly: ["wcag2a","wcag2aa","wcag21aa","wcag22aa"],
                  resultTypes: ["violations","passes","inapplicable","incomplete"]
                });
            }""")
            browser.close()
        res.update({
            "violations": axe_result.get("violations", []),
            "passes": len(axe_result.get("passes", [])),
            "incomplete": len(axe_result.get("incomplete", [])),
            "inapplicable": len(axe_result.get("inapplicable", [])),
        })
    except Exception as e:
        res.update({"error": str(e)})
    return res

# ---------- 3.3 Heurísticas UX (parsing + reglas) ----------
def heuristics_ux(html_text: str, url: str):
    """
    Reglas prácticas de UX/UI:
    - meta viewport
    - orden y jerarquía de headings
    - legibilidad del contenido principal
    - formularios (labels, required, autocomplete)
    - enlaces/tap-target (longitud de texto, # de links por pantalla)
    - densidad visual (heurística simple)
    """
    soup = BeautifulSoup(html_text or "", "lxml")
    issues = []
    tips = []

    # Viewport
    vp = soup.find("meta", attrs={"name":"viewport"})
    if not vp or "width=device-width" not in (vp.get("content") or ""):
        issues.append("Falta meta viewport correcto para móvil (width=device-width, initial-scale=1).")
        tips.append("Añade: <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")

    # Headings jerarquía
    h_tags = [t.name for t in soup.find_all(re.compile(r"h[1-6]"))]
    if h_tags.count("h1") != 1:
        issues.append(f"Se encontraron {h_tags.count('h1')} H1. Debe haber exactamente 1 H1.")
        tips.append("Mantén 1 H1 y usa H2/H3 para subsecciones.")
    # Orden (no bajar de h2 a h4 sin h3, etc.)
    levels = [int(h[1]) for h in h_tags]
    for i in range(1, len(levels)):
        if levels[i] > levels[i-1] + 1:
            issues.append("Jerarquía de headings salta niveles (p.ej., H2→H4).")
            tips.append("Usa niveles consecutivos para mantener semántica y navegación por lector de pantalla.")
            break

    # Legibilidad (texto principal)
    # simplista: concatenar párrafos y medir Flesch Reading Ease
    text = " ".join([p.get_text(" ", strip=True) for p in soup.find_all("p")])[:20000]
    if text:
        try:
            fre = textstat.flesch_reading_ease(text)
            if fre < 50:
                issues.append(f"Texto con legibilidad exigente (Flesch {fre:.0f}).")
                tips.append("Escribe frases más cortas, usa voz activa y listas con viñetas.")
        except Exception:
            pass
    else:
        issues.append("Pocos párrafos detectados; evalúa incluir más contenido descriptivo.")

    # Formularios
    for form in soup.find_all("form"):
        inputs = form.find_all(["input","select","textarea"])
        for inp in inputs:
            itype = (inp.get("type") or "").lower()
            id_ = inp.get("id")
            lbl = None
            if id_:
                lbl = soup.find("label", attrs={"for": id_})
            if not lbl and itype not in ("hidden","submit","button","image","reset"):
                issues.append("Campo de formulario sin <label> asociado.")
        # Autocomplete
        for fi in form.find_all("input"):
            if not fi.get("autocomplete") and (fi.get("name") or fi.get("id")):
                tips.append("Añade atributos autocomplete en los campos frecuentes (p.ej., email, address-line1, given-name).")
                break

    # Enlaces y tap-targets (heurística)
    links = soup.find_all("a")
    long_links = [a for a in links if len((a.get_text() or "").strip()) > 80]
    if long_links:
        issues.append("Hay enlaces con texto demasiado largo (>80 caracteres).")
        tips.append("Usa textos de enlace concisos y descriptivos.")
    if len(links) > 200:
        issues.append("Demasiados enlaces en la página (>200); puede abrumar al usuario.")
        tips.append("Agrupa enlaces en menús/accordion o paginación.")

    # Densidad visual básica (conteo de elementos interactivos)
    buttons = soup.find_all("button")
    ctas = [b for b in buttons if re.search(r"comprar|suscribir|contactar|enviar|download|add to cart", (b.get_text() or "").lower())]
    if len(ctas) > 6:
        issues.append("Demasiados CTA en una sola vista; compite la atención.")
        tips.append("Prioriza 1–2 CTA principales por sección.")

    return {
        "issues": issues,
        "tips": tips,
        "counts": {
            "headings": len(h_tags),
            "links": len(links),
            "buttons": len(buttons),
            "cta_guess": len(ctas),
        }
    }
