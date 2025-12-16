import requests
from bs4 import BeautifulSoup
import logging
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime

logger = logging.getLogger("enrichment")

def get_session():
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ============================================================
# NUEVA FUENTE PRINCIPAL: CVE.ORG (JSON OFICIAL) - CORREGIDO
# ============================================================

def _fetch_from_cve_program(cve_id):
    """
    Usa la API oficial de CVE Program v5.
    Endpoint correcto: https://cveawg.mitre.org/api/cve/{cve_id}
    """
    # API oficial del CVE Program
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    session = get_session()

    try:
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (CVE Enrichment Tool)'
        }
        
        resp = session.get(url, timeout=15, headers=headers)
        
        # Si no se encuentra, intentar con la API alternativa de servicios
        if resp.status_code == 404:
            url_alt = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            resp = session.get(url_alt, timeout=15, headers=headers)
            
            if resp.status_code == 200:
                return _parse_nvd_response(resp.json(), cve_id)
        
        if resp.status_code != 200:
            logger.warning(f"⚠️ CVE API devolvió {resp.status_code} para {cve_id}")
            return None

        data = resp.json()
        
        # Navegar en la estructura CVE 5.0
        cna = data.get("containers", {}).get("cna", {})

        # Descripción
        description = ""
        if "descriptions" in cna and len(cna["descriptions"]) > 0:
            description = cna["descriptions"][0].get("value", "")

        # Referencias
        refs = []
        for r in cna.get("references", []):
            href = r.get("url")
            if href:
                refs.append(href)

        # Fecha (published)
        fecha = data.get("cveMetadata", {}).get("datePublished")

        return {
            "descripcion_tecnica": description.strip() if description else "",
            "referencias_mitre": refs,
            "remediacion_mitre": None,
            "fecha_registro_mitre": fecha,
        }

    except requests.exceptions.JSONDecodeError as e:
        logger.error(f"❌ Error parsing JSON desde CVE.org para {cve_id}: {e}")
        logger.debug(f"Response content: {resp.text[:200] if resp else 'N/A'}")
        return None
    except Exception as e:
        logger.error(f"❌ Error obteniendo datos desde CVE.org para {cve_id}: {e}")
        return None


def _parse_nvd_response(data, cve_id):
    """
    Parsea la respuesta de NVD API 2.0
    """
    try:
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        
        cve_data = vulnerabilities[0].get("cve", {})
        
        # Descripción
        description = ""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Referencias
        refs = []
        references = cve_data.get("references", [])
        for ref in references:
            url = ref.get("url")
            if url:
                refs.append(url)
        
        # Fecha
        fecha = cve_data.get("published")
        
        return {
            "descripcion_tecnica": description.strip() if description else "",
            "referencias_mitre": refs,
            "remediacion_mitre": None,
            "fecha_registro_mitre": fecha,
        }
    except Exception as e:
        logger.error(f"❌ Error parsing NVD response para {cve_id}: {e}")
        return None


# ============================================================
# FALLBACK — MITRE (puede estar vacío)
# ============================================================

def _fetch_from_mitre_html(cve_id):
    """
    Fallback al sitio HTML de MITRE (formato antiguo)
    """
    url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    session = get_session()

    try:
        response = session.get(url, timeout=15)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        descripcion_tecnica = ""
        referencias = []
        fecha_mitre = None

        # Description (plantilla antigua)
        descripcion_tag = soup.find("th", string=lambda s: s and "Description" in s)
        if descripcion_tag:
            desc_td = descripcion_tag.find_next("td")
            if desc_td:
                descripcion_tecnica = desc_td.get_text(strip=True)

        # References (plantilla antigua)
        ref_tag = soup.find("th", string=lambda s: s and "Reference" in s)
        if ref_tag:
            ul = ref_tag.find_next("ul")
            if ul:
                for li in ul.find_all("li"):
                    a = li.find("a", href=True)
                    if a:
                        referencias.append(a["href"])

        # Date Record Created
        fecha_tag = soup.find("th", string=lambda s: s and ("Record" in s or "Created" in s))
        if fecha_tag:
            raw = fecha_tag.find_next("td")
            if raw:
                raw_text = raw.get_text(strip=True)
                try:
                    fecha_mitre = datetime.strptime(raw_text, "%Y%m%d").strftime("%Y-%m-%d")
                except:
                    pass

        # Si está vacío, MITRE no tiene datos
        if not descripcion_tecnica and not referencias:
            logger.debug(f"MITRE HTML no tiene datos útiles para {cve_id}")

        return {
            "descripcion_tecnica": descripcion_tecnica,
            "referencias_mitre": referencias,
            "remediacion_mitre": None,
            "fecha_registro_mitre": fecha_mitre
        }

    except Exception as e:
        logger.error(f"❌ Error en MITRE HTML para {cve_id}: {e}")
        return None


# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================

def enriquecer_desde_mitre(cve_id):
    """
    Enriquece datos de CVE desde múltiples fuentes:
    1. CVE Program API (oficial)
    2. NVD API (alternativa)
    3. MITRE HTML (fallback)
    """

    # 1) Intentar CVE Program (fuente oficial actual)
    datos = _fetch_from_cve_program(cve_id)

    if datos and (datos["descripcion_tecnica"] or datos["referencias_mitre"]):
        # logger.info(f"✓ Datos obtenidos desde CVE Program para {cve_id}")
        return datos

    # 2) Fallback a MITRE HTML
    logger.info(f"⤷ Intentando MITRE HTML como fallback para {cve_id}")
    datos_mitre = _fetch_from_mitre_html(cve_id)
    
    if datos_mitre and (datos_mitre["descripcion_tecnica"] or datos_mitre["referencias_mitre"]):
        # logger.info(f"✓ Datos obtenidos desde MITRE HTML para {cve_id}")
        return datos_mitre

    # 3) Nada encontrado
    logger.warning(f"⚠️ No se pudo enriquecer {cve_id} desde ninguna fuente")

    return {
        "descripcion_tecnica": "",
        "referencias_mitre": [],
        "remediacion_mitre": None,
        "fecha_registro_mitre": None
    }