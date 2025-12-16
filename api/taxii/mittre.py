import requests
import logging
import sys
import json

# Configuración de logs
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def load_kev():
    logging.debug("[*] Descargando KEV (CISA)...")
    r = requests.get(KEV_URL, timeout=20)
    r.raise_for_status()
    data = r.json()
    kev_map = {item["cveID"]: item for item in data.get("vulnerabilities", [])}
    logging.debug(f"[*] KEV cargado: {len(kev_map)} CVEs")
    return kev_map

def load_attack_dataset():
    logging.debug("[*] Descargando dataset ATT&CK desde GitHub...")
    r = requests.get(ATTACK_URL, timeout=30)
    r.raise_for_status()
    dataset = r.json()
    logging.debug(f"[*] Dataset cargado: {len(dataset['objects'])} objetos")
    return dataset

def find_attack_techniques(dataset, cve_id):
    techniques = []
    for obj in dataset["objects"]:
        if obj.get("type") == "attack-pattern":
            if "external_references" in obj:
                for ref in obj["external_references"]:
                    if ref.get("source_name") == "cve" and ref.get("external_id") == cve_id:
                        techniques.append({
                            "technique_id": obj.get("external_references", [{}])[0].get("external_id"),
                            "name": obj.get("name"),
                            "description": obj.get("description"),
                            "kill_chain_phases": obj.get("kill_chain_phases", [])
                        })
    return techniques

def main(cve_id):
    # Paso 1: KEV
    kev_map = load_kev()
    kev_info = kev_map.get(cve_id)
    if kev_info:
        logging.info(f"[+] {cve_id} está presente en KEV (explotado activamente)")
        exploited = True
    else:
        logging.warning(f"[ ] {cve_id} no está listado en KEV")
        exploited = False

    # Paso 2: MITRE ATT&CK solo si está en KEV
    attack_data = None
    techniques = []
    if exploited:
        attack_data = load_attack_dataset()
        techniques = find_attack_techniques(attack_data, cve_id)

    # Paso 3: Consolidar resultados
    result = {
        "cve": cve_id,
        "exploited": exploited,
        "kev_details": kev_info,
        "attack_techniques": techniques
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python3 {sys.argv[0]} CVE-XXXX-YYYY")
        sys.exit(1)
    main(sys.argv[1])
