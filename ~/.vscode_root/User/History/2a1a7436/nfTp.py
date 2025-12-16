"""
Generador de reglas Suricata desde CVEs priorizados por IA
"""
import os
import sys
import logging
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

# Asegurar imports
if '/app' not in sys.path:
    sys.path.insert(0, '/app')

from services.rules.sid_allocator import SIDAllocator
from services.rules.suricata_templates import SuricataTemplates

logger = logging.getLogger(__name__)


class SuricataRuleGenerator:
    """
    Generador de reglas Suricata desde inteligencia de vulnerabilidades.
    
    Flujo:
    1. Consulta CVEs desde MongoDB
    2. Obtiene predicciones de IA
    3. Filtra según criterios (risk_level, attack_vector)
    4. Genera reglas Suricata
    5. Escribe en runtime/suricata/rules/generated.rules
    """
    
    def __init__(self, mongo_db, rules_file: str = "/app/runtime/suricata/rules/generated.rules"):
        """
        Inicializa el generador.
        
        Args:
            mongo_db: Instancia de MongoDB
            rules_file: Ruta al archivo de reglas
        """
        self.db = mongo_db
        self.rules_file = Path(rules_file)
        self.sid_allocator = SIDAllocator()
        self.templates = SuricataTemplates()
        
        # Asegurar que el directorio existe
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)
    
    def get_ia_prediction(self, cve_id: str) -> Optional[Dict]:
        """
        Obtiene predicción de IA desde el endpoint interno.
        
        Args:
            cve_id: Identificador CVE
        
        Returns:
            Datos de predicción o None si falla
        """
        try:
            import requests
            # Llamada interna al servicio de IA
            response = requests.get(
                f"http://localhost:5000/api/v1/ia/predict/{cve_id}",
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"IA prediction failed for {cve_id}: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting IA prediction for {cve_id}: {e}")
            return None
    
    def generate_rule_for_cve(self, cve_data: dict) -> Optional[str]:
        """
        Genera una regla Suricata para un CVE específico.
        
        Args:
            cve_data: Documento CVE desde MongoDB
        
        Returns:
            Regla generada o None si no se puede generar
        """
        cve_id = cve_data.get('cve_id')
        
        if not cve_id:
            logger.warning("CVE sin ID, omitiendo")
            return None
        
        # Obtener predicción de IA
        ia_data = self.get_ia_prediction(cve_id)
        
        if not ia_data:
            logger.warning(f"No IA data for {cve_id}, usando datos por defecto")
            # Fallback a datos básicos
            ia_data = {
                'risk_level': 'MEDIUM',
                'attack_vector': 'NETWORK',
                'exploit_probability': 0.5
            }
        
        # Asignar SID
        protocolo = cve_data.get('protocolo_principal')
        sid = self.sid_allocator.allocate_sid(cve_id, protocolo)
        
        # Generar regla usando plantillas
        rule = self.templates.select_template(cve_data, ia_data, sid)
        
        return rule
    
    def generate_rules_from_query(self, query: dict, limit: int = 100) -> List[str]:
        """
        Genera reglas desde una consulta MongoDB.
        
        Args:
            query: Consulta MongoDB
            limit: Límite de resultados
        
        Returns:
            Lista de reglas generadas
        """
        rules = []
        
        try:
            cves = self.db.vulnerabilidades.find(query).limit(limit)
            
            for cve_data in cves:
                rule = self.generate_rule_for_cve(cve_data)
                if rule:
                    rules.append(rule)
                    logger.info(f"✓ Regla generada para {cve_data.get('cve_id')}")
        
        except Exception as e:
            logger.error(f"Error generando reglas: {e}")
        
        return rules
    
    def generate_top_risk_rules(
        self, 
        risk_levels: List[str] = ['CRITICAL', 'HIGH'],
        attack_vectors: List[str] = ['NETWORK'],
        limit: int = 50
    ) -> List[str]:
        """
        Genera reglas para CVEs de alto riesgo priorizados por IA.
        
        Args:
            risk_levels: Niveles de riesgo a incluir
            attack_vectors: Vectores de ataque a incluir
            limit: Número máximo de reglas
        
        Returns:
            Lista de reglas generadas
        """
        rules = []
        
        try:
            # Consultar CVEs con alta probabilidad de explotación
            # Esto requiere que hayamos corrido la IA previamente
            # Por ahora, filtramos por CVSS alto
            query = {
                'cvssv3.score': {'$gte': 7.0},
                'infraestructura_5g_afectada': {'$ne': []}
            }
            
            cves = self.db.vulnerabilidades.find(query).sort('cvssv3.score', -1).limit(limit)
            
            for cve_data in cves:
                cve_id = cve_data.get('cve_id')
                
                # Obtener predicción de IA
                ia_data = self.get_ia_prediction(cve_id)
                
                if not ia_data:
                    continue
                
                # Filtrar por risk_level y attack_vector
                if ia_data.get('risk_level') not in risk_levels:
                    continue
                
                if ia_data.get('attack_vector') not in attack_vectors:
                    continue
                
                # Generar regla
                rule = self.generate_rule_for_cve(cve_data)
                if rule:
                    rules.append(rule)
                    logger.info(f"✓ Top-risk rule for {cve_id} (CVSS: {cve_data.get('cvssv3', {}).get('score')})")
        
        except Exception as e:
            logger.error(f"Error generando reglas top-risk: {e}")
        
        return rules
    
    def write_rules_file(self, rules: List[str], mode: str = 'append'):
        """
        Escribe reglas al archivo de Suricata.
        
        Args:
            rules: Lista de reglas a escribir
            mode: 'append' o 'overwrite'
        """
        try:
            # Header con metadata
            header = [
                "# VulnDB-5G Generated Rules",
                f"# Generated: {datetime.utcnow().isoformat()}Z",
                f"# Total rules: {len(rules)}",
                "#",
                "# This file is AUTO-GENERATED by VulnDB-5G",
                "# DO NOT EDIT MANUALLY",
                "#",
                ""
            ]
            
            write_mode = 'w' if mode == 'overwrite' else 'a'
            
            with open(self.rules_file, write_mode) as f:
                # Si sobreescribimos, añadir header
                if mode == 'overwrite':
                    f.write('\n'.join(header))
                
                # Escribir reglas
                for rule in rules:
                    f.write(rule + '\n')
            
            logger.info(f"✓ {len(rules)} reglas escritas en {self.rules_file}")
        
        except Exception as e:
            logger.error(f"Error escribiendo reglas: {e}")
            raise
    
    def reload_suricata(self):
        """
        Recarga Suricata para aplicar nuevas reglas.
        
        Método 1: suricatasc (si está disponible)
        Método 2: docker restart (fallback)
        """
        import subprocess
        
        try:
            # Intentar reload via suricatasc
            result = subprocess.run(
                ['docker', 'exec', 'vulndb_suricata', 'suricatasc', '-c', 'reload-rules'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info("✓ Suricata rules reloaded successfully")
                return True
            else:
                logger.warning(f"suricatasc reload failed: {result.stderr}")
        
        except Exception as e:
            logger.warning(f"suricatasc not available: {e}")
        
        # Fallback: restart container
        try:
            logger.info("Attempting container restart...")
            result = subprocess.run(
                ['docker', 'restart', 'vulndb_suricata'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info("✓ Suricata container restarted")
                return True
            else:
                logger.error(f"Container restart failed: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error reloading Suricata: {e}")
            return False
    
    def generate_and_deploy(
        self, 
        query: Optional[dict] = None,
        risk_levels: List[str] = ['CRITICAL', 'HIGH'],
        attack_vectors: List[str] = ['NETWORK'],
        limit: int = 50,
        auto_reload: bool = True
    ) -> dict:
        """
        Pipeline completo: generar reglas y desplegar en Suricata.
        
        Args:
            query: Consulta MongoDB personalizada (opcional)
            risk_levels: Niveles de riesgo a incluir
            attack_vectors: Vectores de ataque a incluir
            limit: Límite de reglas
            auto_reload: Si hacer reload automático de Suricata
        
        Returns:
            Diccionario con estadísticas
        """
        start_time = datetime.utcnow()
        
        # Generar reglas
        if query:
            rules = self.generate_rules_from_query(query, limit)
        else:
            rules = self.generate_top_risk_rules(risk_levels, attack_vectors, limit)
        
        # Escribir archivo
        if rules:
            self.write_rules_file(rules, mode='overwrite')
        
        # Reload Suricata
        reload_success = False
        if auto_reload and rules:
            reload_success = self.reload_suricata()
        
        # Estadísticas
        stats = {
            'rules_generated': len(rules),
            'timestamp': start_time.isoformat() + 'Z',
            'rules_file': str(self.rules_file),
            'suricata_reloaded': reload_success,
            'sid_stats': self.sid_allocator.get_stats()
        }
        
        return stats