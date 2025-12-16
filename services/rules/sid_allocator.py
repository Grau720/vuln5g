"""
SID Allocator para reglas Suricata
Gestiona la asignación de SIDs únicos y persistentes
"""
import os
import json
from pathlib import Path
from typing import Optional

class SIDAllocator:
    """
    Asignador de SIDs para reglas Suricata.
    
    Rango reservado para VulnDB-5G: 9000000 - 9999999
    - 9000000-9099999: Reglas HTTP/2 y SBA
    - 9100000-9199999: Reglas PFCP
    - 9200000-9299999: Reglas NGAP
    - 9300000-9399999: Reglas Diameter
    - 9400000-9499999: Reglas SIP
    - 9500000-9599999: Reglas genéricas de red
    - 9600000-9999999: Reserva futura
    """
    
    SID_RANGES = {
        'http2': (9000000, 9099999),
        'pfcp': (9100000, 9199999),
        'ngap': (9200000, 9299999),
        'diameter': (9300000, 9399999),
        'sip': (9400000, 9499999),
        'generic': (9500000, 9599999),
    }
    
    def __init__(self, state_file: str = "/app/runtime/suricata/rules/sid_state.json"):
        """
        Inicializa el asignador de SIDs.
        
        Args:
            state_file: Ruta al archivo de estado JSON
        """
        self.state_file = Path(state_file)
        self.state = self._load_state()
    
    def _load_state(self) -> dict:
        """Carga el estado persistente de SIDs."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Error cargando estado SID: {e}")
        
        # Estado inicial
        return {
            'last_sid': {
                'http2': self.SID_RANGES['http2'][0],
                'pfcp': self.SID_RANGES['pfcp'][0],
                'ngap': self.SID_RANGES['ngap'][0],
                'diameter': self.SID_RANGES['diameter'][0],
                'sip': self.SID_RANGES['sip'][0],
                'generic': self.SID_RANGES['generic'][0],
            },
            'cve_to_sid': {}  # CVE-ID -> [SIDs]
        }
    
    def _save_state(self):
        """Guarda el estado persistente."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            print(f"⚠️  Error guardando estado SID: {e}")
    
    def get_protocol_category(self, protocolo: Optional[str]) -> str:
        """
        Determina la categoría de protocolo para asignación de SID.
        
        Args:
            protocolo: Nombre del protocolo (HTTP/2, PFCP, etc.)
        
        Returns:
            Categoría de SID ('http2', 'pfcp', etc.)
        """
        if not protocolo:
            return 'generic'
        
        protocolo_lower = protocolo.lower()
        
        if 'http' in protocolo_lower or 'sba' in protocolo_lower or 'rest' in protocolo_lower:
            return 'http2'
        elif 'pfcp' in protocolo_lower or 'gtp' in protocolo_lower:
            return 'pfcp'
        elif 'ngap' in protocolo_lower or 'sctp' in protocolo_lower:
            return 'ngap'
        elif 'diameter' in protocolo_lower:
            return 'diameter'
        elif 'sip' in protocolo_lower:
            return 'sip'
        else:
            return 'generic'
    
    def allocate_sid(self, cve_id: str, protocolo: Optional[str] = None) -> int:
        """
        Asigna un SID único para un CVE.
        
        Args:
            cve_id: Identificador CVE
            protocolo: Protocolo asociado
        
        Returns:
            SID asignado
        """
        category = self.get_protocol_category(protocolo)
        
        # Verificar si ya existe SID para este CVE
        if cve_id in self.state['cve_to_sid']:
            return self.state['cve_to_sid'][cve_id][0]
        
        # Obtener siguiente SID del rango
        current_sid = self.state['last_sid'][category]
        next_sid = current_sid + 1
        
        # Verificar límite del rango
        min_sid, max_sid = self.SID_RANGES[category]
        if next_sid > max_sid:
            raise ValueError(f"Rango SID agotado para categoría {category}")
        
        # Actualizar estado
        self.state['last_sid'][category] = next_sid
        
        if cve_id not in self.state['cve_to_sid']:
            self.state['cve_to_sid'][cve_id] = []
        self.state['cve_to_sid'][cve_id].append(next_sid)
        
        self._save_state()
        
        return next_sid
    
    def get_sids_for_cve(self, cve_id: str) -> list:
        """
        Obtiene todos los SIDs asociados a un CVE.
        
        Args:
            cve_id: Identificador CVE
        
        Returns:
            Lista de SIDs
        """
        return self.state['cve_to_sid'].get(cve_id, [])
    
    def get_stats(self) -> dict:
        """
        Obtiene estadísticas de uso de SIDs.
        
        Returns:
            Diccionario con estadísticas
        """
        stats = {
            'total_cves': len(self.state['cve_to_sid']),
            'total_rules': sum(len(sids) for sids in self.state['cve_to_sid'].values()),
            'by_category': {}
        }
        
        for category, (min_sid, max_sid) in self.SID_RANGES.items():
            used = self.state['last_sid'][category] - min_sid
            total = max_sid - min_sid + 1
            stats['by_category'][category] = {
                'used': used,
                'available': total - used,
                'percentage': round((used / total) * 100, 2)
            }
        
        return stats