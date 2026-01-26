"""
Engine de correlación para agrupar alertas en ataques coordinados

V2.1 - Asset-Aware: Los grupos ahora conocen el asset destino

CAMBIOS V2.1:
- target_asset persiste en attack_groups
- Auto-repair: grupos sin asset se actualizan al consultarlos
- Actualización incremental cuando aparece asset info

LÓGICA ASSET:
- _create_new_group(): Extrae target_asset de la alerta
- _update_group(): Actualiza asset si viene en nueva alerta
- _reopen_group(): Actualiza asset si viene en alerta
- _enrich_group_with_asset(): Repara grupo consultando sus alertas
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from bson import ObjectId

logger = logging.getLogger(__name__)

# Configuración
CORRELATION_WINDOW_HOURS = 1
AUTO_RESOLVE_DAYS = 7

# Mapeo de attack_type a labels legibles para grupos
ATTACK_TYPE_LABELS = {
    'Inyección SQL': 'SQLi',
    'RCE': 'RCE',
    'XSS': 'XSS',
    'CSRF': 'CSRF',
    'Path Traversal': 'PathTraversal',
    'Autenticación': 'AuthBypass',
    'Buffer Overflow': 'BufferOverflow',
    'Inyección de Comandos': 'CmdInjection',
    'XXE': 'XXE',
    'Deserialización Insegura': 'Deserialization',
    None: 'Unknown',
    '': 'Unknown'
}

class CorrelationEngine:
    """
    Motor de correlación de alertas en grupos de ataque.
    
    V2.1: Agrupa por (src_ip, dest_ip, attack_type) + PERSISTE target_asset
    """
    
    def __init__(self, mongo_db):
        self.db = mongo_db
        self.alerts_col = mongo_db['alerts']
        self.groups_col = mongo_db['attack_groups']
    
    def create_indexes(self):
        """Crear índices optimizados para la nueva estructura"""
        try:
            # Índices en alerts - incluir attack_type
            self.alerts_col.create_index([
                ('src_ip', 1),
                ('dest_ip', 1),
                ('vuln_type', 1),
                ('timestamp', -1)
            ])
            self.alerts_col.create_index([('correlation_group_id', 1)])
            self.alerts_col.create_index([('timestamp', -1)])
            self.alerts_col.create_index([('vuln_type', 1)])
            
            # Índices en attack_groups - usar attack_type
            self.groups_col.create_index([
                ('src_ip', 1),
                ('dest_ip', 1),
                ('attack_type', 1)
            ])
            self.groups_col.create_index([('status', 1)])
            self.groups_col.create_index([('last_alert', -1)])
            self.groups_col.create_index([('created_at', -1)])
            self.groups_col.create_index([('attack_type', 1)])
            self.groups_col.create_index([('severity', 1)])
            
            logger.info("✅ Índices de correlación V2.1 creados")
        except Exception as e:
            logger.error(f"Error creando índices: {e}")
    
    def _normalize_attack_type(self, alert: Dict) -> str:
        """
        Normaliza el tipo de ataque desde la alerta.
        
        Prioridad:
        1. vuln_type (ya extraído en alerts_api)
        2. Inferir desde signature
        3. Fallback a 'Unknown'
        """
        # 1. Usar vuln_type si existe
        vuln_type = alert.get('vuln_type')
        if vuln_type:
            return vuln_type
        
        # 2. Inferir desde signature
        signature = alert.get('alert', {}).get('signature', '').lower()
        
        if any(x in signature for x in ['sql', 'sqli']):
            return 'Inyección SQL'
        elif any(x in signature for x in ['rce', 'command execution', 'remote code']):
            return 'RCE'
        elif any(x in signature for x in ['xss', 'cross-site script', 'script injection']):
            return 'XSS'
        elif any(x in signature for x in ['path traversal', 'directory traversal', 'pathtraversal']):
            return 'Path Traversal'
        elif any(x in signature for x in ['csrf', 'request forgery']):
            return 'CSRF'
        elif any(x in signature for x in ['auth', 'privilege', 'access control']):
            return 'Autenticación'
        elif any(x in signature for x in ['buffer overflow', 'overflow']):
            return 'Buffer Overflow'
        elif any(x in signature for x in ['command injection']):
            return 'Inyección de Comandos'
        elif any(x in signature for x in ['xxe', 'xml external']):
            return 'XXE'
        
        # 3. Fallback
        return 'Unknown'
    
    def _get_attack_label(self, attack_type: str) -> str:
        """Obtiene label corto para el grupo"""
        return ATTACK_TYPE_LABELS.get(attack_type, 'Unknown')
    
    def _extract_target_asset_from_alert(self, alert: Dict) -> Optional[Dict]:
        """
        Extrae información del asset destino desde la alerta.
        
        Returns:
            Dict con asset info o None
        """
        target_asset = alert.get('target_asset')
        
        if target_asset and isinstance(target_asset, dict):
            # Limpiar None values
            return {k: v for k, v in target_asset.items() if v is not None}
        
        return None
    
    def correlate_alert(self, alert: Dict) -> Optional[ObjectId]:
        """
        Correlaciona una alerta con un grupo existente o crea uno nuevo.
        
        V2.1: Persiste target_asset en el grupo.
        
        Lógica:
        1. Normalizar attack_type desde la alerta
        2. Buscar grupo 'active'/'re-opened' con misma firma (dentro de ventana)
        3. Si existe → actualizar (incluyendo asset si viene)
        4. Si hay grupo 'resolved' con misma firma → reabrirlo (incluyendo asset)
        5. Si no hay nada → crear nuevo grupo (con asset si viene)
        
        Returns:
            ObjectId del grupo
        """
        try:
            src_ip = alert.get('src_ip')
            dest_ip = alert.get('dest_ip')
            timestamp = alert.get('timestamp')
            
            # Normalizar tipo de ataque
            attack_type = self._normalize_attack_type(alert)
            
            # Guardar attack_type en la alerta para referencia
            alert['attack_type'] = attack_type
            
            if not all([src_ip, dest_ip, timestamp]):
                logger.warning(f"Alerta incompleta para correlación: src={src_ip}, dest={dest_ip}")
                return None
            
            # 1. Buscar grupo activo con misma firma
            existing_group = self._find_existing_group(src_ip, dest_ip, attack_type, timestamp)
            
            if existing_group:
                group_id = existing_group['_id']
                self._update_group(group_id, alert)
                logger.debug(f"Alerta añadida a grupo: {existing_group['group_id']}")
                return group_id
            
            # 2. Buscar grupo resuelto para reabrir
            resolved_group = self._find_resolved_group(src_ip, dest_ip, attack_type)
            
            if resolved_group:
                group_id = resolved_group['_id']
                self._reopen_group(group_id, alert)
                logger.warning(f"⚠️ Grupo reabierto: {resolved_group['group_id']}")
                return group_id
            
            # 3. Crear nuevo grupo
            group_id = self._create_new_group(alert, src_ip, dest_ip, attack_type)
            return group_id
        
        except Exception as e:
            logger.error(f"Error correlacionando alerta: {e}", exc_info=True)
            return None
    
    def _find_existing_group(self, src_ip: str, dest_ip: str,
                            attack_type: str, timestamp: str) -> Optional[Dict]:
        """
        Busca grupo ACTIVO con la misma firma de ataque.
        
        Criterios V2:
        - Misma IP origen
        - Misma IP destino
        - Mismo tipo de ataque (attack_type)
        - Status: 'active' o 're-opened'
        - Última alerta dentro de ventana de correlación
        """
        try:
            timestamp_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            window_start = timestamp_dt - timedelta(hours=CORRELATION_WINDOW_HOURS)
            
            group = self.groups_col.find_one({
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'attack_type': attack_type,
                'last_alert': {'$gte': window_start},
                'status': {'$in': ['active', 're-opened']}
            })
            
            return group
        
        except Exception as e:
            logger.error(f"Error buscando grupo existente: {e}")
            return None
    
    def _find_resolved_group(self, src_ip: str, dest_ip: str,
                            attack_type: str) -> Optional[Dict]:
        """
        Busca grupo RESUELTO con misma firma para reabrirlo.
        """
        try:
            group = self.groups_col.find_one(
                {
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'attack_type': attack_type,
                    'status': 'resolved'
                },
                sort=[('last_alert', -1)]
            )
            
            return group
        
        except Exception as e:
            logger.error(f"Error buscando grupo resuelto: {e}")
            return None
    
    def _create_new_group(self, alert: Dict, src_ip: str,
                         dest_ip: str, attack_type: str) -> ObjectId:
        """
        Crea nuevo grupo de ataque.
        
        V2.1: PERSISTE target_asset desde la alerta.
        """
        try:
            timestamp = alert.get('timestamp')
            severity = alert.get('alert', {}).get('severity', 3)
            category = alert.get('alert', {}).get('category', 'Unknown')
            
            # ✅ NUEVO: Extraer asset destino
            target_asset = self._extract_target_asset_from_alert(alert)
            
            # Generar ID descriptivo
            attack_label = self._get_attack_label(attack_type)
            group_id = self._generate_group_id(attack_label)
            
            group = {
                'group_id': group_id,
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'attack_type': attack_type,
                'attack_label': attack_label,
                'category': category,
                'severity': severity,
                'first_alert': datetime.fromisoformat(timestamp.replace('Z', '+00:00')),
                'last_alert': datetime.fromisoformat(timestamp.replace('Z', '+00:00')),
                'alert_count': 1,
                'status': 'active',
                'created_at': datetime.utcnow(),
                'pattern': self._detect_pattern(alert),
                'manually_resolved': False,
                'cves_detected': self._extract_cves_from_alert(alert),
                'description': f"{attack_type} desde {src_ip} hacia {dest_ip}",
                # ✅ NUEVO: Persistir asset
                'target_asset': target_asset,
                'asset_enriched': target_asset is not None
            }
            
            result = self.groups_col.insert_one(group)
            
            asset_info = f" - Asset: {target_asset.get('hostname', target_asset.get('ip'))}" if target_asset else " - Asset: Unknown"
            logger.info(f"✅ Nuevo grupo creado: {group_id} ({attack_type}){asset_info}")
            
            return result.inserted_id
        
        except Exception as e:
            logger.error(f"Error creando nuevo grupo: {e}")
            raise
    
    def _update_group(self, group_id: ObjectId, alert: Dict):
        """
        Actualiza grupo existente con nueva alerta.
        
        V2.1: Actualiza target_asset si viene en la alerta y no existía antes.
        """
        try:
            timestamp = alert.get('timestamp')
            timestamp_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            # Extraer CVEs de esta alerta
            new_cves = self._extract_cves_from_alert(alert)
            
            # ✅ NUEVO: Extraer asset de la alerta
            target_asset = self._extract_target_asset_from_alert(alert)
            
            update_ops = {
                '$set': {
                    'last_alert': timestamp_dt,
                    'status': 'active'
                },
                '$inc': {'alert_count': 1}
            }
            
            # Añadir CVEs únicos al array
            if new_cves:
                update_ops['$addToSet'] = {'cves_detected': {'$each': new_cves}}
            
            # ✅ NUEVO: Actualizar asset si viene y no existía
            if target_asset:
                # Solo actualizar si el grupo no tiene asset o está vacío
                current_group = self.groups_col.find_one({'_id': group_id})
                current_asset = current_group.get('target_asset')
                
                if not current_asset or not current_asset.get('hostname'):
                    update_ops['$set']['target_asset'] = target_asset
                    update_ops['$set']['asset_enriched'] = True
                    logger.debug(f"🔄 Asset actualizado en grupo {group_id}: {target_asset.get('hostname', target_asset.get('ip'))}")
            
            self.groups_col.update_one({'_id': group_id}, update_ops)
        
        except Exception as e:
            logger.error(f"Error actualizando grupo: {e}")
    
    def _reopen_group(self, group_id: ObjectId, alert: Dict):
        """
        Reabre grupo resuelto.
        
        V2.1: Actualiza target_asset si viene en la alerta.
        """
        try:
            timestamp = alert.get('timestamp')
            timestamp_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            new_cves = self._extract_cves_from_alert(alert)
            
            # ✅ NUEVO: Extraer asset
            target_asset = self._extract_target_asset_from_alert(alert)
            
            update_ops = {
                '$set': {
                    'last_alert': timestamp_dt,
                    'status': 're-opened',
                    'manually_resolved': False,
                    'reopened_at': datetime.utcnow()
                },
                '$inc': {'alert_count': 1}
            }
            
            if new_cves:
                update_ops['$addToSet'] = {'cves_detected': {'$each': new_cves}}
            
            # ✅ NUEVO: Actualizar asset si viene
            if target_asset:
                update_ops['$set']['target_asset'] = target_asset
                update_ops['$set']['asset_enriched'] = True
                logger.debug(f"🔄 Asset actualizado al reabrir grupo {group_id}: {target_asset.get('hostname', target_asset.get('ip'))}")
            
            self.groups_col.update_one({'_id': group_id}, update_ops)
            logger.warning(f"⚠️ Grupo reabierto automáticamente: {group_id}")
        
        except Exception as e:
            logger.error(f"Error reabriendo grupo: {e}")
    
    def _enrich_group_with_asset(self, group: Dict) -> Dict:
        """
        ✅ NUEVO: Enriquece un grupo sin asset buscando en sus alertas.
        
        AUTO-REPAIR para grupos antiguos que no tienen target_asset.
        """
        try:
            # Si ya tiene asset, no hacer nada
            if group.get('target_asset') and group.get('target_asset').get('hostname'):
                return group
            
            group_id = group['_id']
            
            # Buscar la alerta más reciente del grupo que tenga asset
            alert_with_asset = self.alerts_col.find_one(
                {
                    'correlation_group_id': group_id,
                    'target_asset': {'$exists': True, '$ne': None}
                },
                sort=[('timestamp', -1)]
            )
            
            if alert_with_asset:
                target_asset = alert_with_asset.get('target_asset')
                
                if target_asset:
                    # Actualizar el grupo
                    self.groups_col.update_one(
                        {'_id': group_id},
                        {
                            '$set': {
                                'target_asset': target_asset,
                                'asset_enriched': True,
                                'asset_enriched_at': datetime.utcnow()
                            }
                        }
                    )
                    
                    group['target_asset'] = target_asset
                    group['asset_enriched'] = True
                    
                    logger.info(f"🔧 AUTO-REPAIR: Asset añadido a grupo {group.get('group_id')}: {target_asset.get('hostname', target_asset.get('ip'))}")
        
        except Exception as e:
            logger.debug(f"Error enriqueciendo grupo con asset: {e}")
        
        return group
    
    def _extract_cves_from_alert(self, alert: Dict) -> List[str]:
        """Extrae CVE IDs de una alerta"""
        import re
        cves = []
        
        # Desde cve_id directo
        if alert.get('cve_id'):
            cves.append(alert['cve_id'])
        
        # Desde signature
        signature = alert.get('alert', {}).get('signature', '')
        matches = re.findall(r'CVE-\d{4}-\d+', signature)
        cves.extend(matches)
        
        return list(set(cves))  # Deduplicar
    
    def _detect_pattern(self, alert: Dict) -> str:
        """Detecta patrón de ataque"""
        signature = alert.get('alert', {}).get('signature', '').lower()
        
        if any(x in signature for x in ['scan', 'probe', 'reconnaissance']):
            return 'reconnaissance'
        elif any(x in signature for x in ['exploit', 'injection', 'overflow', 'rce']):
            return 'exploitation'
        elif any(x in signature for x in ['shell', 'backdoor', 'persistence']):
            return 'post-exploit'
        else:
            return 'exploitation'  # Default para ataques
    
    def _generate_group_id(self, attack_label: str) -> str:
        """
        Genera ID descriptivo para el grupo.
        
        Formato: ATK-{TIPO}-{NÚMERO}
        Ejemplo: ATK-SQLi-000042
        """
        # Contar grupos existentes con este tipo
        count = self.groups_col.count_documents({'attack_label': attack_label})
        return f"ATK-{attack_label}-{count + 1:06d}"
    
    def update_group_statuses(self):
        """
        Actualiza estados de grupos.
        
        Solo loggea candidatos para resolución (requiere confirmación manual).
        """
        try:
            now = datetime.utcnow()
            threshold = now - timedelta(days=AUTO_RESOLVE_DAYS)
            
            old_groups = self.groups_col.find({
                'status': {'$in': ['active', 're-opened']},
                'last_alert': {'$lt': threshold},
                'manually_resolved': False
            })
            
            count = 0
            for group in old_groups:
                logger.info(f"⏰ Candidato para resolver ({AUTO_RESOLVE_DAYS}+ días): {group['group_id']}")
                count += 1
            
            if count > 0:
                logger.info(f"📊 {count} grupos candidatos para resolución manual")
        
        except Exception as e:
            logger.error(f"Error actualizando estados: {e}")
    
    def mark_group_resolved(self, group_id: ObjectId, manually: bool = True) -> bool:
        """Marca grupo como resuelto"""
        try:
            result = self.groups_col.update_one(
                {'_id': group_id},
                {
                    '$set': {
                        'status': 'resolved',
                        'manually_resolved': manually,
                        'resolved_at': datetime.utcnow()
                    }
                }
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error marcando grupo como resuelto: {e}")
            return False
    
    def get_all_groups(self, page: int = 1, per_page: int = 10,
                      status: str = "all", severity: int = None,
                      src_ip: str = None, category: str = None,
                      attack_type: str = None) -> Dict:
        """
        Obtiene grupos con filtros.
        
        V2.1: AUTO-REPAIR de grupos sin asset al consultarlos.
        
        Args:
            attack_type: Filtrar por tipo de ataque (SQLi, RCE, etc.)
        """
        try:
            query = {}
            
            if status != "all":
                query['status'] = status
            
            if severity is not None:
                query['severity'] = severity
            
            if src_ip:
                query['src_ip'] = src_ip
            
            if category:
                query['category'] = {'$regex': category, '$options': 'i'}
            
            # Filtro por attack_type
            if attack_type:
                query['attack_type'] = {'$regex': attack_type, '$options': 'i'}
            
            total = self.groups_col.count_documents(query)
            skip = (page - 1) * per_page
            
            groups = list(self.groups_col.find(query)
                         .sort('last_alert', -1)
                         .skip(skip)
                         .limit(per_page))
            
            # ✅ NUEVO: Auto-repair de grupos sin asset
            for group in groups:
                if not group.get('target_asset') or not group.get('target_asset', {}).get('hostname'):
                    group = self._enrich_group_with_asset(group)
                
                group['_id'] = str(group['_id'])
            
            return {
                'groups': groups,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                }
            }
        
        except Exception as e:
            logger.error(f"Error obteniendo grupos: {e}")
            return {'groups': [], 'pagination': {}}
    
    def get_group_with_alerts(self, group_id: str, page: int = 1,
                             per_page: int = 25) -> Dict:
        """
        Obtiene grupo con sus alertas paginadas.
        
        V2.1: AUTO-REPAIR del asset si no existe.
        """
        try:
            group = self.groups_col.find_one({'_id': ObjectId(group_id)})
            
            if not group:
                return None
            
            # ✅ NUEVO: Auto-repair si no tiene asset
            if not group.get('target_asset') or not group.get('target_asset', {}).get('hostname'):
                group = self._enrich_group_with_asset(group)
            
            group['_id'] = str(group['_id'])
            
            total = self.alerts_col.count_documents({
                'correlation_group_id': ObjectId(group_id)
            })
            skip = (page - 1) * per_page
            
            alerts = list(self.alerts_col.find({
                'correlation_group_id': ObjectId(group_id)
            }).sort('timestamp', -1).skip(skip).limit(per_page))
            
            for alert in alerts:
                alert['_id'] = str(alert['_id'])
                if 'correlation_group_id' in alert:
                    alert['correlation_group_id'] = str(alert['correlation_group_id'])
            
            return {
                'group': group,
                'alerts': alerts,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                }
            }
        
        except Exception as e:
            logger.error(f"Error obteniendo grupo: {e}")
            return None
    
    def get_groups_summary(self) -> Dict:
        """
        Resumen de grupos por tipo de ataque.
        
        Útil para dashboard.
        """
        try:
            pipeline = [
                {
                    '$group': {
                        '_id': '$attack_type',
                        'count': {'$sum': 1},
                        'active': {
                            '$sum': {'$cond': [{'$eq': ['$status', 'active']}, 1, 0]}
                        },
                        'resolved': {
                            '$sum': {'$cond': [{'$eq': ['$status', 'resolved']}, 1, 0]}
                        },
                        'total_alerts': {'$sum': '$alert_count'},
                        'with_asset': {
                            '$sum': {'$cond': [{'$eq': ['$asset_enriched', True]}, 1, 0]}
                        }
                    }
                },
                {'$sort': {'count': -1}}
            ]
            
            results = list(self.groups_col.aggregate(pipeline))
            
            return {
                'by_attack_type': [
                    {
                        'attack_type': r['_id'] or 'Unknown',
                        'groups': r['count'],
                        'active': r['active'],
                        'resolved': r['resolved'],
                        'total_alerts': r['total_alerts'],
                        'with_asset': r.get('with_asset', 0)
                    }
                    for r in results
                ],
                'total_groups': sum(r['count'] for r in results),
                'total_active': sum(r['active'] for r in results),
                'total_with_asset': sum(r.get('with_asset', 0) for r in results)
            }
        
        except Exception as e:
            logger.error(f"Error generando resumen: {e}")
            return {}