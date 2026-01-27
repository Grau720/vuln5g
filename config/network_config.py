# config/network_config.py

import socket
import ipaddress
import psutil
from typing import List, Set
import logging

logger = logging.getLogger(__name__)

def get_local_networks() -> Set[str]:
    """
    Detecta automáticamente las redes locales del servidor usando psutil.
    
    Returns:
        Set de redes en formato CIDR (ej: {'172.22.0.0/16', '192.168.1.0/24'})
    """
    local_networks = set()
    
    try:
        # Obtener todas las interfaces de red
        net_if_addrs = psutil.net_if_addrs()
        
        for interface_name, addr_list in net_if_addrs.items():
            for addr in addr_list:
                # Solo IPv4
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    
                    # Ignorar localhost
                    if ip.startswith('127.'):
                        continue
                    
                    if ip and netmask:
                        try:
                            # Calcular red CIDR
                            interface_net = ipaddress.IPv4Interface(f"{ip}/{netmask}")
                            network = interface_net.network
                            local_networks.add(str(network))
                            logger.debug(f"Red detectada: {network} (interfaz: {interface_name})")
                        except Exception as e:
                            logger.warning(f"Error procesando {ip}/{netmask}: {e}")
        
        # Siempre incluir localhost
        local_networks.add('127.0.0.0/8')
        
        # Siempre incluir redes Docker comunes
        local_networks.add('172.16.0.0/12')
        
        # Si no se detectó nada, usar RFC1918 por defecto
        if len(local_networks) <= 2:  # solo localhost y docker
            logger.warning("No se detectaron redes específicas, usando RFC1918 por defecto")
            local_networks.update({
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16'
            })
        
    except Exception as e:
        logger.error(f"Error detectando redes locales: {e}")
        # Fallback a redes privadas RFC1918
        local_networks = {
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
        }
    
    logger.info(f"🌐 Redes locales detectadas: {sorted(local_networks)}")
    return local_networks


def is_target_in_local_networks(target: str, local_networks: Set[str]) -> bool:
    """
    Verifica si un target está dentro de las redes locales permitidas.
    
    Args:
        target: IP o CIDR a verificar (ej: "172.22.0.50" o "10.0.0.0/24")
        local_networks: Set de redes locales detectadas
    
    Returns:
        True si el target está en alguna red local
    """
    try:
        # Si es un hostname, permitirlo (asumimos que es interno)
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if "/" not in target:
                logger.debug(f"Target {target} es hostname, permitido")
                return True  # Es un hostname
        
        # Convertir target a network
        target_net = ipaddress.ip_network(target, strict=False)
        
        # Verificar si está contenido en alguna red local
        for local_net_str in local_networks:
            local_net = ipaddress.ip_network(local_net_str)
            
            # Verificar si target es subred de local_net o se superponen
            if target_net.subnet_of(local_net) or target_net.overlaps(local_net):
                logger.debug(f"Target {target} permitido (overlaps con {local_net_str})")
                return True
        
        logger.warning(f"Target {target} NO está en redes locales permitidas")
        return False
        
    except Exception as e:
        logger.error(f"Error validando target {target}: {e}")
        return False


def get_discovery_config() -> dict:
    """
    Obtiene configuración de discovery con redes detectadas automáticamente.
    
    Returns:
        {
            'allowed_networks': ['172.22.0.0/16', ...],
            'max_ips_per_scan': 2048,
            'default_targets': {
                'core': ['172.22.0.0/24'],
                'ran_oam': [],
                'transport': []
            }
        }
    """
    local_nets = get_local_networks()
    
    # Sugerir un target por defecto basado en la red principal
    default_core = None
    
    # Ordenar por prefixlen (más específicas primero)
    sorted_nets = sorted(
        [ipaddress.ip_network(n) for n in local_nets if not n.startswith('127.')],
        key=lambda n: n.prefixlen,
        reverse=True
    )
    
    for net in sorted_nets:
        # Usar la red /24 más específica que no sea localhost o muy grande
        if 16 <= net.prefixlen <= 24:
            default_core = str(net)
            break
        elif net.prefixlen > 24:
            # Convertir a /24 para sugerencia
            default_core = str(ipaddress.ip_network(f"{net.network_address}/24", strict=False))
            break
    
    # Si no encontramos nada, usar la primera red que no sea localhost
    if not default_core and sorted_nets:
        net = sorted_nets[0]
        if net.prefixlen <= 16:
            default_core = str(ipaddress.ip_network(f"{net.network_address}/24", strict=False))
        else:
            default_core = str(net)
    
    return {
        'allowed_networks': sorted(local_nets),
        'max_ips_per_scan': 2048,
        'default_targets': {
            'core': [default_core] if default_core else [],
            'ran_oam': [],
            'transport': []
        }
    }