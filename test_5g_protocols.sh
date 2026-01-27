#!/bin/bash

echo "=========================================="
echo "  TEST 5G COMPLETO - Versión Ligera"
echo "  Optimizado para VM"
echo "=========================================="
echo ""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# IPs según tu docker-compose
NRF_IP="172.22.0.10"
AMF_IP="172.22.0.12"
SMF_IP="172.22.0.13"
UPF_IP="172.22.0.20"
AUSF_IP="172.22.0.14"
UDM_IP="172.22.0.15"
API_IP="172.22.0.52"

echo "=== Configuración de red 5G ==="
echo "NRF:  $NRF_IP"
echo "AMF:  $AMF_IP"
echo "SMF:  $SMF_IP"
echo "UPF:  $UPF_IP"
echo "AUSF: $AUSF_IP"
echo "UDM:  $UDM_IP"
echo "API:  $API_IP"
echo ""

echo "=== PASO 1: Limpiar logs ==="
> ./runtime/suricata/logs/fast.log
> ./runtime/suricata/logs/eve.json
echo -e "${GREEN}✓${NC} Logs limpiados"

echo ""
echo "=========================================="
echo "  GENERANDO TRÁFICO 5G (LIGERO)"
echo "=========================================="

docker exec vulndb_attacker python3 << 'PYTHON'
import socket
import time
import urllib.request

print("\n" + "="*60)
print("TEST 1/5: PFCP (N4 Interface - UPF)")
print("="*60)
print("Puerto: 8805 | Protocolo: PFCP (Packet Forwarding Control)")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
upf_ip = "172.22.0.20"

# Enviar 20 paquetes PFCP malformados (NO 0x20 en offset 0)
payloads = [
    b"\x00\x01\x02\x03",  # Byte incorrecto
    b"\xFF\xFF\xFF\xFF",  # Byte incorrecto
    b"\x10\x11\x12\x13",  # Byte incorrecto
]

count = 0
for i in range(7):  # 7 iteraciones * 3 payloads = 21 paquetes
    for payload in payloads:
        s.sendto(payload, (upf_ip, 8805))
        count += 1
    time.sleep(0.1)

s.close()
print(f"✓ Enviados {count} paquetes PFCP malformados al UPF")

# ============================================
print("\n" + "="*60)
print("TEST 2/5: GTP-U TEID Spoofing (N3 Interface)")
print("="*60)
print("Puerto: 2152 | Protocolo: GTP-U (User Plane)")

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# GTP-U header con TEID=0 (sospechoso)
# Estructura: version|type|length|TEID
gtp_header = b"\x30\xFF\x00\x10\x00\x00\x00\x00"
data = b"MALICIOUS_DATA_HERE"

count = 0
for i in range(15):  # Solo 15 paquetes
    s.sendto(gtp_header + data, (upf_ip, 2152))
    count += 1
    time.sleep(0.08)

s.close()
print(f"✓ Enviados {count} paquetes GTP-U con TEID=0 al UPF")

# ============================================
print("\n" + "="*60)
print("TEST 3/5: GTP-U Flooding (DoS Attack)")
print("="*60)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
gtp_packet = b"\x30\x01\x00\x08\x12\x34\x56\x78FLOOD"

start = time.time()
count = 0
# Enviar 80 paquetes rápidos (ligero, no 150)
for i in range(80):
    s.sendto(gtp_packet, (upf_ip, 2152))
    count += 1

duration = time.time() - start
s.close()
print(f"✓ Enviados {count} paquetes en {duration:.2f}s ({count/duration:.0f} pps)")

# ============================================
print("\n" + "="*60)
print("TEST 4/5: SBI - Unauthorized API Access (N11)")
print("="*60)
print("Interfaces SBI de 5G Core (HTTP/2)")

# Puertos SBI reales de Open5GS según tu config
api_ip = "172.22.0.52"
sbi_targets = [
    ("AUSF", "172.22.0.14", 7777, "/nausf-auth/v1/ue-authentications"),
    ("UDM",  "172.22.0.15", 7777, "/nudm-sdm/v1/imsi-123456/am-data"),
    ("SMF",  "172.22.0.13", 7777, "/nsmf-pdusession/v1/sm-contexts"),
]

count = 0
for nf_name, nf_ip, port, path in sbi_targets:
    try:
        url = f"http://{nf_ip}:{port}{path}"
        req = urllib.request.Request(
            url,
            data=b'{"supi":"imsi-999700000000001"}',
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        # Sin Authorization header - ATAQUE
        urllib.request.urlopen(req, timeout=2)
        print(f"  → {nf_name}: Request sent")
        count += 1
    except Exception as e:
        # El tráfico se envía aunque falle
        print(f"  → {nf_name}: Traffic sent (expected error)")
        count += 1
    time.sleep(0.3)

print(f"✓ {count} peticiones SBI no autorizadas enviadas")

# ============================================
print("\n" + "="*60)
print("TEST 5/5: SBI API Flooding")
print("="*60)

# Flooding ligero: solo 60 peticiones (no 120)
nrf_ip = "172.22.0.10"
url = f"http://{nrf_ip}:7777/nnrf-disc/v1/nf-instances"

count = 0
start = time.time()
for i in range(60):
    try:
        urllib.request.urlopen(url, timeout=0.5)
    except:
        pass
    count += 1

duration = time.time() - start
print(f"✓ {count} peticiones en {duration:.2f}s ({count/duration:.0f} req/s)")

# ============================================
print("\n" + "="*60)
print("RESUMEN DEL TEST")
print("="*60)
print("✓ PFCP malformado: 21 paquetes")
print("✓ GTP-U TEID spoof: 15 paquetes")
print("✓ GTP-U flooding: 80 paquetes")
print("✓ SBI no autorizado: 3 peticiones")
print("✓ SBI flooding: 60 peticiones")
print("="*60)
PYTHON

echo ""
echo -e "${YELLOW}Esperando 10 segundos para procesamiento de Suricata...${NC}"
sleep 10

echo ""
echo "=========================================="
echo "  RESULTADOS"
echo "=========================================="

# Verificar si hay logs
if [ ! -f ./runtime/suricata/logs/fast.log ]; then
    echo -e "${RED}✗ fast.log no existe${NC}"
    exit 1
fi

TOTAL=$(wc -l < ./runtime/suricata/logs/fast.log)

echo ""
echo "=== ALERTAS TOTALES ==="
echo -e "${BLUE}Total de alertas detectadas: $TOTAL${NC}"

if [ "$TOTAL" -eq 0 ]; then
    echo -e "${RED}✗ No se detectaron alertas${NC}"
    echo ""
    echo "Verificar:"
    echo "1. ¿Mirroring activo? sudo iptables -t mangle -L PREROUTING -n"
    echo "2. ¿Suricata corriendo? docker ps | grep suricata"
    exit 1
fi

echo ""
echo "=== DESGLOSE POR PROTOCOLO 5G ==="
PFCP=$(grep -c "5G-PFCP" ./runtime/suricata/logs/fast.log 2>/dev/null || echo "0")
GTP=$(grep -c "5G-GTP" ./runtime/suricata/logs/fast.log 2>/dev/null || echo "0")
SBI=$(grep -c "5G-SBI" ./runtime/suricata/logs/fast.log 2>/dev/null || echo "0")
NGAP=$(grep -c "5G-NGAP" ./runtime/suricata/logs/fast.log 2>/dev/null || echo "0")

echo "• PFCP (N4):  $PFCP alertas"
echo "• GTP-U (N3): $GTP alertas"
echo "• SBI (N11):  $SBI alertas"
echo "• NGAP (N2):  $NGAP alertas"

echo ""
echo "=== TOP 5 CVEs DETECTADOS ==="
# Extraer CVEs y contar
grep -oP 'CVE-\d{4}-\d+' ./runtime/suricata/logs/fast.log | sort | uniq -c | sort -rn | head -5

echo ""
echo "=== PRIMERAS 10 ALERTAS ==="
head -10 ./runtime/suricata/logs/fast.log | while read line; do
    # Extraer solo la parte importante
    echo "$line" | grep -oP '\[\*\*\].*?\[\*\*\]' | sed 's/\[\*\*\] //g'
done

echo ""
echo "=== ÚLTIMAS 5 ALERTAS ==="
tail -5 ./runtime/suricata/logs/fast.log | while read line; do
    echo "$line" | grep -oP '\[\*\*\].*?\[\*\*\]' | sed 's/\[\*\*\] //g'
done

echo ""
echo "=========================================="
echo "  ESTADÍSTICAS FINALES"
echo "=========================================="

# Alertas por nivel de riesgo
CRITICAL=$(grep -c "CRITICAL" ./runtime/suricata/logs/fast.log 2>/dev/null || echo "0")
HIGH=$(grep -c "HIGH" ./runtime/suricata/logs/fast.log 2>/dev/null || echo "0")
MEDIUM=$(grep -c "MEDIUM" ./runtime/suricata/logs/fast.log 2>/dev/null || echo "0")

echo "Nivel de riesgo:"
echo "  • Critical: $CRITICAL"
echo "  • High: $HIGH"
echo "  • Medium: $MEDIUM"

echo ""
echo "Interfaces 5G testeadas:"
echo "  • N4 (SMF-UPF): PFCP"
echo "  • N3 (gNB-UPF): GTP-U"
echo "  • N11 (NF-NF): SBI/HTTP2"
echo "  • N2 (gNB-AMF): NGAP [no probado - requiere SCTP]"

echo ""
if [ "$TOTAL" -gt 50 ]; then
    echo -e "${GREEN}✓✓✓ ÉXITO COMPLETO ✓✓✓${NC}"
    echo "Sistema de detección funcionando correctamente"
elif [ "$TOTAL" -gt 10 ]; then
    echo -e "${YELLOW}⚠ ÉXITO PARCIAL ⚠${NC}"
    echo "Algunas reglas funcionan, revisar configuración"
else
    echo -e "${RED}⚠ DETECCIÓN LIMITADA ⚠${NC}"
    echo "Pocas alertas generadas, verificar reglas"
fi

echo ""
echo "=========================================="
echo "  Ver logs completos:"
echo "  cat ./runtime/suricata/logs/fast.log"
echo "  cat ./runtime/suricata/logs/eve.json | jq"
echo "=========================================="