#!/bin/bash
# Setup Traffic Mirroring to Suricata using iptables TEE
# VERSIÓN EXTENDIDA - Incluye UPF, API y otros componentes 5G
set -e

echo "=========================================="
echo "VULNDB-5G TRAFFIC MIRRORING SETUP V2"
echo "=========================================="
echo ""

# Configuration
ATTACKER_IP="172.22.0.55"
API_IP="172.22.0.52"
UPF_IP="172.22.0.20"
AMF_IP="172.22.0.10"
SURICATA_IP="172.22.0.54"
BRIDGE_INTERFACE="br-d498833cc7cd"

echo "Configuration:"
echo "  Attacker:  ${ATTACKER_IP}"
echo "  API:       ${API_IP}"
echo "  UPF:       ${UPF_IP}"
echo "  AMF:       ${AMF_IP}"
echo "  Suricata:  ${SURICATA_IP}"
echo "  Bridge:    ${BRIDGE_INTERFACE}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ ERROR: This script must be run as root"
    exit 1
fi

echo "=========================================="
echo "CLEANING UP OLD RULES"
echo "=========================================="
echo ""

# Clean up ALL existing TEE rules
echo "Removing any existing TEE rules..."
iptables -t mangle -F PREROUTING 2>/dev/null || true

echo "✅ Old rules cleaned"
echo ""

echo "=========================================="
echo "ADDING MIRRORING RULES FOR 5G TRAFFIC"
echo "=========================================="
echo ""

# ============================================
# REGLA 1: Attacker <-> API (HTTP/SBI)
# ============================================
echo "[1] Mirroring: Attacker <-> API (SBI/HTTP)"
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -d ${API_IP} -j TEE --gateway ${SURICATA_IP}
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${API_IP} -d ${ATTACKER_IP} -j TEE --gateway ${SURICATA_IP}
echo "  ✓ ${ATTACKER_IP} <-> ${API_IP}"

# ============================================
# REGLA 2: Attacker <-> UPF (PFCP/GTP-U)
# ============================================
echo "[2] Mirroring: Attacker <-> UPF (PFCP puerto 8805, GTP-U puerto 2152)"
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -d ${UPF_IP} -j TEE --gateway ${SURICATA_IP}
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${UPF_IP} -d ${ATTACKER_IP} -j TEE --gateway ${SURICATA_IP}
echo "  ✓ ${ATTACKER_IP} <-> ${UPF_IP}"

# ============================================
# REGLA 3: Attacker <-> AMF (NGAP)
# ============================================
echo "[3] Mirroring: Attacker <-> AMF (NGAP)"
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -d ${AMF_IP} -j TEE --gateway ${SURICATA_IP}
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${AMF_IP} -d ${ATTACKER_IP} -j TEE --gateway ${SURICATA_IP}
echo "  ✓ ${ATTACKER_IP} <-> ${AMF_IP}"

# ============================================
# REGLA 4: Todo el tráfico UDP (para PFCP, GTP-U, SCTP encapsulado)
# ============================================
echo "[4] Mirroring: Todo tráfico UDP desde Attacker"
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -p udp -j TEE --gateway ${SURICATA_IP}

# ============================================
# REGLA 5: Todo el tráfico SCTP (protocolo 132 - para NGAP)
# ============================================
echo "[5] Mirroring: Todo tráfico SCTP desde Attacker"
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -p sctp -j TEE --gateway ${SURICATA_IP}

echo ""
echo "✅ All mirroring rules added successfully!"
echo ""

# Verify rules
echo "=========================================="
echo "VERIFICATION"
echo "=========================================="
echo ""
echo "Active iptables mangle rules:"
iptables -t mangle -L PREROUTING -n -v --line-numbers

echo ""
echo "=========================================="
echo "TESTING CONNECTIVITY"
echo "=========================================="
echo ""

echo "Test 1: HTTP to API..."
docker exec vulndb_attacker curl -s "http://${API_IP}:5000/" > /dev/null 2>&1 && echo "  ✓ API reachable" || echo "  ⚠ API not responding"

echo "Test 2: UDP to UPF PFCP (8805)..."
docker exec vulndb_attacker python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'TEST', ('${UPF_IP}', 8805))
s.close()
print('  ✓ UDP packet sent to PFCP')
"

echo "Test 3: UDP to UPF GTP-U (2152)..."
docker exec vulndb_attacker python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'TEST', ('${UPF_IP}', 2152))
s.close()
print('  ✓ UDP packet sent to GTP-U')
"

echo ""
echo "Waiting 5 seconds for Suricata to process..."
sleep 5

echo ""
echo "Checking Suricata packet counters..."
docker exec vulndb_suricata suricatasc -c "dump-counters" 2>/dev/null | grep -E "capture.kernel_packets|decoder.udp|decoder.tcp" | head -5 || echo "  ⚠ Could not get counters"

echo ""
echo "Checking for alerts..."
ALERTS=$(cat ./runtime/suricata/logs/fast.log 2>/dev/null | wc -l)
if [ "$ALERTS" -gt 0 ]; then
    echo "  ✓ ${ALERTS} alerts detected!"
    tail -5 ./runtime/suricata/logs/fast.log
else
    echo "  ⚠ No alerts yet (this is normal for benign test traffic)"
fi

echo ""
echo "=========================================="
echo "CLEANUP INSTRUCTIONS"
echo "=========================================="
echo ""
echo "To remove ALL mirroring rules, run:"
echo "  iptables -t mangle -F PREROUTING"
echo ""
echo "Or to remove specific rules:"
echo "  iptables -t mangle -L PREROUTING --line-numbers"
echo "  iptables -t mangle -D PREROUTING <line_number>"
echo ""

echo "=========================================="
echo "SETUP COMPLETE ✅"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Run: ./test_5g_python_only.sh"
echo "2. Check: cat ./runtime/suricata/logs/fast.log"
echo ""