#!/bin/bash
# Setup Traffic Mirroring to Suricata using iptables TEE
# This script mirrors traffic between attacker and API to Suricata for inspection

set -e

echo "=========================================="
echo "VULNDB-5G TRAFFIC MIRRORING SETUP"
echo "=========================================="
echo ""

# Configuration
ATTACKER_IP="172.22.0.55"
API_IP="172.22.0.52"
SURICATA_IP="172.22.0.54"
BRIDGE_INTERFACE="br-d498833cc7cd"  # From docker network inspect

echo "Configuration:"
echo "  Attacker:  ${ATTACKER_IP}"
echo "  API:       ${API_IP}"
echo "  Suricata:  ${SURICATA_IP}"
echo "  Bridge:    ${BRIDGE_INTERFACE}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ ERROR: This script must be run as root"
    exit 1
fi

# Check if TEE module is available
echo "Checking iptables TEE module..."
if ! iptables -t mangle -A PREROUTING -j TEE --gateway ${SURICATA_IP} 2>/dev/null; then
    echo "⚠️  WARNING: TEE module not available or failed"
    iptables -t mangle -D PREROUTING -j TEE --gateway ${SURICATA_IP} 2>/dev/null || true
fi

echo ""
echo "=========================================="
echo "METHOD 1: iptables TEE (Traffic Duplication)"
echo "=========================================="
echo ""
echo "Setting up traffic mirroring rules..."

# Clean up any existing rules first
echo "Cleaning up old rules..."
iptables -t mangle -D PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -d ${API_IP} -j TEE --gateway ${SURICATA_IP} 2>/dev/null || true
iptables -t mangle -D PREROUTING -i ${BRIDGE_INTERFACE} -s ${API_IP} -d ${ATTACKER_IP} -j TEE --gateway ${SURICATA_IP} 2>/dev/null || true

# Add mirroring rules - Attacker -> API
echo "Adding rule: ${ATTACKER_IP} -> ${API_IP} ==> ${SURICATA_IP}"
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -d ${API_IP} -j TEE --gateway ${SURICATA_IP}

# Add mirroring rules - API -> Attacker  
echo "Adding rule: ${API_IP} -> ${ATTACKER_IP} ==> ${SURICATA_IP}"
iptables -t mangle -A PREROUTING -i ${BRIDGE_INTERFACE} -s ${API_IP} -d ${ATTACKER_IP} -j TEE --gateway ${SURICATA_IP}

echo ""
echo "✅ Traffic mirroring rules added successfully!"
echo ""

# Verify rules
echo "=========================================="
echo "VERIFICATION"
echo "=========================================="
echo ""
echo "Current iptables mangle table rules:"
iptables -t mangle -L PREROUTING -n -v | grep -E "TEE|Chain"

echo ""
echo "=========================================="
echo "TESTING"
echo "=========================================="
echo ""
echo "Waiting 2 seconds for rules to take effect..."
sleep 2

echo "Sending test HTTP request..."
docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/api/v1/test" > /dev/null 2>&1 || echo "  (Expected 404 - endpoint doesn't exist)"

echo "Waiting 3 seconds for Suricata to process..."
sleep 3

echo ""
echo "Checking Suricata packet counters..."
docker exec vulndb_suricata suricatasc -c "dump-counters" | jq -r '.message.decoder.tcp, .message.decoder.ipv4' 2>/dev/null || \
docker exec vulndb_suricata suricatasc -c "dump-counters" | grep -E '"tcp":|"ipv4":' | head -2

echo ""
echo "=========================================="
echo "CLEANUP INSTRUCTIONS"
echo "=========================================="
echo ""
echo "To remove the mirroring rules later, run:"
echo ""
echo "  iptables -t mangle -D PREROUTING -i ${BRIDGE_INTERFACE} -s ${ATTACKER_IP} -d ${API_IP} -j TEE --gateway ${SURICATA_IP}"
echo "  iptables -t mangle -D PREROUTING -i ${BRIDGE_INTERFACE} -s ${API_IP} -d ${ATTACKER_IP} -j TEE --gateway ${SURICATA_IP}"
echo ""
echo "=========================================="
echo "SETUP COMPLETE"
echo "=========================================="