#!/bin/bash
# Suricata HTTP Traffic Inspection Diagnostic
# This script must be run from the host (not from Claude's container)

echo "=========================================="
echo "1. SURICATA PROCESS STATUS"
echo "=========================================="
docker exec vulndb_suricata ps aux | grep suricata

echo ""
echo "=========================================="
echo "2. NETWORK INTERFACE"
echo "=========================================="
docker exec vulndb_suricata ip addr show eth0

echo ""
echo "=========================================="
echo "3. SURICATA LOGS (last 30 lines)"
echo "=========================================="
docker exec vulndb_suricata tail -30 /var/log/suricata/suricata.log

echo ""
echo "=========================================="
echo "4. RULES LOADED"
echo "=========================================="
docker exec vulndb_suricata suricatasc -c "ruleset-stats"

echo ""
echo "=========================================="
echo "5. APP LAYER PROTOCOLS STATUS"
echo "=========================================="
docker exec vulndb_suricata suricatasc -c "dump-counters" | grep -E "(http|tcp|flow)" | head -20

echo ""
echo "=========================================="
echo "6. CHECK IF HTTP PARSER IS ENABLED"
echo "=========================================="
docker exec vulndb_suricata cat /etc/suricata/suricata.yaml 2>/dev/null | grep -A 5 "app-layer:" | head -20

echo ""
echo "=========================================="
echo "7. TEST TRAFFIC - SEND ATTACK"
echo "=========================================="
echo "Sending test attack..."
docker exec vulndb_attacker curl -v "http://172.22.0.52:5000/api/v1/exec?cmd=whoami" 2>&1 | head -20

echo ""
echo "Waiting 3 seconds for Suricata to process..."
sleep 3

echo ""
echo "=========================================="
echo "8. CHECK FOR ALERTS"
echo "=========================================="
if docker exec vulndb_suricata test -f /var/log/suricata/fast.log; then
    echo "fast.log EXISTS:"
    docker exec vulndb_suricata cat /var/log/suricata/fast.log
else
    echo "fast.log DOES NOT EXIST"
fi

echo ""
echo "=========================================="
echo "9. CHECK EVE.JSON FOR HTTP EVENTS"
echo "=========================================="
if docker exec vulndb_suricata test -f /var/log/suricata/eve.json; then
    echo "Last 10 events in eve.json:"
    docker exec vulndb_suricata tail -10 /var/log/suricata/eve.json | jq -r '.event_type' 2>/dev/null || docker exec vulndb_suricata tail -10 /var/log/suricata/eve.json
else
    echo "eve.json DOES NOT EXIST"
fi

echo ""
echo "=========================================="
echo "10. PACKET CAPTURE STATS"
echo "=========================================="
docker exec vulndb_suricata suricatasc -c "capture-mode" 2>/dev/null || echo "Could not get capture mode"
docker exec vulndb_suricata suricatasc -c "dump-counters" | grep -E "capture|decoder|app_layer" | head -30

echo ""
echo "=========================================="
echo "DIAGNOSTIC COMPLETE"
echo "=========================================="