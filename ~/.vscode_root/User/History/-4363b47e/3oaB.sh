#!/bin/bash
# Analyze why HTTP app-layer rules aren't triggering

echo "=========================================="
echo "HTTP APP-LAYER DETECTION ANALYSIS"
echo "=========================================="
echo ""

echo "1. Check EVE.JSON for HTTP events"
echo "----------------------------------------"
docker exec vulndb_suricata tail -20 /var/log/suricata/eve.json | jq -r 'select(.event_type == "http") | {timestamp, method: .http.http_method, uri: .http.url, hostname: .http.hostname}' 2>/dev/null || echo "No HTTP events found in eve.json"

echo ""
echo "2. Check if HTTP parser is processing the traffic"
echo "----------------------------------------"
docker exec vulndb_suricata suricatasc -c "dump-counters" | jq -r '.message.app_layer.flow.http, .message.app_layer.tx.http' 2>/dev/null || \
docker exec vulndb_suricata suricatasc -c "dump-counters" | grep -A 2 '"http":'

echo ""
echo "3. Check TCP stream reassembly"
echo "----------------------------------------"
docker exec vulndb_suricata suricatasc -c "dump-counters" | jq -r '.message.tcp.sessions, .message.tcp.reassembly_gap' 2>/dev/null || \
docker exec vulndb_suricata suricatasc -c "dump-counters" | grep -E '"sessions":|"reassembly'

echo ""
echo "4. Test with fresh request and monitor"
echo "----------------------------------------"
echo "Clearing fast.log..."
docker exec vulndb_suricata sh -c "> /var/log/suricata/fast.log"

echo "Sending test request with malicious payload..."
docker exec vulndb_attacker curl -v "http://172.22.0.52:5000/api/v1/exec?cmd=ls%20-la" 2>&1 | grep -E "GET|HTTP"

echo ""
echo "Waiting 3 seconds for processing..."
sleep 3

echo ""
echo "Alerts triggered:"
docker exec vulndb_suricata cat /var/log/suricata/fast.log | cut -d']' -f3 | sort | uniq -c

echo ""
echo "5. Check our actual rules"
echo "----------------------------------------"
echo "Rules that SHOULD have matched:"
docker exec vulndb_suricata grep -E "9999001|9999002|9504" /etc/suricata/rules/generated.rules

echo ""
echo "=========================================="
echo "DIAGNOSIS SUMMARY"
echo "=========================================="
echo ""
echo "The issue is likely one of:"
echo "  A) HTTP parser not enabled in suricata.yaml"
echo "  B) Packets arriving out of order (stream reassembly issue)"
echo "  C) Rules using http.uri/http.method require full HTTP parsing"
echo ""
echo "Next step: Check suricata.yaml HTTP configuration"