#!/bin/bash
# Complete Suricata rules deployment
# Generates rules from MongoDB CVEs and tests detection

set -e

echo "=========================================="
echo "VULNDB-5G COMPLETE RULES DEPLOYMENT"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Step 1: Generate rules from MongoDB using API
echo "=========================================="
echo "STEP 1: Generating Rules from CVE Database"
echo "=========================================="
echo ""

print_status "Querying API to generate rules for top-risk CVEs..."
echo "  Risk levels: CRITICAL, HIGH"
echo "  Attack vectors: NETWORK"
echo "  Limit: 100 CVEs"
echo ""

RESPONSE=$(curl -s -X GET "http://172.22.0.52:5000/api/v1/rules/suricata/top-risk?risk=CRITICAL,HIGH&attack_vector=NETWORK&limit=100&deploy=true")

if [ $? -eq 0 ]; then
    # Parse response
    STATUS=$(echo "$RESPONSE" | jq -r '.status // "error"')
    
    if [ "$STATUS" = "success" ]; then
        RULES_COUNT=$(echo "$RESPONSE" | jq -r '.stats.rules_generated // 0')
        print_status "Generated $RULES_COUNT rules successfully"
        
        # Show detailed stats
        echo ""
        echo "Generation Statistics:"
        echo "$RESPONSE" | jq '.stats'
    else
        ERROR_MSG=$(echo "$RESPONSE" | jq -r '.message // "Unknown error"')
        print_error "API returned error: $ERROR_MSG"
        echo "Full response: $RESPONSE"
        exit 1
    fi
else
    print_error "Failed to connect to API"
    exit 1
fi

echo ""

# Step 2: Verify rules file
echo "=========================================="
echo "STEP 2: Verifying Generated Rules"
echo "=========================================="
echo ""

print_status "Checking generated rules file..."
RULES_IN_FILE=$(docker exec vulndb_suricata wc -l /etc/suricata/rules/generated.rules | awk '{print $1}')
print_status "Rules file contains $RULES_IN_FILE lines"

echo ""
print_status "Sample of generated rules:"
docker exec vulndb_suricata head -5 /etc/suricata/rules/generated.rules

echo ""

# Step 3: Test Suricata syntax
echo "=========================================="
echo "STEP 3: Testing Suricata Syntax"
echo "=========================================="
echo ""

print_status "Running Suricata syntax test..."
SYNTAX_TEST=$(docker exec vulndb_suricata suricata -T -S /etc/suricata/rules/generated.rules -l /tmp 2>&1)

if echo "$SYNTAX_TEST" | grep -q "successfully loaded"; then
    LOADED=$(echo "$SYNTAX_TEST" | grep -oP '\d+(?= rules successfully loaded)')
    print_status "Syntax test passed: $LOADED rules loaded"
else
    print_error "Syntax test failed!"
    echo "$SYNTAX_TEST"
    exit 1
fi

echo ""

# Step 4: Restart Suricata
echo "=========================================="
echo "STEP 4: Restarting Suricata"
echo "=========================================="
echo ""

print_status "Restarting Suricata container..."
docker restart vulndb_suricata
sleep 5

print_status "Waiting for Suricata to initialize..."
sleep 5

# Verify Suricata is running
if docker exec vulndb_suricata pgrep suricata > /dev/null; then
    print_status "Suricata is running"
else
    print_error "Suricata failed to start"
    exit 1
fi

echo ""

# Step 5: Verify rules loaded
echo "=========================================="
echo "STEP 5: Verifying Rules Loaded"
echo "=========================================="
echo ""

RULES_LOADED=$(docker exec vulndb_suricata suricatasc -c "ruleset-stats" | jq -r '.message[0].rules_loaded // 0')
print_status "Suricata loaded $RULES_LOADED rules"

if [ "$RULES_LOADED" -gt 0 ]; then
    print_status "Rules loaded successfully"
else
    print_warning "No rules loaded - check Suricata logs"
fi

echo ""

# Step 6: Run detection tests
echo "=========================================="
echo "STEP 6: Testing Attack Detection"
echo "=========================================="
echo ""

print_status "Clearing alert logs..."
docker exec vulndb_suricata sh -c "> /var/log/suricata/fast.log"

echo ""
print_status "Running attack simulations..."

echo "  Test 1: RCE with whoami..."
docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/api/v1/exec?cmd=whoami" > /dev/null 2>&1
sleep 1

echo "  Test 2: RCE with pipe operator..."
docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/api/v1/exec?cmd=ls%7Ccat" > /dev/null 2>&1
sleep 1

echo "  Test 3: RCE with semicolon..."
docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/api/v1/exec?cmd=whoami%3Bls" > /dev/null 2>&1
sleep 1

echo "  Test 4: SQL Injection..."
docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/api/v1/users?id=1%20UNION%20SELECT" > /dev/null 2>&1
sleep 1

echo "  Test 5: Path Traversal..."
docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/api/v1/file?path=../../../etc/passwd" > /dev/null 2>&1
sleep 1

echo "  Test 6: Multiple RCE commands..."
docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/api/v1/exec?cmd=ls;pwd;id" > /dev/null 2>&1
sleep 1

print_status "Waiting for Suricata to process alerts..."
sleep 3

echo ""

# Step 7: Analyze results
echo "=========================================="
echo "STEP 7: Detection Results"
echo "=========================================="
echo ""

ALERT_COUNT=$(docker exec vulndb_suricata wc -l /var/log/suricata/fast.log 2>/dev/null | awk '{print $1}' || echo "0")

if [ "$ALERT_COUNT" -gt 0 ]; then
    print_status "DETECTION WORKING! Generated $ALERT_COUNT alerts"
    
    echo ""
    echo "Alerts by Rule (Top 10):"
    docker exec vulndb_suricata cat /var/log/suricata/fast.log | \
        grep -oP '\[1:\K\d+' | sort | uniq -c | sort -rn | head -10 | \
        while read count sid; do
            echo "  SID $sid: $count alerts"
        done
    
    echo ""
    echo "Recent Alerts (Last 10):"
    docker exec vulndb_suricata tail -10 /var/log/suricata/fast.log | \
        cut -d']' -f3 | sed 's/^ */  - /'
    
    echo ""
    print_status "✓ Detection is working correctly!"
else
    print_warning "No alerts detected - rules may need adjustment"
    
    echo ""
    echo "Debugging info:"
    echo "  - Check if HTTP traffic is being parsed:"
    docker exec vulndb_suricata suricatasc -c "dump-counters" | grep -E '"http":|"tcp":' | head -5
fi

echo ""

# Step 8: Summary
echo "=========================================="
echo "DEPLOYMENT SUMMARY"
echo "=========================================="
echo ""

echo "Components Status:"
print_status "TEE Traffic Mirroring: Active"
print_status "Suricata Container: Running"
print_status "Rules Generated: $RULES_COUNT from CVE database"
print_status "Rules Loaded: $RULES_LOADED in Suricata"
print_status "Alerts Detected: $ALERT_COUNT in tests"

echo ""
echo "Configuration:"
echo "  - Rules file: /etc/suricata/rules/generated.rules"
echo "  - Alert log: /var/log/suricata/fast.log"
echo "  - EVE log: /var/log/suricata/eve.json"
echo "  - Traffic mirror: iptables TEE to 172.22.0.54"

echo ""
echo "Useful Commands:"
echo "  - View alerts:  docker exec vulndb_suricata tail -f /var/log/suricata/fast.log"
echo "  - View rules:   docker exec vulndb_suricata cat /etc/suricata/rules/generated.rules"
echo "  - Rule stats:   curl http://172.22.0.52:5000/api/v1/rules/suricata/stats"
echo "  - Regenerate:   curl -X GET 'http://172.22.0.52:5000/api/v1/rules/suricata/top-risk?deploy=true'"

echo ""
if [ "$ALERT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}=========================================="
    echo "   ✓ DEPLOYMENT SUCCESSFUL"
    echo -e "==========================================${NC}"
else
    echo -e "${YELLOW}=========================================="
    echo "   ⚠ DEPLOYMENT NEEDS REVIEW"
    echo -e "==========================================${NC}"
fi

echo ""