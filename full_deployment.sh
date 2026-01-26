#!/bin/bash
# Complete Suricata rules deployment (INTERACTIVE VERSION)
# Generates rules from MongoDB CVEs and tests detection
# Executes API calls from inside docker network

# ==========================
# NEW: Attack mode selector
# ==========================
# IT  = existing HTTP attack simulations (default)
# 5G  = safe 5G interface stimulation (NO flood / NO destructive tests)
ATTACK_MODE=${ATTACK_MODE:-"IT"}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Global variables for stats
RULES_COUNT=0
RULES_IN_FILE=0
LOADED=0
FINAL_LOADED="N/A"
ALERT_COUNT=0

# Step 1: Generate rules
step1_generate_rules() {
    echo "=========================================="
    echo "STEP 1: Generating Rules from CVE Database"
    echo "=========================================="
    echo ""

    print_status "Querying API to generate rules for top-risk CVEs..."
    echo "  Risk levels: CRITICAL, HIGH, MEDIUM"
    echo "  Attack vectors: NETWORK,LOCAL,ADJACENT,PHYSICAL"
    echo "  Limit: 150 CVEs"
    echo ""

    RESPONSE=$(docker exec vulndb_attacker curl -s -X GET "http://172.22.0.52:5000/api/v1/rules/suricata/top-risk?risk=CRITICAL,HIGH,MEDIUM&attack_vector=NETWORK,LOCAL,ADJACENT,PHYSICAL&limit=200&deploy=true")    

    if [ $? -eq 0 ] && [ -n "$RESPONSE" ]; then
        if echo "$RESPONSE" | jq . > /dev/null 2>&1; then
            STATUS=$(echo "$RESPONSE" | jq -r '.status // "error"')
            
            if [ "$STATUS" = "success" ]; then
                RULES_COUNT=$(echo "$RESPONSE" | jq -r '.stats.rules_generated // 0')
                print_status "Generated $RULES_COUNT rules successfully"
                
                echo ""
                echo "Generation Statistics:"
                echo "$RESPONSE" | jq '.stats'
            else
                ERROR_MSG=$(echo "$RESPONSE" | jq -r '.message // "Unknown error"')
                print_error "API returned error: $ERROR_MSG"
                return 1
            fi
        else
            print_error "API returned invalid JSON"
            return 1
        fi
    else
        print_error "Failed to connect to API"
        return 1
    fi
    echo ""
}

# Step 2: Verify rules
step2_verify_rules() {
    echo "=========================================="
    echo "STEP 2: Verifying Generated Rules"
    echo "=========================================="
    echo ""

    print_status "Checking generated rules file..."
    RULES_IN_FILE=$(docker exec vulndb_suricata wc -l /etc/suricata/rules/generated.rules 2>/dev/null | awk '{print $1}' || echo "0")

    if [ "$RULES_IN_FILE" -eq 0 ]; then
        print_error "Rules file is empty or doesn't exist!"
        return 1
    fi

    print_status "Rules file contains $RULES_IN_FILE lines"

    echo ""
    print_status "Sample of generated rules:"
    docker exec vulndb_suricata head -5 /etc/suricata/rules/generated.rules

    echo ""
}

# Step 3: Test syntax
step3_test_syntax() {
    echo "=========================================="
    echo "STEP 3: Testing Suricata Syntax"
    echo "=========================================="
    echo ""

    print_status "Running Suricata syntax test..."
    SYNTAX_TEST=$(docker exec vulndb_suricata suricata -T -c /etc/suricata/suricata.yaml -l /tmp 2>&1)

    if echo "$SYNTAX_TEST" | grep -q "successfully loaded"; then
        LOADED=$(echo "$SYNTAX_TEST" | grep -oP '\d+(?= rules successfully loaded)' || echo "unknown")
        print_status "Syntax test passed: $LOADED rules validated"
    else
        print_error "Syntax test failed!"
        echo "$SYNTAX_TEST" | tail -20
        return 1
    fi

    echo ""
}

# Step 4: Verify Suricata status
step4_verify_status() {
    echo "=========================================="
    echo "STEP 4: Verifying Suricata Status"
    echo "=========================================="
    echo ""

    print_status "Checking if Suricata is running..."

    if docker exec vulndb_suricata ps aux | grep suricata | grep -v grep > /dev/null 2>&1; then
        print_status "Suricata is already running"
        
        LOADED_FROM_LOG=$(docker exec vulndb_suricata cat /var/log/suricata/suricata.log 2>/dev/null | grep "rules successfully loaded" | tail -1 | grep -oP '\d+(?= rules successfully loaded)' || echo "unknown")
        
        if [ "$LOADED_FROM_LOG" != "unknown" ] && [ "$LOADED_FROM_LOG" != "" ]; then
            print_status "Currently loaded: $LOADED_FROM_LOG rules"
            
            if [ "$LOADED_FROM_LOG" != "$LOADED" ] && [ "$LOADED" != "unknown" ]; then
                print_warning "Rules changed ($LOADED_FROM_LOG -> $LOADED), reloading rules..."
                
                SURICATA_PID=$(docker exec vulndb_suricata ps aux | grep suricata | grep -v grep | awk '{print $2}')
                if [ -n "$SURICATA_PID" ]; then
                    docker exec vulndb_suricata kill -USR2 $SURICATA_PID 2>/dev/null || true
                    sleep 5
                    print_status "Rules reloaded via signal (no restart needed)"
                fi
            else
                print_status "Rules are up to date, no reload needed"
            fi
        fi
    else
        print_warning "Suricata not running, starting container..."
        docker start vulndb_suricata > /dev/null 2>&1
        sleep 15
        
        if docker exec vulndb_suricata ps aux | grep suricata | grep -v grep > /dev/null 2>&1; then
            print_status "Suricata started successfully"
        else
            print_error "Failed to start Suricata"
            return 1
        fi
    fi

    echo ""
}

# Step 5: Verify runtime
step5_verify_runtime() {
    echo "=========================================="
    echo "STEP 5: Verifying Runtime Status"
    echo "=========================================="
    echo ""

    sleep 3

    FINAL_LOADED=$(docker exec vulndb_suricata cat /var/log/suricata/suricata.log 2>/dev/null | grep "rules successfully loaded" | tail -1 | grep -oP '\d+(?= rules successfully loaded)' || echo "N/A")

    if [ "$FINAL_LOADED" != "N/A" ]; then
        print_status "Suricata is running with $FINAL_LOADED rules loaded"
    else
        print_warning "Could not verify loaded rules count"
    fi

    ERROR_COUNT=$(docker exec vulndb_suricata cat /var/log/suricata/suricata.log 2>/dev/null | tail -50 | grep -i "error" | wc -l || echo "0")

    if [ "$ERROR_COUNT" -gt 0 ]; then
        print_warning "Found $ERROR_COUNT errors in recent logs"
    else
        print_status "No errors detected in recent logs"
    fi

    echo ""
}

# =========================================================
# NEW: Safe 5G interface stimulation (NO FLOOD / NO DESTRUCT)
# =========================================================

# Utility: check if a container exists
container_exists() {
    docker ps -a --format '{{.Names}}' | grep -qx "$1"
}

# Utility: run a command in a container if exists
docker_exec_safe() {
    local cname="$1"
    shift
    if container_exists "$cname"; then
        docker exec "$cname" "$@" 2>/dev/null
        return $?
    else
        return 127
    fi
}

# Safe UDP poke (few packets, controlled)
safe_udp_poke() {
    local target_ip="$1"
    local target_port="$2"
    local label="$3"
    local count="${4:-5}"
    local delay="${5:-0.2}"

    print_info "Sending ${count} small UDP datagrams to ${target_ip}:${target_port} (${label})"
    # Using bash /dev/udp inside attacker container (safe, rate-limited)
    for i in $(seq 1 "$count"); do
        docker exec vulndb_attacker bash -lc "echo -n '5g-test-${label}-${i}' > /dev/udp/${target_ip}/${target_port}" >/dev/null 2>&1 || true
        sleep "$delay"
    done
}

# Safe SBI HTTP calls (benign payloads; no auth bypass attempts)
safe_sbi_http_calls() {
    local base="$1"
    local label="$2"
    print_info "SBI safe calls to ${base} (${label})"

    # GET health-ish paths (won't exist sometimes; still generates HTTP traffic)
    docker exec vulndb_attacker curl -s -m 2 "${base}/" >/dev/null 2>&1 || true
    sleep 0.3
    docker exec vulndb_attacker curl -s -m 2 "${base}/health" >/dev/null 2>&1 || true
    sleep 0.3

    # POST benign JSON (intentionally generic)
    docker exec vulndb_attacker curl -s -m 2 -X POST "${base}/test" \
        -H "Content-Type: application/json" \
        -d '{"test":"5g-sbi-safe","ts":123}' >/dev/null 2>&1 || true
    sleep 0.3
}

# N1-ish: trigger UE actions (if nr-cli exists)
safe_n1_ue_actions() {
    print_info "N1/NAS safe stimulation via UE actions (UERANSIM)"
    if docker_exec_safe ueransim-ue1 bash -lc "command -v nr-cli" >/dev/null 2>&1; then
        docker exec ueransim-ue1 bash -lc "nr-cli --exec 'status'" >/dev/null 2>&1 || true
        sleep 0.5
        docker exec ueransim-ue1 bash -lc "nr-cli --exec 'deregister'" >/dev/null 2>&1 || true
        sleep 0.8
        # A gentle re-register attempt depends on your UE config; keep it non-destructive:
        docker exec ueransim-ue1 bash -lc "nr-cli --exec 'register'" >/dev/null 2>&1 || true
    else
        print_warning "ueransim-ue1: nr-cli not found. Skipping UE actions."
    fi
}

# N2-ish: gentle gNB restart once (NO loop storms)
safe_n2_gnb_restart_once() {
    print_info "N2/NGAP safe stimulation via single gNB restart"
    # Try to restart the process once (safe)
    docker_exec_safe ueransim-gnb bash -lc "pkill -f nr-gnb" >/dev/null 2>&1 || true
    sleep 1
    # Attempt to start again if binary path exists; if not, just warn.
    if docker_exec_safe ueransim-gnb bash -lc "test -x /ueransim/build/nr-gnb" >/dev/null 2>&1; then
        docker exec -d ueransim-gnb bash -lc "/ueransim/build/nr-gnb -c /etc/ueransim/gnb.yaml" >/dev/null 2>&1 || true
        sleep 1.5
    else
        print_warning "ueransim-gnb: nr-gnb binary not found at /ueransim/build/nr-gnb. Skipping start."
    fi
}

# Step 6 (existing): Test detection (IT web attacks)
step6_test_detection() {
    echo "=========================================="
    echo "STEP 6: Testing Attack Detection"
    echo "=========================================="
    echo ""

    print_status "Clearing alert logs..."
    docker exec vulndb_suricata sh -c "> /var/log/suricata/fast.log" 2>/dev/null || true

    echo ""
    print_status "Running attack simulations..."

    echo "  Test 1: RCE with cmd parameter..."
    docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/?cmd=whoami" > /dev/null 2>&1 || true
    sleep 1

    echo "  Test 2: RCE with semicolon..."
    docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/?cmd=ls%3Bpwd" > /dev/null 2>&1 || true
    sleep 1

    echo "  Test 3: SQL Injection..."
    docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/?id=1%20UNION%20SELECT" > /dev/null 2>&1 || true
    sleep 1

    echo "  Test 4: Path Traversal..."
    docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/?file=../../../etc/passwd" > /dev/null 2>&1 || true
    sleep 1

    echo "  Test 5: XSS attempt..."
    docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/?q=<script>alert(1)</script>" > /dev/null 2>&1 || true
    sleep 1

    echo "  Test 6: Multiple commands..."
    docker exec vulndb_attacker curl -s "http://172.22.0.52:5000/?cmd=id;whoami;pwd" > /dev/null 2>&1 || true
    sleep 1

    print_status "Waiting for Suricata to process alerts..."
    sleep 5

    echo ""
}

# NEW Step 6G: Safe 5G interface stimulation
step6_test_detection_5g() {
    echo "=========================================="
    echo "STEP 6G: Testing 5G Interface Stimulation (SAFE)"
    echo "=========================================="
    echo ""

    print_warning "SAFE MODE: This generates controlled 5G-like traffic (no floods / no destructive tests)."
    echo ""

    print_status "Clearing alert logs..."
    docker exec vulndb_suricata sh -c "> /var/log/suricata/fast.log" 2>/dev/null || true
    sleep 1

    print_status "Running SAFE 5G interface stimulation..."
    echo ""

    # N1/NAS (UE actions)
    echo "  Test N1: UE actions (register/deregister/status)..."
    safe_n1_ue_actions
    sleep 1

    # N2/NGAP (single gNB restart)
    echo "  Test N2: Single gNB restart (NGAP reconnect)..."
    safe_n2_gnb_restart_once
    sleep 1

    # N11/SBI - example HTTP traffic to core components if they expose SBI endpoints in your setup
    # NOTE: Ports can differ depending on your Open5GS config; we keep it generic and non-failing-friendly.
    echo "  Test N11/SBI: Safe HTTP calls (best-effort)..."
    # Common Open5GS SBI ports vary; if you have a known one, set SBI_BASE env var, e.g. SBI_BASE="http://172.22.0.12:7777"
    if [ -n "${SBI_BASE:-}" ]; then
        safe_sbi_http_calls "$SBI_BASE" "SBI_BASE"
    else
        # Fallback to your existing API endpoint just to keep some HTTP traffic if SBI not configured
        safe_sbi_http_calls "http://172.22.0.52:5000" "Fallback-HTTP"
        print_warning "Set SBI_BASE env var to point to your SBI endpoint if available (e.g. http://AMF_IP:PORT)."
    fi
    sleep 1

    # N4/PFCP (SMF↔UPF) - SAFE: few UDP datagrams to UPF PFCP port (8805)
    echo "  Test N4/PFCP: Safe UDP pokes to UPF:8805..."
    safe_udp_poke "172.22.0.20" "8805" "PFCP" 6 0.2
    sleep 1

    # N3/GTP-U (User Plane) - SAFE: few UDP datagrams to UPF GTP-U port (2152)
    echo "  Test N3/GTP-U: Safe UDP pokes to UPF:2152..."
    safe_udp_poke "172.22.0.20" "2152" "GTPU" 6 0.2
    sleep 1

    print_status "Waiting for Suricata to process alerts..."
    sleep 5

    echo ""
}

# Step 7: Analyze results
step7_analyze_results() {
    echo "=========================================="
    echo "STEP 7: Detection Results"
    echo "=========================================="
    echo ""

    ALERT_COUNT=$(docker exec vulndb_suricata wc -l /var/log/suricata/fast.log 2>/dev/null | awk '{print $1}' || echo "0")

    if [ "$ALERT_COUNT" -gt 0 ]; then
        print_status "DETECTION WORKING! Generated $ALERT_COUNT alerts"
        
        echo ""
        echo "Alert Breakdown by Attack Type:"
        docker exec vulndb_suricata grep -oP '5G-[A-Za-z]+' /var/log/suricata/fast.log 2>/dev/null | sort | uniq -c | sort -rn | while read count type; do
            printf "  %-35s %s alerts\n" "→ $type:" "$count"
        done
        
        echo ""
        echo "Top 5 Most Triggered Rules (by SID):"
        docker exec vulndb_suricata cat /var/log/suricata/fast.log 2>/dev/null | \
            grep -oP '\[1:\K\d+' | sort | uniq -c | sort -rn | head -5 | \
            while read count sid; do
                # Get CVE ID from rules file
                CVE=$(docker exec vulndb_suricata grep "sid:$sid" /etc/suricata/rules/generated.rules 2>/dev/null | grep -oP 'CVE-\d{4}-\d+' | head -1)
                if [ -n "$CVE" ]; then
                    echo "  SID $sid ($CVE): $count alerts"
                else
                    echo "  SID $sid: $count alerts"
                fi
            done
        
        echo ""
        echo "Recent Alerts (Last 5):"
        docker exec vulndb_suricata tail -5 /var/log/suricata/fast.log 2>/dev/null | \
            grep -oP '\*\*\] \K.*?(?= \[\*\*)' | sed 's/^/  - /' || true
        
        echo ""
        print_status "✓ Detection is working correctly!"
    else
        print_warning "No alerts detected"
    fi

    echo ""
}

# Step 8: Summary
step8_summary() {
    echo "=========================================="
    echo "DEPLOYMENT SUMMARY"
    echo "=========================================="
    echo ""

    echo "Components Status:"
    if docker exec vulndb_suricata ps aux | grep suricata | grep -v grep > /dev/null 2>&1; then
        SURICATA_PID=$(docker exec vulndb_suricata ps aux | grep suricata | grep -v grep | awk '{print $2}')
        print_status "Suricata Container: Running (PID $SURICATA_PID)"
    else
        print_warning "Suricata Container: Status unknown"
    fi

    print_status "Rules Generated: $RULES_COUNT from CVE database"
    print_status "Rules in File: $RULES_IN_FILE lines"
    print_status "Rules Loaded: $FINAL_LOADED (runtime)"

    if [ "$ALERT_COUNT" -gt 0 ]; then
        print_status "Alerts Detected: $ALERT_COUNT in tests"
        echo ""
        echo "  Alert Breakdown by Attack Type:"
        
        # Use same optimized method as STEP 7
        docker exec vulndb_suricata grep -oP '5G-[A-Za-z]+' /var/log/suricata/fast.log 2>/dev/null | sort | uniq -c | sort -rn | while read count type; do
            printf "    %-38s %s alerts\n" "→ $type:" "$count"
        done
    else
        print_status "Alerts Detected: 0 in tests"
    fi

    echo ""
    echo "Configuration:"
    echo "  - Config file: /etc/suricata/suricata.yaml"
    echo "  - Rules file: /etc/suricata/rules/generated.rules"
    echo "  - Alert log: /var/log/suricata/fast.log"
    echo "  - EVE log: /var/log/suricata/eve.json"
    echo "  - API endpoint: http://172.22.0.52:5000"
    echo "  - Attack mode: $ATTACK_MODE"

    echo ""
    if [ "$ALERT_COUNT" -gt 0 ]; then
        echo -e "${GREEN}=========================================="
        echo "   ✓ DEPLOYMENT SUCCESSFUL"
        echo "   Detection system is fully operational"
        echo -e "==========================================${NC}"
    elif [ "$FINAL_LOADED" != "N/A" ] && [ "$FINAL_LOADED" != "0" ]; then
        echo -e "${YELLOW}=========================================="
        echo "   ⚠ DEPLOYMENT COMPLETE WITH WARNINGS"
        echo "   Rules loaded but no test alerts"
        echo -e "==========================================${NC}"
    else
        echo -e "${RED}=========================================="
        echo "   ✗ DEPLOYMENT NEEDS REVIEW"
        echo -e "==========================================${NC}"
    fi

    echo ""
}

# Show menu
show_menu() {
    clear
    echo "=========================================="
    echo "   VULNDB-5G DEPLOYMENT MANAGER"
    echo "=========================================="
    echo ""
    echo "Select operation:"
    echo ""
    echo "  [0] Run Full Deployment (All Steps)"
    echo ""
    echo "  [1] Generate Rules from CVE Database"
    echo "  [2] Verify Generated Rules"
    echo "  [3] Test Suricata Syntax"
    echo "  [4] Verify Suricata Status"
    echo "  [5] Verify Runtime Status"
    echo "  [6] Test Attack Detection (IT - HTTP)"
    echo "  [6g] Test 5G Interface Stimulation (SAFE)"
    echo "  [7] Analyze Detection Results"
    echo "  [8] Show Summary"
    echo ""
    echo "  [9] View Live Alerts (tail -f)"
    echo "  [h] Show Helpful Commands"
    echo "  [q] Quit"
    echo ""
    echo -n "Choice: "
}

# Show helpful commands
show_help() {
    echo ""
    echo "=========================================="
    echo "   HELPFUL COMMANDS"
    echo "=========================================="
    echo ""
    echo "View alerts:"
    echo "  docker exec vulndb_suricata tail -f /var/log/suricata/fast.log"
    echo ""
    echo "View EVE JSON:"
    echo "  docker exec vulndb_suricata tail -f /var/log/suricata/eve.json | jq"
    echo ""
    echo "View active rules:"
    echo "  docker exec vulndb_suricata grep ^alert /etc/suricata/rules/generated.rules | wc -l"
    echo ""
    echo "Check Suricata status:"
    echo "  docker exec vulndb_suricata ps aux | grep suricata"
    echo ""
    echo "Regenerate rules via API:"
    echo "  docker exec vulndb_attacker curl -X GET 'http://172.22.0.52:5000/api/v1/rules/suricata/top-risk?deploy=true&limit=100'"
    echo ""
    echo "Run SAFE 5G tests (full):"
    echo "  ATTACK_MODE=5G ./script.sh --full"
    echo ""
    echo "Optional: set SBI endpoint base:"
    echo "  SBI_BASE='http://172.22.0.12:7777' ATTACK_MODE=5G ./script.sh --full"
    echo ""
    echo "Press Enter to continue..."
    read
}

# View live alerts
view_live_alerts() {
    echo ""
    print_info "Showing live alerts (Ctrl+C to stop)..."
    echo ""
    docker exec vulndb_suricata tail -f /var/log/suricata/fast.log
}

# Main execution
main() {
    if [ "$1" = "--full" ] || [ "$1" = "-f" ]; then
        # Run full deployment without menu
        echo "=========================================="
        echo "VULNDB-5G COMPLETE RULES DEPLOYMENT"
        echo "=========================================="
        echo ""
        
        step1_generate_rules || exit 1
        step2_verify_rules || exit 1
        step3_test_syntax || exit 1
        step4_verify_status || exit 1
        step5_verify_runtime || exit 1

        # NEW: choose IT vs SAFE 5G stimulation
        if [ "$ATTACK_MODE" = "5G" ] || [ "$ATTACK_MODE" = "5g" ]; then
            step6_test_detection_5g || exit 1
        else
            step6_test_detection || exit 1
        fi

        step7_analyze_results || exit 1
        step8_summary
        exit 0
    fi

    # Interactive menu mode
    while true; do
        show_menu
        read choice
        
        case $choice in
            0)
                clear
                step1_generate_rules && \
                step2_verify_rules && \
                step3_test_syntax && \
                step4_verify_status && \
                step5_verify_runtime && \
                ( \
                  if [ "$ATTACK_MODE" = "5G" ] || [ "$ATTACK_MODE" = "5g" ]; then \
                    step6_test_detection_5g; \
                  else \
                    step6_test_detection; \
                  fi \
                ) && \
                step7_analyze_results && \
                step8_summary
                echo ""
                echo "Press Enter to continue..."
                read
                ;;
            1) clear; step1_generate_rules; echo "Press Enter to continue..."; read ;;
            2) clear; step2_verify_rules; echo "Press Enter to continue..."; read ;;
            3) clear; step3_test_syntax; echo "Press Enter to continue..."; read ;;
            4) clear; step4_verify_status; echo "Press Enter to continue..."; read ;;
            5) clear; step5_verify_runtime; echo "Press Enter to continue..."; read ;;
            6) clear; step6_test_detection; echo "Press Enter to continue..."; read ;;
            6g|6G) clear; step6_test_detection_5g; echo "Press Enter to continue..."; read ;;
            7) clear; step7_analyze_results; echo "Press Enter to continue..."; read ;;
            8) clear; step8_summary; echo "Press Enter to continue..."; read ;;
            9) clear; view_live_alerts ;;
            h|H) clear; show_help ;;
            q|Q) echo ""; echo "Exiting..."; exit 0 ;;
            *) echo "Invalid option. Press Enter to continue..."; read ;;
        esac
    done
}

# Run main with arguments
main "$@"
