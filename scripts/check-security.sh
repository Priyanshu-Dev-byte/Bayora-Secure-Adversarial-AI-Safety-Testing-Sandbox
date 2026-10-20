#!/usr/bin/env bash
# =============================================================================
# Bayora — Container Security Check Script
# Prints the effective security settings for each sandbox container.
#
# Usage: bash scripts/check-security.sh
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

CONTAINERS=("bayora-red" "bayora-blue" "bayora-client-llm" "bayora-gateway" "bayora-control-plane")

check_pass() { echo -e "  ${GREEN}✓${NC} $1: $2"; }
check_fail() { echo -e "  ${RED}✗${NC} $1: $2"; }
check_info() { echo -e "  ${CYAN}ℹ${NC} $1: $2"; }

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Bayora — Container Security Audit Report            ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

for CONTAINER in "${CONTAINERS[@]}"; do
    echo -e "${YELLOW}━━━ ${CONTAINER} ━━━${NC}"

    # Check if container is running
    if ! docker inspect "$CONTAINER" &>/dev/null; then
        check_fail "Status" "Container not found or not running"
        echo ""
        continue
    fi

    # --- User (non-root check) ---
    USER_ID=$(docker exec "$CONTAINER" id -u 2>/dev/null || echo "unknown")
    if [ "$USER_ID" = "0" ]; then
        check_fail "User" "Running as root (UID 0)"
    elif [ "$USER_ID" = "unknown" ]; then
        check_info "User" "Could not determine (exec may be blocked)"
    else
        check_pass "User" "Non-root (UID $USER_ID)"
    fi

    # --- Capabilities ---
    CAP_ADD=$(docker inspect --format '{{.HostConfig.CapAdd}}' "$CONTAINER" 2>/dev/null)
    CAP_DROP=$(docker inspect --format '{{.HostConfig.CapDrop}}' "$CONTAINER" 2>/dev/null)
    if echo "$CAP_DROP" | grep -qi "all"; then
        check_pass "Capabilities" "cap_drop=ALL, cap_add=${CAP_ADD}"
    else
        check_fail "Capabilities" "cap_drop is not ALL (got: $CAP_DROP)"
    fi

    # --- Seccomp ---
    SECCOMP=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$CONTAINER" 2>/dev/null)
    if echo "$SECCOMP" | grep -qi "seccomp"; then
        check_pass "Seccomp" "Custom profile applied"
    else
        check_info "Seccomp" "Using Docker default (${SECCOMP})"
    fi

    # --- No New Privileges ---
    if echo "$SECCOMP" | grep -qi "no-new-privileges"; then
        check_pass "NoNewPrivs" "Enabled"
    else
        check_fail "NoNewPrivs" "Not enabled"
    fi

    # --- Read-only Root Filesystem ---
    READONLY=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER" 2>/dev/null)
    if [ "$READONLY" = "true" ]; then
        check_pass "Filesystem" "Read-only root filesystem"
    else
        check_fail "Filesystem" "Root filesystem is writable"
    fi

    # --- Verify read-only by attempting a write ---
    WRITE_TEST=$(docker exec "$CONTAINER" sh -c "touch /test_write 2>&1" 2>/dev/null || true)
    if echo "$WRITE_TEST" | grep -qi "read-only\|permission denied"; then
        check_pass "Write Test" "Write to / correctly denied"
    fi

    # --- Resource Limits ---
    MEM_LIMIT=$(docker inspect --format '{{.HostConfig.Memory}}' "$CONTAINER" 2>/dev/null)
    CPU_LIMIT=$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$CONTAINER" 2>/dev/null)
    PID_LIMIT=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$CONTAINER" 2>/dev/null)

    if [ "$MEM_LIMIT" != "0" ] && [ -n "$MEM_LIMIT" ]; then
        MEM_MB=$((MEM_LIMIT / 1048576))
        check_pass "Memory Limit" "${MEM_MB} MB"
    else
        check_fail "Memory Limit" "Unlimited"
    fi

    if [ "$CPU_LIMIT" != "0" ] && [ -n "$CPU_LIMIT" ]; then
        CPU_CORES=$(echo "scale=2; $CPU_LIMIT / 1000000000" | bc 2>/dev/null || echo "$CPU_LIMIT nanocpus")
        check_pass "CPU Limit" "${CPU_CORES} cores"
    else
        check_fail "CPU Limit" "Unlimited"
    fi

    if [ "$PID_LIMIT" != "0" ] && [ "$PID_LIMIT" != "-1" ] && [ -n "$PID_LIMIT" ]; then
        check_pass "PID Limit" "$PID_LIMIT processes"
    else
        check_fail "PID Limit" "Unlimited"
    fi

    # --- Privileged Mode ---
    PRIVILEGED=$(docker inspect --format '{{.HostConfig.Privileged}}' "$CONTAINER" 2>/dev/null)
    if [ "$PRIVILEGED" = "false" ]; then
        check_pass "Privileged" "Disabled"
    else
        check_fail "Privileged" "ENABLED — this is a security risk!"
    fi

    # --- Network ---
    NETWORKS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CONTAINER" 2>/dev/null)
    check_info "Networks" "$NETWORKS"

    echo ""
done

echo -e "${BOLD}━━━ Network Isolation Summary ━━━${NC}"
echo ""
RED_NETS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' bayora-red 2>/dev/null || echo "N/A")
BLUE_NETS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' bayora-blue 2>/dev/null || echo "N/A")
LLM_NETS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' bayora-client-llm 2>/dev/null || echo "N/A")
GW_NETS=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' bayora-gateway 2>/dev/null || echo "N/A")

check_info "Red networks" "$RED_NETS"
check_info "Blue networks" "$BLUE_NETS"
check_info "LLM networks" "$LLM_NETS"
check_info "Gateway networks" "$GW_NETS"

# Check Red↔Blue isolation
if echo "$RED_NETS" | grep -q "blue" || echo "$BLUE_NETS" | grep -q "red"; then
    check_fail "Isolation" "Red and Blue share a network!"
else
    check_pass "Isolation" "Red and Blue share NO network"
fi

echo ""
echo -e "${BOLD}Security audit complete.${NC}"
