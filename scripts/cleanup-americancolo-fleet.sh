#!/bin/bash
# Cleanup script for AmericanColo fleet
# This removes monitoring-related containers and exporter services
# PRESERVES: registry, netbootxyz, watchtower, and all Docker containers on workers
# Does NOT reboot any machines

set -e

# Configuration
MASTER_IP="88.0.33.141"
SSH_KEY="~/.ssh/ubuntu_key"
SSH_USER="root"

# Worker server IP pattern: 88.0.X.1
# Brickbox: 1-12, 25-48
# RunpodCCC: 96-99
BRICKBOX_SERVERS="1 2 3 4 5 6 7 8 9 10 11 12 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48"
RUNPOD_SERVERS="96 97 98 99"
ALL_WORKERS="${BRICKBOX_SERVERS} ${RUNPOD_SERVERS}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AmericanColo Fleet Cleanup ===${NC}"
echo -e "${CYAN}Master: ${MASTER_IP}${NC}"
echo -e "${CYAN}Workers: $(echo ${ALL_WORKERS} | wc -w) servers${NC}"
echo ""

# Containers to REMOVE on master (monitoring-related only)
# Note: registry, netbootxyz are PRESERVED
# Old monitoring: admin-grafana-1, admin-prometheus-1, admin-db-1, cadvisor, my-node-exporter
# DC Overview containers: cryptolabs-proxy, dc-overview, prometheus, grafana, ipmi-monitor, vastai-exporter
REMOVE_CONTAINERS="admin-grafana-1 admin-prometheus-1 admin-db-1 ipmi-monitor cadvisor my-node-exporter watchtower cryptolabs-proxy dc-overview prometheus grafana vastai-exporter"

# Exporter services to remove on workers (systemd services only, no Docker!)
# - node_exporter: from jjziets/DCMontoring install_node_exporter.sh
# - dcgm-exporter: from jjziets/DCMontoring install_NvidiaDCGM_Exporter.sh
# - dc-exporter: old dc-exporter (dc-overview will install dc-exporter-rs)
# - gddr6-metrics-exporter: legacy (may already be cleared)
# - dcgm, nvidia-dcgm: NVIDIA DCGM daemon (replaced by dc-exporter-rs for GPU metrics)
EXPORTER_SERVICES="node_exporter dc-exporter dcgm-exporter gddr6-metrics-exporter dcgm nvidia-dcgm"

# Function to run SSH command on master
ssh_master() {
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i ${SSH_KEY} ${SSH_USER}@${MASTER_IP} "$@"
}

# Function to run SSH command on worker
ssh_worker() {
    local subnet=$1
    shift
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -i ${SSH_KEY} ${SSH_USER}@88.0.${subnet}.1 "$@" 2>/dev/null
}

# ============================================================================
# Step 1: Clean master node (BBmain)
# ============================================================================
echo -e "${YELLOW}Step 1: Cleaning master node (${MASTER_IP})...${NC}"
echo ""

echo "  Containers to PRESERVE: registry, netbootxyz"
echo "  Containers to REMOVE: ${REMOVE_CONTAINERS}"
echo ""

# Stop and remove monitoring containers on master (one by one so missing names don't skip the rest)
echo "  Stopping monitoring containers..."
for c in ${REMOVE_CONTAINERS}; do
  ssh_master "docker stop ${c} 2>/dev/null && echo \"    stopped ${c}\" || true"
done

echo "  Removing monitoring containers..."
for c in ${REMOVE_CONTAINERS}; do
  ssh_master "docker rm ${c} 2>/dev/null && echo \"    removed ${c}\" || true"
done

# Remove exporter services on master (if any)
echo "  Removing exporter services on master..."
for svc in ${EXPORTER_SERVICES}; do
    ssh_master "systemctl stop ${svc} 2>/dev/null || true"
    ssh_master "systemctl disable ${svc} 2>/dev/null || true"
    ssh_master "rm -f /etc/systemd/system/${svc}.service 2>/dev/null || true"
done
ssh_master "systemctl daemon-reload 2>/dev/null || true"

# Prune unused volumes (only those not in use)
echo "  Pruning unused volumes..."
ssh_master "docker volume prune -f 2>/dev/null || true"

# Prune unused images
echo "  Pruning unused images..."
ssh_master "docker image prune -f 2>/dev/null || true"

echo -e "${GREEN}  ✓ Master node cleaned${NC}"
echo ""

# Show remaining containers on master
echo "  Remaining containers on master:"
ssh_master "docker ps --format 'table {{.Names}}\t{{.Status}}'" | head -10
echo ""

# ============================================================================
# Step 2: Clean exporter services on workers (PARALLEL - max 64 concurrent)
# ============================================================================
echo -e "${YELLOW}Step 2: Cleaning exporter services on workers...${NC}"
echo -e "${CYAN}  Note: Docker containers on workers are NOT affected${NC}"
echo -e "${CYAN}  Running cleanup in parallel (max 64 concurrent)...${NC}"
echo ""

# Max parallel jobs
MAX_PARALLEL=64

# Temp directory for results
RESULT_DIR=$(mktemp -d)
trap "rm -rf ${RESULT_DIR}" EXIT

# Counter for progress
total=$(echo ${ALL_WORKERS} | wc -w)

# Function to clean a single worker (runs in background)
clean_worker() {
    local subnet=$1
    local worker_ip="88.0.${subnet}.1"
    local result_file="${RESULT_DIR}/${subnet}.result"
    
    # Check if worker is reachable
    if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -i ${SSH_KEY} ${SSH_USER}@${worker_ip} "echo 1" > /dev/null 2>&1; then
        echo "UNREACHABLE" > "${result_file}"
        return
    fi
    
    # Get hostname
    hostname=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -i ${SSH_KEY} ${SSH_USER}@${worker_ip} "hostname" 2>/dev/null || echo "unknown")
    
    # Run all cleanup in a single SSH command for speed
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 -o BatchMode=yes -i ${SSH_KEY} ${SSH_USER}@${worker_ip} "
        for svc in node_exporter dc-exporter dcgm-exporter gddr6-metrics-exporter dcgm nvidia-dcgm; do
            systemctl stop \${svc} 2>/dev/null || true
            systemctl disable \${svc} 2>/dev/null || true
            rm -f /etc/systemd/system/\${svc}.service 2>/dev/null || true
        done
        systemctl daemon-reload 2>/dev/null || true
        rm -f /usr/local/bin/node_exporter /usr/local/bin/dc-exporter* /opt/dc-exporter/* 2>/dev/null || true
    " 2>/dev/null
    
    echo "OK:${hostname}" > "${result_file}"
}

# Launch all workers in parallel (with max limit)
running=0
for subnet in ${ALL_WORKERS}; do
    clean_worker ${subnet} &
    running=$((running + 1))
    
    # Limit concurrent jobs
    if [ ${running} -ge ${MAX_PARALLEL} ]; then
        wait -n 2>/dev/null || wait
        running=$((running - 1))
    fi
done

# Wait for all remaining jobs
wait

# Collect and display results
echo "  Results:"
ok_count=0
fail_count=0
for subnet in ${ALL_WORKERS}; do
    worker_ip="88.0.${subnet}.1"
    result_file="${RESULT_DIR}/${subnet}.result"
    
    if [ -f "${result_file}" ]; then
        result=$(cat "${result_file}")
        if [ "${result}" = "UNREACHABLE" ]; then
            echo -e "    ${worker_ip}: ${RED}UNREACHABLE${NC}"
            fail_count=$((fail_count + 1))
        else
            hostname=$(echo "${result}" | cut -d: -f2)
            echo -e "    ${hostname} (${worker_ip}): ${GREEN}✓ cleaned${NC}"
            ok_count=$((ok_count + 1))
        fi
    else
        echo -e "    ${worker_ip}: ${RED}NO RESULT${NC}"
        fail_count=$((fail_count + 1))
    fi
done

echo ""
echo -e "  ${GREEN}✓ ${ok_count} workers cleaned${NC}, ${RED}${fail_count} failed${NC}"

echo ""

# ============================================================================
# Step 3: Verification
# ============================================================================
echo -e "${YELLOW}Step 3: Verification...${NC}"
echo ""

echo "  Master containers (should see registry, netbootxyz only):"
ssh_master "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'"
echo ""

echo "  Sample worker check (88.0.1.1):"
echo "    Exporter services:"
ssh_worker 1 "systemctl list-units --type=service | grep -E 'node_exporter|dcgm|dc-exporter|gddr6' || echo '    (none running)'"
echo ""

# ============================================================================
# Complete
# ============================================================================
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "Summary:"
echo "  • Master: Removed ALL monitoring containers (old + dc-overview), kept registry/netbootxyz"
echo "  • Workers: Removed exporter systemd services, Docker containers untouched"
echo "  • No reboots performed"
echo ""
echo "To redeploy dc-overview:"
echo "  ssh ${SSH_USER}@${MASTER_IP} -i ${SSH_KEY}"
echo "  pip install --force-reinstall git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages"
echo "  dc-overview quickstart -c /root/dc-overview-config.yaml -y"
