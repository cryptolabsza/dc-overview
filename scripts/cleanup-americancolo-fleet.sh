#!/bin/bash
# Cleanup script for AmericanColo fleet
# This removes ALL monitoring-related containers, images, and volumes
# PRESERVES: registry, netbootxyz, and all Docker containers on workers
# Does NOT reboot any machines
# Designed for testing - ensures fresh images on next deploy

# NOTE: We do NOT use 'set -e' because cleanup commands may fail (e.g., item doesn't exist)
# and we want to continue cleaning up everything regardless

# Configuration
MASTER_IP="88.0.33.141"
SSH_KEY="${HOME}/.ssh/ubuntu_key"
SSH_USER="root"

# Worker server IP pattern: 88.0.X.1
# Brickbox: 1-11 (12 is offline), 25-48
# RunpodCCC: 95-99
BRICKBOX_SERVERS="1 2 3 4 5 6 7 8 9 10 11 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48"
RUNPOD_SERVERS="95 96 97 98 99"
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

# Pre-flight checks
if [ ! -f "${SSH_KEY}" ]; then
    echo -e "${RED}ERROR: SSH key not found at ${SSH_KEY}${NC}"
    exit 1
fi

if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes -i "${SSH_KEY}" "${SSH_USER}@${MASTER_IP}" "echo connected" >/dev/null 2>&1; then
    echo -e "${RED}ERROR: Cannot connect to master ${SSH_USER}@${MASTER_IP} with key ${SSH_KEY}${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Pre-flight checks passed${NC}"
echo ""

# Containers to REMOVE on master (monitoring-related only)
# Note: registry, netbootxyz are PRESERVED
# Old monitoring: admin-grafana-1, admin-prometheus-1, admin-db-1, cadvisor, my-node-exporter
# DC Overview containers: cryptolabs-proxy, dc-overview, prometheus, grafana, ipmi-monitor, vastai-exporter, runpod-exporter
# Also includes docker-compose prefixed versions
REMOVE_CONTAINERS="admin-grafana-1 admin-prometheus-1 admin-db-1 ipmi-monitor cadvisor my-node-exporter watchtower cryptolabs-proxy dc-overview prometheus grafana vastai-exporter runpod-exporter certbot"

# Container name patterns for wildcard matching (catches docker-compose prefixed names)
CONTAINER_PATTERNS="grafana prometheus ipmi-monitor dc-overview cryptolabs-proxy vastai-exporter runpod-exporter certbot"

# Exporter services to remove on workers (systemd services only, no Docker!)
# - node_exporter: from jjziets/DCMontoring install_node_exporter.sh
# - dcgm-exporter: from jjziets/DCMontoring install_NvidiaDCGM_Exporter.sh
# - dc-exporter: old dc-exporter (dc-overview will install dc-exporter-rs)
# - gddr6-metrics-exporter: legacy (may already be cleared)
# - dcgm, nvidia-dcgm: NVIDIA DCGM daemon (replaced by dc-exporter-rs for GPU metrics)
# - dc-watchdog-agent: DC Watchdog external monitoring agent
EXPORTER_SERVICES="node_exporter dc-exporter dcgm-exporter gddr6-metrics-exporter dcgm nvidia-dcgm dc-watchdog-agent"

# DC Watchdog agent directories to remove
DC_WATCHDOG_DIRS="/opt/dc-watchdog /etc/dc-watchdog"

# Config directories to remove (created by setup commands)
CONFIG_DIRS="/etc/ipmi-monitor /etc/dc-overview /etc/cryptolabs-proxy"

# Legacy exporter files to remove
LEGACY_EXPORTER_FILES="/opt/runpod_exporter.py /opt/vastai_exporter.py /opt/runpod-exporter /opt/vastai-exporter"

# Ports to check for legacy host-based exporters
EXPORTER_PORTS="8622 8623"

# Function to run SSH command on master
ssh_master() {
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "${SSH_KEY}" "${SSH_USER}@${MASTER_IP}" "$@"
}

# Function to run SSH command on worker
ssh_worker() {
    local subnet=$1
    shift
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes -i "${SSH_KEY}" "${SSH_USER}@88.0.${subnet}.1" "$@" 2>/dev/null
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

# Also stop containers matching patterns (catches docker-compose prefixed names like root_grafana_1)
echo "  Stopping containers by pattern..."
for pattern in ${CONTAINER_PATTERNS}; do
  ssh_master "docker ps -a --format '{{.Names}}' | grep -i '${pattern}' | xargs -r docker stop 2>/dev/null || true"
done

echo "  Removing monitoring containers..."
for c in ${REMOVE_CONTAINERS}; do
  ssh_master "docker rm -f ${c} 2>/dev/null && echo \"    removed ${c}\" || true"
done

# Also remove containers matching patterns
echo "  Removing containers by pattern..."
for pattern in ${CONTAINER_PATTERNS}; do
  ssh_master "docker ps -a --format '{{.Names}}' | grep -i '${pattern}' | xargs -r docker rm -f 2>/dev/null || true"
done

# Remove exporter services on master (if any)
echo "  Removing exporter services on master..."
for svc in ${EXPORTER_SERVICES}; do
    ssh_master "systemctl stop ${svc} 2>/dev/null || true"
    ssh_master "systemctl disable ${svc} 2>/dev/null || true"
    ssh_master "rm -f /etc/systemd/system/${svc}.service 2>/dev/null || true"
done
ssh_master "systemctl daemon-reload 2>/dev/null || true"

# Kill any host-based exporters running on ports 8622/8623 (legacy installations)
echo "  Killing legacy host-based exporters..."
for port in ${EXPORTER_PORTS}; do
    ssh_master "lsof -t -i :${port} 2>/dev/null | xargs -r kill -9 && echo \"    killed process on port ${port}\" || true"
done

# Free ports 80/443 for proxy (stop nginx/apache, kill any processes)
echo "  Freeing ports 80 and 443..."
ssh_master "systemctl stop nginx 2>/dev/null && echo '    stopped nginx' || true"
ssh_master "systemctl disable nginx 2>/dev/null || true"
ssh_master "systemctl stop apache2 2>/dev/null && echo '    stopped apache2' || true"
ssh_master "systemctl disable apache2 2>/dev/null || true"
for port in 80 443; do
    ssh_master "lsof -t -i :${port} 2>/dev/null | xargs -r kill -9 && echo \"    killed process on port ${port}\" || true"
    ssh_master "fuser -k ${port}/tcp 2>/dev/null && echo \"    killed process on port ${port} (fuser)\" || true"
done

# Remove legacy exporter files
echo "  Removing legacy exporter files..."
for file in ${LEGACY_EXPORTER_FILES}; do
    ssh_master "rm -f ${file} 2>/dev/null && echo \"    removed ${file}\" || true"
done

# Remove DC Watchdog agent directories on master
echo "  Removing DC Watchdog agent..."
for dir in ${DC_WATCHDOG_DIRS}; do
    ssh_master "rm -rf ${dir} 2>/dev/null && echo \"    removed ${dir}\" || true"
done

# Remove config directories (created by setup commands)
echo "  Removing config directories..."
for dir in ${CONFIG_DIRS}; do
    ssh_master "rm -rf ${dir} 2>/dev/null && echo \"    removed ${dir}\" || true"
done

# Remove IPMI Monitor database files that may exist outside volumes
echo "  Removing stale database files..."
ssh_master "rm -rf /var/lib/ipmi-monitor 2>/dev/null || true"

# Uninstall pip packages and clear cache
echo "  Uninstalling pip packages..."
ssh_master "pip uninstall dc-overview -y --break-system-packages 2>/dev/null || true"
ssh_master "pip uninstall ipmi-monitor -y --break-system-packages 2>/dev/null || true"
ssh_master "pip uninstall cryptolabs-proxy -y --break-system-packages 2>/dev/null || true"
ssh_master "pip cache purge 2>/dev/null || true"

# Remove pipx installations (these shadow pip installs via ~/.local/bin)
echo "  Removing pipx installations..."
ssh_master "pipx uninstall dc-overview 2>/dev/null && echo '    pipx: removed dc-overview' || true"
ssh_master "pipx uninstall ipmi-monitor 2>/dev/null && echo '    pipx: removed ipmi-monitor' || true"
ssh_master "pipx uninstall cryptolabs-proxy 2>/dev/null && echo '    pipx: removed cryptolabs-proxy' || true"
ssh_master "rm -f /root/.local/bin/dc-overview /root/.local/bin/ipmi-monitor /root/.local/bin/cryptolabs-proxy 2>/dev/null || true"

# Remove dc-overview related volumes explicitly
echo "  Removing monitoring volumes..."
REMOVE_VOLUMES="prometheus-data grafana-data ipmi-monitor-data ipmi_data dc-overview-data fleet-auth-data cryptolabs-proxy-data root_grafana-data root_prometheus-data ipmi-monitor_ipmi-data ipmi-monitor_ipmi_data dc-overview_grafana-data dc-overview_prometheus-data"
for v in ${REMOVE_VOLUMES}; do
  ssh_master "docker volume rm ${v} 2>/dev/null && echo \"    removed volume ${v}\" || true"
done

# Also remove compose-created volumes by pattern (catches all naming conventions)
echo "  Removing volumes by pattern..."
VOLUME_PATTERNS="dc-overview prometheus grafana ipmi vastai runpod cryptolabs-proxy fleet-auth"
for pattern in ${VOLUME_PATTERNS}; do
  ssh_master "docker volume ls --format '{{.Name}}' | grep -i '${pattern}' | xargs -r docker volume rm 2>/dev/null || true"
done

# Prune any remaining unused volumes
echo "  Pruning unused volumes..."
ssh_master "docker volume prune -f 2>/dev/null || true"

# Remove dc-overview related networks
echo "  Removing monitoring networks..."
REMOVE_NETWORKS="cryptolabs dc-overview_monitoring dc-overview_default"
for net in ${REMOVE_NETWORKS}; do
  # Disconnect all containers from the network first
  ssh_master "docker network inspect ${net} -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | xargs -r -n1 docker network disconnect -f ${net} 2>/dev/null || true"
  ssh_master "docker network rm ${net} 2>/dev/null && echo \"    removed network ${net}\" || true"
done

# Also remove networks by pattern
echo "  Removing networks by pattern..."
ssh_master "docker network ls --format '{{.Name}}' | grep -iE 'dc-overview|cryptolabs|monitoring' | xargs -r docker network rm 2>/dev/null || true"

# Prune unused networks
echo "  Pruning unused networks..."
ssh_master "docker network prune -f 2>/dev/null || true"

# Remove dc-overview related images ONLY (ensures fresh pull on next deploy)
# PRESERVES: registry, netbootxyz, pxe images
echo "  Removing monitoring images..."
REMOVE_IMAGES="ghcr.io/cryptolabsza/ipmi-monitor ghcr.io/cryptolabsza/dc-overview ghcr.io/cryptolabsza/cryptolabs-proxy ghcr.io/cryptolabsza/vastai-exporter ghcr.io/cryptolabsza/runpod-exporter prom/prometheus grafana/grafana"
for img in ${REMOVE_IMAGES}; do
  ssh_master "docker images --format '{{.Repository}}:{{.Tag}}' | grep '^${img}' | xargs -r docker rmi -f 2>/dev/null && echo \"    removed ${img}\" || true"
done

# Prune dangling images only (not all unused - preserves registry/netbootxyz/pxe images)
echo "  Pruning dangling images..."
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
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 -o BatchMode=yes -i "${SSH_KEY}" ${SSH_USER}@${worker_ip} "
        # Stop and disable all exporter/agent services
        for svc in node_exporter dc-exporter dcgm-exporter gddr6-metrics-exporter dcgm nvidia-dcgm dc-watchdog-agent; do
            systemctl stop \${svc} 2>/dev/null || true
            systemctl disable \${svc} 2>/dev/null || true
            rm -f /etc/systemd/system/\${svc}.service 2>/dev/null || true
        done
        systemctl daemon-reload 2>/dev/null || true
        
        # Kill any remaining processes on exporter ports
        for port in 9100 9835 9878; do
            lsof -t -i :\${port} 2>/dev/null | xargs -r kill -15 2>/dev/null || true
        done
        sleep 1
        for port in 9100 9835 9878; do
            lsof -t -i :\${port} 2>/dev/null | xargs -r kill -9 2>/dev/null || true
        done
        
        # Remove all exporter and agent binaries
        rm -f /usr/local/bin/node_exporter 2>/dev/null || true
        rm -f /usr/local/bin/dc-exporter-rs 2>/dev/null || true
        rm -f /usr/local/bin/dc-exporter 2>/dev/null || true
        rm -f /usr/local/bin/dc-watchdog-agent 2>/dev/null || true
        rm -rf /opt/dc-exporter /opt/dc-exporter-rs 2>/dev/null || true
        
        # Remove DC Watchdog agent config and data
        rm -rf /opt/dc-watchdog /etc/dc-watchdog 2>/dev/null || true
        
        # Remove temp install files
        rm -rf /tmp/node_exporter* /tmp/dc-exporter* 2>/dev/null || true
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

echo "  Verifying config directories removed..."
for dir in ${CONFIG_DIRS}; do
    if ssh_master "test ! -e ${dir}"; then
        echo -e "    ${dir}: ${GREEN}removed${NC}"
    else
        echo -e "    ${dir}: ${RED}still exists${NC}"
    fi
done
echo ""

echo "  Verifying monitoring volumes removed..."
leftover_vols=$(ssh_master "docker volume ls --format '{{.Name}}' | grep -iE 'dc-overview|prometheus|grafana|ipmi|vastai|runpod|cryptolabs-proxy|fleet-auth' || true")
if [ -z "${leftover_vols}" ]; then
    echo -e "    ${GREEN}No matching monitoring volumes remain${NC}"
else
    echo -e "    ${RED}Leftover volumes detected:${NC}"
    echo "${leftover_vols}" | sed 's/^/      - /'
fi
echo ""

echo "  Sample worker check (88.0.1.1):"
echo "    Exporter services:"
ssh_worker 1 "systemctl list-units --type=service --all | grep -E 'node_exporter|dcgm|dc-exporter|gddr6|dc-watchdog' || echo '    (none found)'"
echo "    Binaries:"
ssh_worker 1 "ls -la /usr/local/bin/node_exporter /usr/local/bin/dc-exporter-rs /usr/local/bin/dc-exporter /usr/local/bin/dc-watchdog-agent 2>&1 | grep -v 'No such file' || echo '    (none found)'"
echo "    Processes on exporter ports:"
ssh_worker 1 "lsof -i :9100 -i :9835 -i :9878 2>/dev/null | head -5 || echo '    (none listening)'"
echo ""

# ============================================================================
# Complete
# ============================================================================
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "Summary:"
echo "  • Master: Removed monitoring containers, volumes, and images"
echo "  • Master: Removed config dirs (${CONFIG_DIRS})"
echo "  • Master: Removed IPMI Monitor databases"
echo "  • Master: pip packages (dc-overview, ipmi-monitor, cryptolabs-proxy) uninstalled"
echo "  • Master: Freed ports 80/443 (stopped nginx/apache, killed processes)"
echo "  • Master: Removed DC Watchdog agent"
echo "  • Preserved: registry, netbootxyz, pxe containers and images"
echo "  • Workers: Removed exporter systemd services, Docker containers untouched"
echo "  • Workers: Removed DC Watchdog agent (/opt/dc-watchdog, /etc/dc-watchdog)"
echo "  • No reboots performed"
echo "  • Next deploy will pull fresh monitoring images"
echo ""
echo "To redeploy dc-overview:"
echo "  ssh ${SSH_USER}@${MASTER_IP} -i ${SSH_KEY}"
echo "  pip install --force-reinstall --no-cache-dir git+https://github.com/cryptolabsza/cryptolabs-proxy.git@dev --break-system-packages"
echo "  pip install --force-reinstall --no-cache-dir git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages"
echo "  dc-overview setup -c /root/test-config.yaml -y"
