#!/bin/bash
# Cleanup script for DC Overview dev fleet
# This removes ALL dc-overview related containers, volumes, networks, images, and exporters
# while preserving unrelated services (minecraft, watchtower, etc.)
# Designed for testing - ensures fresh images on next deploy

# NOTE: We do NOT use 'set -e' because cleanup commands may fail (e.g., item doesn't exist)
# and we want to continue cleaning up everything regardless

# Configuration
MASTER_HOST="root@41.193.204.66"
MASTER_PORT=100
WK01_PORT=101
WK03_PORT=103
SSH_KEY="~/.ssh/ubuntu_key"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Track what was cleaned for summary
CLEANED_CONTAINERS=0
CLEANED_VOLUMES=0
CLEANED_NETWORKS=0
CLEANED_IMAGES=0
CLEANED_SERVICES=0
ERRORS=0

echo -e "${YELLOW}=== DC Overview Dev Fleet Cleanup ===${NC}"
echo ""

# DC Overview containers to remove (including certbot from ipmi-monitor standalone)
# Note: watchtower is NOT removed as it may be shared with minecraft or other services
DC_CONTAINERS="cryptolabs-proxy dc-overview ipmi-monitor grafana prometheus vastai-exporter runpod-exporter certbot watchtower"

# Container name patterns for wildcard matching (catches docker-compose prefixed names)
CONTAINER_PATTERNS="grafana prometheus ipmi-monitor dc-overview cryptolabs-proxy vastai-exporter runpod-exporter certbot"

# DC Overview volumes to remove (all possible naming conventions)
DC_VOLUMES="dc-overview-data ipmi-monitor-data ipmi_data grafana-data prometheus-data dc-overview_grafana-data dc-overview_prometheus-data fleet-auth-data cryptolabs-proxy-data root_grafana-data root_prometheus-data ipmi-monitor_ipmi-data ipmi-monitor_ipmi_data"

# Volume patterns for wildcard matching
VOLUME_PATTERNS="dc-overview prometheus grafana ipmi vastai runpod cryptolabs-proxy fleet-auth"

# DC Overview networks to remove
DC_NETWORKS="cryptolabs dc-overview_monitoring dc-overview_default"

# Exporter services to remove (systemd services)
EXPORTER_SERVICES="dc-exporter node_exporter dc-watchdog-agent"

# DC Watchdog agent directories to remove
DC_WATCHDOG_DIRS="/opt/dc-watchdog /etc/dc-watchdog"

# Config directories to remove (created by quickstart commands)
CONFIG_DIRS="/etc/ipmi-monitor /etc/dc-overview /etc/cryptolabs-proxy"

# Legacy exporter files to remove
LEGACY_EXPORTER_FILES="/opt/runpod_exporter.py /opt/vastai_exporter.py /opt/runpod-exporter /opt/vastai-exporter"

# Ports to check for legacy host-based exporters
EXPORTER_PORTS="8622 8623"

# Function to run SSH command
ssh_cmd() {
    local port=$1
    shift
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${MASTER_HOST} -p ${port} -i ${SSH_KEY} "$@"
}

echo -e "${YELLOW}Step 1: Cleaning master node (port ${MASTER_PORT})...${NC}"

# Stop and remove containers on master
echo "  Stopping containers..."
ssh_cmd ${MASTER_PORT} "docker stop ${DC_CONTAINERS} 2>/dev/null || true"

# Also stop containers matching patterns (catches docker-compose prefixed names)
echo "  Stopping containers by pattern..."
for pattern in ${CONTAINER_PATTERNS}; do
  ssh_cmd ${MASTER_PORT} "docker ps -a --format '{{.Names}}' | grep -i '${pattern}' | xargs -r docker stop 2>/dev/null || true"
done

echo "  Removing containers..."
ssh_cmd ${MASTER_PORT} "docker rm -f ${DC_CONTAINERS} 2>/dev/null || true"

# Also remove containers matching patterns
echo "  Removing containers by pattern..."
for pattern in ${CONTAINER_PATTERNS}; do
  ssh_cmd ${MASTER_PORT} "docker ps -a --format '{{.Names}}' | grep -i '${pattern}' | xargs -r docker rm -f 2>/dev/null || true"
done

# Remove volumes on master
echo "  Removing volumes..."
ssh_cmd ${MASTER_PORT} "docker volume rm ${DC_VOLUMES} 2>/dev/null || true"

# Also remove volumes by pattern
echo "  Removing volumes by pattern..."
for pattern in ${VOLUME_PATTERNS}; do
  ssh_cmd ${MASTER_PORT} "docker volume ls --format '{{.Name}}' | grep -i '${pattern}' | xargs -r docker volume rm 2>/dev/null || true"
done

# Prune unused volumes
echo "  Pruning unused volumes..."
ssh_cmd ${MASTER_PORT} "docker volume prune -f 2>/dev/null || true"

# Remove networks on master (force disconnect any remaining containers first)
echo "  Removing networks..."
for net in ${DC_NETWORKS}; do
    # Disconnect all containers from the network first
    ssh_cmd ${MASTER_PORT} "docker network inspect ${net} -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | xargs -r -n1 docker network disconnect -f ${net} 2>/dev/null || true"
    ssh_cmd ${MASTER_PORT} "docker network rm ${net} 2>/dev/null || true"
done

# Also remove networks by pattern
echo "  Removing networks by pattern..."
ssh_cmd ${MASTER_PORT} "docker network ls --format '{{.Name}}' | grep -iE 'dc-overview|cryptolabs|monitoring' | xargs -r docker network rm 2>/dev/null || true"

# Prune unused networks
echo "  Pruning unused networks..."
ssh_cmd ${MASTER_PORT} "docker network prune -f 2>/dev/null || true"

# Remove exporters on master
echo "  Removing exporter services..."
for svc in ${EXPORTER_SERVICES}; do
    ssh_cmd ${MASTER_PORT} "systemctl stop ${svc} 2>/dev/null || true"
    ssh_cmd ${MASTER_PORT} "systemctl disable ${svc} 2>/dev/null || true"
    ssh_cmd ${MASTER_PORT} "rm -f /etc/systemd/system/${svc}.service 2>/dev/null || true"
done
ssh_cmd ${MASTER_PORT} "systemctl daemon-reload"

# Kill any host-based exporters running on ports 8622/8623 (legacy installations)
echo "  Killing legacy host-based exporters..."
for port in ${EXPORTER_PORTS}; do
    ssh_cmd ${MASTER_PORT} "lsof -t -i :${port} 2>/dev/null | xargs -r kill -9 && echo \"    killed process on port ${port}\" || true"
done

# Free ports 80/443 for proxy (stop nginx/apache, kill any processes)
echo "  Freeing ports 80 and 443..."
ssh_cmd ${MASTER_PORT} "systemctl stop nginx 2>/dev/null && echo '    stopped nginx' || true"
ssh_cmd ${MASTER_PORT} "systemctl disable nginx 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "systemctl stop apache2 2>/dev/null && echo '    stopped apache2' || true"
ssh_cmd ${MASTER_PORT} "systemctl disable apache2 2>/dev/null || true"
for port in 80 443; do
    ssh_cmd ${MASTER_PORT} "lsof -t -i :${port} 2>/dev/null | xargs -r kill -9 && echo \"    killed process on port ${port}\" || true"
    ssh_cmd ${MASTER_PORT} "fuser -k ${port}/tcp 2>/dev/null && echo \"    killed process on port ${port} (fuser)\" || true"
done

# Remove legacy exporter files
echo "  Removing legacy exporter files..."
for file in ${LEGACY_EXPORTER_FILES}; do
    ssh_cmd ${MASTER_PORT} "rm -f ${file} 2>/dev/null && echo \"    removed ${file}\" || true"
done

# Remove DC Watchdog agent directories
echo "  Removing DC Watchdog agent..."
for dir in ${DC_WATCHDOG_DIRS}; do
    ssh_cmd ${MASTER_PORT} "rm -rf ${dir} 2>/dev/null && echo \"    removed ${dir}\" || true"
done

# Remove dc-overview related images ONLY (ensures fresh pull on next deploy)
# PRESERVES: minecraft, watchtower images
echo "  Removing monitoring images..."
DC_IMAGES="ghcr.io/cryptolabsza/ipmi-monitor ghcr.io/cryptolabsza/dc-overview ghcr.io/cryptolabsza/cryptolabs-proxy ghcr.io/cryptolabsza/vastai-exporter ghcr.io/cryptolabsza/runpod-exporter prom/prometheus grafana/grafana"
for img in ${DC_IMAGES}; do
  ssh_cmd ${MASTER_PORT} "docker images --format '{{.Repository}}:{{.Tag}}' | grep '^${img}' | xargs -r docker rmi -f 2>/dev/null && echo \"    removed ${img}\" || true"
done

# Prune dangling images only (not all unused - preserves minecraft/watchtower images)
echo "  Pruning dangling images..."
ssh_cmd ${MASTER_PORT} "docker image prune -f 2>/dev/null || true"

# Clean up certbot lock files
echo "  Cleaning certbot lock files..."
ssh_cmd ${MASTER_PORT} "rm -f /var/lib/letsencrypt/.certbot.lock 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "pkill -f certbot 2>/dev/null || true"

# Remove config directories (created by quickstart commands)
echo "  Removing config directories..."
for dir in ${CONFIG_DIRS}; do
    ssh_cmd ${MASTER_PORT} "rm -rf ${dir} 2>/dev/null && echo \"    removed ${dir}\" || true"
done

# Remove IPMI Monitor database files that may exist outside volumes
echo "  Removing stale database files..."
ssh_cmd ${MASTER_PORT} "rm -f /var/lib/ipmi-monitor/*.db 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "rm -rf /var/lib/ipmi-monitor 2>/dev/null || true"

# Uninstall pip packages and clear cache
echo "  Uninstalling pip packages..."
ssh_cmd ${MASTER_PORT} "pip uninstall dc-overview -y --break-system-packages 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "pip uninstall ipmi-monitor -y --break-system-packages 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "pip uninstall cryptolabs-proxy -y --break-system-packages 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "pip cache purge 2>/dev/null || true"

echo -e "${GREEN}  ✓ Master node cleaned${NC}"

echo ""
echo -e "${YELLOW}Step 2: Cleaning wk01 (port ${WK01_PORT})...${NC}"

# Remove exporters on wk01
for svc in ${EXPORTER_SERVICES}; do
    ssh_cmd ${WK01_PORT} "systemctl stop ${svc} 2>/dev/null || true"
    ssh_cmd ${WK01_PORT} "systemctl disable ${svc} 2>/dev/null || true"
    ssh_cmd ${WK01_PORT} "rm -f /etc/systemd/system/${svc}.service 2>/dev/null || true"
done
ssh_cmd ${WK01_PORT} "systemctl daemon-reload"

# Remove DC Watchdog agent directories on wk01
echo "  Removing DC Watchdog agent..."
for dir in ${DC_WATCHDOG_DIRS}; do
    ssh_cmd ${WK01_PORT} "rm -rf ${dir} 2>/dev/null && echo \"    removed ${dir}\" || true"
done

echo -e "${GREEN}  ✓ wk01 cleaned${NC}"

echo ""
echo -e "${YELLOW}Step 3: Cleaning wk03 (port ${WK03_PORT})...${NC}"

# Remove exporters on wk03
for svc in ${EXPORTER_SERVICES}; do
    ssh_cmd ${WK03_PORT} "systemctl stop ${svc} 2>/dev/null || true"
    ssh_cmd ${WK03_PORT} "systemctl disable ${svc} 2>/dev/null || true"
    ssh_cmd ${WK03_PORT} "rm -f /etc/systemd/system/${svc}.service 2>/dev/null || true"
done
ssh_cmd ${WK03_PORT} "systemctl daemon-reload"

# Remove DC Watchdog agent directories on wk03
echo "  Removing DC Watchdog agent..."
for dir in ${DC_WATCHDOG_DIRS}; do
    ssh_cmd ${WK03_PORT} "rm -rf ${dir} 2>/dev/null && echo \"    removed ${dir}\" || true"
done

echo -e "${GREEN}  ✓ wk03 cleaned${NC}"

echo ""
echo -e "${YELLOW}Step 4: Verification...${NC}"

echo "  Master containers:"
ssh_cmd ${MASTER_PORT} "docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'"

echo ""
echo "  Master volumes:"
ssh_cmd ${MASTER_PORT} "docker volume ls"

echo ""
echo "  Master networks:"
ssh_cmd ${MASTER_PORT} "docker network ls"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                     CLEANUP COMPLETE                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Summary:${NC}"
echo -e "  ${GREEN}•${NC} Master node (port ${MASTER_PORT}):"
echo -e "      - Containers, volumes, networks removed"
echo -e "      - Docker images pruned (fresh pull on next deploy)"
echo -e "      - Config dirs removed (${CONFIG_DIRS})"
echo -e "      - pip packages (dc-overview, ipmi-monitor, cryptolabs-proxy) uninstalled"
echo -e "      - Ports 80/443 freed (nginx/apache stopped, processes killed)"
echo ""
echo -e "  ${GREEN}•${NC} Worker nodes (wk01:${WK01_PORT}, wk03:${WK03_PORT}):"
echo -e "      - Exporter services stopped: ${EXPORTER_SERVICES}"
echo ""
echo -e "  ${GREEN}•${NC} All nodes:"
echo -e "      - DC Watchdog agent removed (${DC_WATCHDOG_DIRS})"
echo ""
echo -e "  ${YELLOW}•${NC} Preserved:"
echo -e "      - minecraft, watchtower (if not dc-overview related)"
echo ""
echo -e "${CYAN}To redeploy dc-overview:${NC}"
echo ""
echo -e "  ${YELLOW}# SSH to master${NC}"
echo "  ssh ${MASTER_HOST} -p ${MASTER_PORT} -i ${SSH_KEY}"
echo ""
echo -e "  ${YELLOW}# Install latest dev versions${NC}"
echo "  pip install --force-reinstall --no-cache-dir git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages"
echo "  pip install --force-reinstall --no-cache-dir git+https://github.com/cryptolabsza/cryptolabs-proxy.git@dev --break-system-packages"
echo ""
echo -e "  ${YELLOW}# Deploy${NC}"
echo "  dc-overview quickstart -c /root/test-config.yaml -y"
echo ""
