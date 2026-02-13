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
# Note: watchtower is NOT removed - it is for minecraft and other non-dc-overview services
# cryptolabs-watchtower IS removed - deployed by cryptolabs-proxy for auto-updates
DC_CONTAINERS="cryptolabs-proxy dc-overview ipmi-monitor grafana prometheus vastai-exporter runpod-exporter certbot cryptolabs-watchtower"

# Container name patterns for wildcard matching (catches docker-compose prefixed names)
# Excludes "watchtower" - that's for minecraft; we remove "cryptolabs-watchtower" via DC_CONTAINERS
CONTAINER_PATTERNS="grafana prometheus ipmi-monitor dc-overview cryptolabs-proxy vastai-exporter runpod-exporter certbot cryptolabs-watchtower"

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

# Config directories to remove (created by setup commands)
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

# Stop and remove containers on master (single SSH session for speed)
echo "  Stopping and removing containers..."
ssh_cmd ${MASTER_PORT} "
  docker stop -t 3 ${DC_CONTAINERS} 2>/dev/null; \
  for p in ${CONTAINER_PATTERNS}; do docker ps -a --format '{{.Names}}' | grep -i \"\$p\" | xargs -r docker stop -t 3 2>/dev/null; done; \
  docker rm -f ${DC_CONTAINERS} 2>/dev/null; \
  for p in ${CONTAINER_PATTERNS}; do docker ps -a --format '{{.Names}}' | grep -i \"\$p\" | xargs -r docker rm -f 2>/dev/null; done; \
  echo done
"

# Remove volumes, networks on master (single SSH session)
echo "  Removing volumes and networks..."
ssh_cmd ${MASTER_PORT} "
  docker volume rm ${DC_VOLUMES} 2>/dev/null; \
  for p in ${VOLUME_PATTERNS}; do docker volume ls --format '{{.Name}}' | grep -i \"\$p\" | xargs -r docker volume rm 2>/dev/null; done; \
  docker volume prune -f 2>/dev/null; \
  for net in ${DC_NETWORKS}; do \
    docker network inspect \$net -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | xargs -r -n1 docker network disconnect -f \$net 2>/dev/null; \
    docker network rm \$net 2>/dev/null; \
  done; \
  docker network ls --format '{{.Name}}' | grep -iE 'dc-overview|cryptolabs|monitoring' | xargs -r docker network rm 2>/dev/null; \
  docker network prune -f 2>/dev/null; \
  echo done
"

# Remove services, images, configs on master (single SSH session)
echo "  Removing services, images, and configs..."
ssh_cmd ${MASTER_PORT} "
  for svc in ${EXPORTER_SERVICES}; do systemctl stop \$svc 2>/dev/null; systemctl disable \$svc 2>/dev/null; rm -f /etc/systemd/system/\$svc.service; done; \
  systemctl daemon-reload; \
  for port in ${EXPORTER_PORTS}; do lsof -t -i :\$port 2>/dev/null | xargs -r kill -9; done; \
  systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null; \
  systemctl stop apache2 2>/dev/null; systemctl disable apache2 2>/dev/null; \
  for port in 80 443; do lsof -t -i :\$port 2>/dev/null | xargs -r kill -9; fuser -k \$port/tcp 2>/dev/null; done; \
  rm -f ${LEGACY_EXPORTER_FILES}; \
  rm -rf ${DC_WATCHDOG_DIRS}; \
  for img in ghcr.io/cryptolabsza/ipmi-monitor ghcr.io/cryptolabsza/dc-overview ghcr.io/cryptolabsza/cryptolabs-proxy ghcr.io/cryptolabsza/vastai-exporter ghcr.io/cryptolabsza/runpod-exporter prom/prometheus grafana/grafana; do \
    docker images --format '{{.Repository}}:{{.Tag}}' | grep \"^\$img\" | xargs -r docker rmi -f 2>/dev/null; \
  done; \
  docker image prune -f 2>/dev/null; \
  rm -f /var/lib/letsencrypt/.certbot.lock; pkill -f certbot 2>/dev/null; \
  rm -rf ${CONFIG_DIRS}; \
  rm -rf /var/lib/ipmi-monitor; \
  pip uninstall dc-overview ipmi-monitor cryptolabs-proxy -y --break-system-packages 2>/dev/null; \
  pipx uninstall dc-overview 2>/dev/null; pipx uninstall ipmi-monitor 2>/dev/null; pipx uninstall cryptolabs-proxy 2>/dev/null; \
  rm -f /usr/local/bin/dc-overview /usr/local/bin/ipmi-monitor /usr/local/bin/cryptolabs-proxy; \
  pip cache purge 2>/dev/null; \
  echo done
"

echo -e "${GREEN}  ✓ Master node cleaned${NC}"

echo ""
echo -e "${YELLOW}Step 2: Cleaning workers...${NC}"

# Worker cleanup function (single SSH session per worker)
clean_worker() {
    local port=$1
    local name=$2
    echo -e "  ${CYAN}${name} (port ${port})${NC}"

    ssh_cmd ${port} "
      for svc in ${EXPORTER_SERVICES}; do systemctl stop \$svc 2>/dev/null; systemctl disable \$svc 2>/dev/null; rm -f /etc/systemd/system/\$svc.service; done; \
      systemctl daemon-reload; \
      rm -f /usr/local/bin/dc-exporter-rs /usr/local/bin/dc-exporter /usr/local/bin/dc-exporter.bin /usr/local/bin/node_exporter /usr/local/bin/dc-watchdog-agent; \
      rm -rf /etc/dc-exporter ${DC_WATCHDOG_DIRS}; \
      echo done
    "

    echo -e "    ${GREEN}✓ ${name} cleaned${NC}"
}

clean_worker ${WK01_PORT} "wk01"
clean_worker ${WK03_PORT} "wk03"

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
echo -e "      - minecraft, watchtower (separate from cryptolabs-watchtower)"
echo ""
echo -e "${CYAN}To redeploy dc-overview:${NC}"
echo ""
echo -e "  ${YELLOW}# SSH to master${NC}"
echo "  ssh ${MASTER_HOST} -p ${MASTER_PORT} -i ${SSH_KEY}"
echo ""
echo -e "  ${YELLOW}# Install latest stable${NC}"
echo "  apt install pipx -y && pipx ensurepath && source ~/.bashrc"
echo "  pipx install dc-overview"
echo ""
echo -e "  ${YELLOW}# Deploy${NC}"
echo "  dc-overview setup -c /root/test-config.yaml -y"
echo ""
echo -e "  ${YELLOW}# Or for dev (UNSTABLE):${NC}"
echo "  dc-overview setup --dev -c /root/test-config.yaml -y"
echo ""
