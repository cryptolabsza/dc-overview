#!/bin/bash
# Cleanup script for DC Overview dev fleet
# This removes all dc-overview related containers, volumes, networks, and exporters
# while preserving unrelated services (minecraft, watchtower, etc.)

set -e

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
NC='\033[0m' # No Color

echo -e "${YELLOW}=== DC Overview Dev Fleet Cleanup ===${NC}"
echo ""

# DC Overview containers to remove (including certbot from ipmi-monitor standalone)
# Note: watchtower-minecraft is preserved, but 'watchtower' (if created by quickstart) is removed
DC_CONTAINERS="cryptolabs-proxy dc-overview ipmi-monitor grafana prometheus vastai-exporter certbot watchtower"

# DC Overview volumes to remove (all possible naming conventions)
DC_VOLUMES="dc-overview-data ipmi-monitor-data grafana-data prometheus-data dc-overview_grafana-data dc-overview_prometheus-data fleet-auth-data cryptolabs-proxy-data root_grafana-data root_prometheus-data ipmi-monitor_ipmi-data"

# DC Overview networks to remove
DC_NETWORKS="cryptolabs dc-overview_monitoring"

# Exporter services to remove
EXPORTER_SERVICES="dc-exporter node_exporter"

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

echo "  Removing containers..."
ssh_cmd ${MASTER_PORT} "docker rm ${DC_CONTAINERS} 2>/dev/null || true"

# Remove volumes on master
echo "  Removing volumes..."
ssh_cmd ${MASTER_PORT} "docker volume rm ${DC_VOLUMES} 2>/dev/null || true"

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

# Prune unused images on master
echo "  Pruning unused images..."
ssh_cmd ${MASTER_PORT} "docker image prune -a -f 2>/dev/null || true"

# Clean up certbot lock files
echo "  Cleaning certbot lock files..."
ssh_cmd ${MASTER_PORT} "rm -f /var/lib/letsencrypt/.certbot.lock 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "pkill -f certbot 2>/dev/null || true"

# Uninstall pip packages and clear cache
echo "  Uninstalling dc-overview and ipmi-monitor pip packages..."
ssh_cmd ${MASTER_PORT} "pip uninstall dc-overview -y --break-system-packages 2>/dev/null || true"
ssh_cmd ${MASTER_PORT} "pip uninstall ipmi-monitor -y --break-system-packages 2>/dev/null || true"
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
echo -e "${GREEN}=== Cleanup Complete ===${NC}"
echo ""
echo "To redeploy, run:"
echo "  ssh ${MASTER_HOST} -p ${MASTER_PORT} -i ${SSH_KEY}"
echo "  pip install --force-reinstall --no-cache-dir git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages"
echo "  dc-overview quickstart -c /root/test-config.yaml -y"
