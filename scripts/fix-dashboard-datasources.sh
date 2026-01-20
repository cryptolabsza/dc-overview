#!/bin/bash
# Fix dashboard datasource references for deployment
# Usage: ./fix-dashboard-datasources.sh <dashboard.json> [datasource_uid]
#
# This script replaces ${DS_PROMETHEUS} and common random UIDs
# with a standard datasource UID (default: "prometheus")

DASHBOARD_FILE="$1"
DATASOURCE_UID="${2:-prometheus}"

if [ -z "$DASHBOARD_FILE" ]; then
    echo "Usage: $0 <dashboard.json> [datasource_uid]"
    echo "  Fixes datasource references in Grafana dashboard JSON"
    exit 1
fi

if [ ! -f "$DASHBOARD_FILE" ]; then
    echo "Error: File not found: $DASHBOARD_FILE"
    exit 1
fi

echo "Fixing: $DASHBOARD_FILE"
echo "  Target UID: $DATASOURCE_UID"

# Create temp file
TEMP_FILE=$(mktemp)

# Replace common patterns
cat "$DASHBOARD_FILE" | \
    sed "s/\${DS_PROMETHEUS}/${DATASOURCE_UID}/g" | \
    sed 's/"uid": "[a-z0-9]\{14\}"/"uid": "'"${DATASOURCE_UID}"'"/g' \
    > "$TEMP_FILE"

# Count replacements
ORIG_COUNT=$(grep -c "DS_PROMETHEUS\|[a-z0-9]\{14\}" "$DASHBOARD_FILE" 2>/dev/null || echo 0)
NEW_COUNT=$(grep -c "${DATASOURCE_UID}" "$TEMP_FILE" 2>/dev/null || echo 0)

mv "$TEMP_FILE" "$DASHBOARD_FILE"

echo "  Done! ($NEW_COUNT datasource references)"
