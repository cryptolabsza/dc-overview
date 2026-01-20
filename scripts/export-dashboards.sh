#!/bin/bash
# Export dashboards from Grafana with fixed datasource references
# Usage: ./export-dashboards.sh <grafana_url> <admin_password> <output_dir>

GRAFANA_URL="${1:-http://localhost:3000}"
GRAFANA_PASS="${2:-admin}"
OUTPUT_DIR="${3:-./dashboards}"
DATASOURCE_UID="prometheus"

mkdir -p "$OUTPUT_DIR"

echo "Exporting dashboards from $GRAFANA_URL"

# Get all dashboard UIDs
UIDS=$(curl -s -u "admin:$GRAFANA_PASS" "$GRAFANA_URL/api/search" | \
    python3 -c "import json,sys; [print(d['uid']) for d in json.load(sys.stdin) if d.get('type')=='dash-db']")

for uid in $UIDS; do
    echo "  Exporting: $uid"
    
    curl -s -u "admin:$GRAFANA_PASS" "$GRAFANA_URL/api/dashboards/uid/$uid" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
d = data.get('dashboard', {})
# Remove provisioning-incompatible fields
for k in ['id', 'version', '__inputs', '__requires']: 
    d.pop(k, None)
# Fix datasource references
s = json.dumps(d, indent=2)
s = s.replace('\${DS_PROMETHEUS}', '${DATASOURCE_UID}')
print(s)
" | sed "s/\${DATASOURCE_UID}/$DATASOURCE_UID/g" > "$OUTPUT_DIR/${uid}.json"
    
    if [ -s "$OUTPUT_DIR/${uid}.json" ]; then
        echo "    Saved: $OUTPUT_DIR/${uid}.json"
    fi
done

echo "Done! Dashboards exported to $OUTPUT_DIR"
