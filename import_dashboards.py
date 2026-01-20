#!/usr/bin/env python3
import json
import requests
import glob
import os

GRAFANA_URL = "http://127.0.0.1:3000"
GRAFANA_USER = "admin"
GRAFANA_PASS = "DcOverview2024!"

# Get datasource UID
resp = requests.get(f"{GRAFANA_URL}/api/datasources", auth=(GRAFANA_USER, GRAFANA_PASS))
datasources = resp.json()
ds_uid = datasources[0]["uid"] if datasources else None
print(f"Datasource UID: {ds_uid}")

def update_datasource(obj, ds_uid):
    if isinstance(obj, dict):
        if "datasource" in obj and isinstance(obj["datasource"], dict):
            if obj["datasource"].get("type") == "prometheus":
                obj["datasource"]["uid"] = ds_uid
        for key, value in obj.items():
            update_datasource(value, ds_uid)
    elif isinstance(obj, list):
        for item in obj:
            update_datasource(item, ds_uid)

# Import each dashboard
for dashboard_file in glob.glob("/tmp/dashboards/*.json"):
    name = os.path.basename(dashboard_file)
    print(f"\nImporting: {name}")
    
    with open(dashboard_file, "r") as f:
        dashboard = json.load(f)
    
    # Remove id for fresh import
    if "id" in dashboard:
        del dashboard["id"]
    
    # Update datasource UIDs
    update_datasource(dashboard, ds_uid)
    
    # Prepare import payload
    payload = {
        "dashboard": dashboard,
        "overwrite": True,
        "folderId": 0
    }
    
    # Import
    resp = requests.post(
        f"{GRAFANA_URL}/api/dashboards/db",
        json=payload,
        auth=(GRAFANA_USER, GRAFANA_PASS),
        headers={"Content-Type": "application/json"}
    )
    
    result = resp.json()
    if result.get("status") == "success":
        print(f"  Success: {result.get('url', '')}")
    else:
        print(f"  Error: {result.get('message', str(result)[:100])}")

print("\n=== All dashboards imported ===")
