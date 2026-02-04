# DC Watchdog + Fleet Management: Config Checklist

Use this to verify your quickstart config (e.g. `/root/test-config.yaml`) when DC Watchdog is enabled.

## Intended flow

1. **Deploy** – Quickstart runs; Fleet Management and dc-overview start. Go agents can be installed if an API key is available (e.g. from `.secrets.yaml`).
2. **First-time in Fleet** – DC Watchdog is **not** shown as enabled until the user clicks **Link Account** and completes SSO. This is intentional so the user explicitly enables and validates the key.
3. **After SSO** – Fleet stores the validated API key. That key can be refreshed; Go agents register with the Watchdog server and receive worker tokens for identification and encrypted comms.

## Config checklist (e.g. `/root/test-config.yaml`)

- **Components**
  - `components.dc_watchdog: true` so Step 8c runs and installs Go agents when a key is present.

- **Watchdog section**
  - `watchdog.server_url`: `https://watchdog.cryptolabs.co.za`
  - `watchdog.install_agent: true`
  - `watchdog.agent_use_mtr: true` (optional)
  - Do **not** put the API key in the main config file (keep it in secrets). That way Fleet still requires first-time SSO.

- **API key for agent install**
  - In **.secrets.yaml** (e.g. `/etc/dc-overview/.secrets.yaml` or next to your config):
    - `ipmi_ai_license: sk-ipmi-xxx` (same key for IPMI + Watchdog), or
    - `watchdog_api_key: sk-ipmi-xxx`
  - This allows quickstart to install the Go agents. Fleet Management will still show “Link Account” until the user completes SSO.

- **SSH (for agent deployment)**
  - `ssh.username`, `ssh.key_path`, `ssh.port` (e.g. `100`) must match how you log in to workers (e.g. `ssh root@41.193.204.66 -p 100 -i ~/.ssh/ubuntu_key` → `username: root`, `port: 100`, `key_path: ~/.ssh/ubuntu_key`).

- **Servers**
  - Each server needs `name` and `server_ip` (and optional `has_gpu`, `bmc_ip`, etc.).

## Example minimal snippet

```yaml
components:
  dc_overview: true
  ipmi_monitor: true   # or false
  dc_watchdog: true

ssh:
  username: root
  auth_method: key
  port: 100
  key_path: ~/.ssh/ubuntu_key

watchdog:
  server_url: https://watchdog.cryptolabs.co.za
  install_agent: true
  agent_use_mtr: true

servers:
  - name: master
    server_ip: 41.193.204.66
    has_gpu: true
```

Secrets (e.g. `.secrets.yaml`): set `ipmi_ai_license` or `watchdog_api_key` so quickstart can install agents; Fleet will still require “Link Account” + SSO the first time.
