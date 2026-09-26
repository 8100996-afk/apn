# APN VPN switch panel

This repository contains the APN admin panel used on the AWS Ubuntu server. The panel serves `/switch` through Caddy and controls the Mihomo node chosen for VPN clients.

## Update an existing installation

Run on the AWS server:

```bash
curl -fsSL https://raw.githubusercontent.com/8100996-afk/apn/main/update-direct-mode.sh -o /tmp/update-direct-mode.sh
sudo bash /tmp/update-direct-mode.sh
```

The updater checks the existing panel code, downloads and verifies `app.py`, keeps a backup, and restores the old version if the service cannot start. It does not reinstall Mihomo, Caddy, or the VPN.

In the panel, **切回服务器 IP（VPN直连）** routes clients in `10.66.0.0/24` through the AWS server. Selecting a node switches the VPN back to the proxy route in table 100. The selected direct mode is restored when the panel service restarts.

`install.sh` is for a fresh server only; do not rerun it to update a working installation.
