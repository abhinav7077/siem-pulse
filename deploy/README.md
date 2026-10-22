# Deployment examples

| Folder | What |
|--------|------|
| `../../Dockerfile`, `../../docker-compose.yml` | Container image and Compose setup (checks + dashboard in one container) |
| `helm/siem-pulse` | Helm chart: Deployment (checks + dashboard), ConfigMap, PVC, Service, optional Ingress |
| `kubernetes/cronjob.yaml` | Plain Kubernetes CronJob for checks only |
| `systemd/` | `siem-pulse.timer` (hourly checks), dashboard service, self-check timer |
| `grafana/siem-pulse-dashboard.json` | Grafana dashboard for the Prometheus metrics |

All of them keep config + inventory read-only (`/etc/siem-pulse`) and the SQLite history on a writable volume (`/data` or `/var/lib/siem-pulse`). Run exactly **one** scheduler per history database.

## systemd quick install

```bash
sudo useradd --system --home /var/lib/siem-pulse --create-home siempulse
sudo python3 -m venv /opt/siem-pulse/venv && sudo /opt/siem-pulse/venv/bin/pip install siem-pulse
sudo mkdir -p /etc/siem-pulse && sudo cp config.yaml sample_devices.xlsx /etc/siem-pulse/
sudo cp .env /etc/siem-pulse/siem-pulse.env && sudo chmod 600 /etc/siem-pulse/siem-pulse.env
sudo cp deploy/systemd/* /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now siem-pulse.timer siem-pulse-heartbeat.timer siem-pulse-dashboard.service
```

## Helm

```bash
kubectl create namespace siem-pulse
kubectl -n siem-pulse create secret generic siem-pulse-secrets --from-env-file=.env
helm install siem-pulse deploy/helm/siem-pulse -n siem-pulse -f my-values.yaml
```
