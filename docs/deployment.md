# Deployment

Keep config + inventory read-only and the SQLite history on a writable volume. Run exactly **one** scheduler per history database.

## Docker / Compose

```bash
cp .env.example .env            # credentials + DASHBOARD_TOKEN_ADMIN
docker compose up -d
open "http://127.0.0.1:8080/?token=$DASHBOARD_TOKEN_ADMIN"
```

The image (`ghcr.io/abhinav7077/siem-pulse`) runs as UID 10001, works with a read-only root filesystem, reads `/etc/siem-pulse/config.yaml` and keeps state in `/data`. Behind a TLS-inspecting proxy, build with `docker build --secret id=pip_ca,src=corp-ca.pem .`.

## Kubernetes (Helm)

```bash
kubectl create namespace siem-pulse
kubectl -n siem-pulse create secret generic siem-pulse-secrets --from-env-file=.env
helm install siem-pulse deploy/helm/siem-pulse -n siem-pulse -f my-values.yaml
```

One pod runs checks and the dashboard (`Recreate` strategy, history on a PVC). Put your `config.yaml` under `config:` and devices under `inventory:` in your values file, or use `devices.source: servicenow`.

## Kubernetes CronJob

`deploy/kubernetes/cronjob.yaml` runs one check per hour with history on a PVC (no dashboard).

## systemd

`deploy/systemd/` contains an hourly `siem-pulse.timer`, a dashboard service and a self-check timer — install steps in `deploy/README.md`.

## cron

```bash
7 * * * *    cd /var/lib/siem-pulse && siem-pulse --config /etc/siem-pulse/config.yaml
*/15 * * * * cd /var/lib/siem-pulse && siem-pulse --config /etc/siem-pulse/config.yaml --check-heartbeat
```
