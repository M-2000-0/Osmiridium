# Operations Runbook (Single Operator)

Everything below assumes you are the only operator. Commands are copy-paste ready.

## 1. First deployment

```bash
./scripts/deploy.sh            # builds + starts coordinator
./scripts/deploy.sh --status   # check everything is up
```

Health: `curl http://localhost:8080/health` → `ok`

## 2. Normal workflow

| Task | Command |
|------|---------|
| Create session | `curl -X POST localhost:8080/sessions -H "x-api-key: $KEY" -d '{"name":"demo","num_parties":3}'` |
| Add participant | `curl -X POST localhost:8080/sessions/<id>/participants -H "x-api-key: $KEY" -d '{"party_id":0,"name":"alice","endpoint":"host:9000","role":"DataProvider"}'` |
| Execute | `curl -X POST localhost:8080/sessions/<id>/execute -H "x-api-key: $KEY"` |
| Get results | `curl localhost:8080/sessions/<id>/results -H "x-api-key: $KEY"` |
| Check status | `docker compose ps` |

## 3. Updating (zero-downtime-ish)

```bash
git pull                        # or merge a release tag
./scripts/deploy.sh --pull      # pull latest image from GHCR
```

The GitHub Action `deploy.yml` does this automatically on every push to `main`
when `DEPLOY_HOST`/`DEPLOY_USER`/`DEPLOY_KEY` are set.

## 4. Backups

```bash
./scripts/backup.sh             # tarball of ./data into backups/
./scripts/restore.sh backups/osmiridium-<stamp>.tar.gz
```

Automate with cron (runs daily 03:00, keeps 30 days):

```cron
0 3 * * * /opt/osmiridium/scripts/backup.sh >> /var/log/osmiridium-backup.log 2>&1
```

## 5. Monitoring

Stack (started with deploy.sh): Prometheus on :9090, Grafana on :3000.

- Grafana login: admin / admin (change on first login)
- Dashboard: **Osmiridium Coordinator** (provisioned)
- Alerts: when `/health` fails or session error rate rises, Prometheus alerts
  fire and Grafana can notify you via email/Slack/webhook.

## 6. Incident response

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Container unhealthy | API down | `docker compose logs coord` |
| `429 Too Many Requests` | Rate limit hit | raise `OSMOSMPC_RATE_LIMIT` in `.env`, redeploy |
| `401 Unauthorized` | Wrong/empty API key | check `OSMOSMPC_API_KEY` matches `x-api-key` header |
| Disk filling | logs/backups | `docker system prune -f`; check `backups/` retention |
| Certs expired | TLS certs | regenerate via CLI keygen, update `data/certs`, redeploy |
| Key compromise | secrets leak | rotate `OSMOSMPC_API_KEY`, re-run keygen, restore from last clean backup |

## 7. Security checklist (before going public)

- [ ] `OSMOSMPC_API_KEY` set to a strong random value (not `changeme`)
- [ ] TLS enabled (`OSMOSMPC_TLS_ENABLED=true`) with real certs
- [ ] Ports 8080/9090/3000 firewalled to known IPs
- [ ] Grafana admin password changed
- [ ] Backups scheduled and restore tested once
- [ ] `.env` not committed to git

## 8. Day-0 for a new server

```bash
ssh <user>@<host>
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git curl
git clone https://github.com/M-2000-0/Osmiridium.git /opt/osmiridium
cd /opt/osmiridium
cp .env.example .env   # edit values
./scripts/deploy.sh
```