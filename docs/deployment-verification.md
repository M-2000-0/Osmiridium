# Deployment Verification Checklist

## Pre-deployment

- [ ] All tests pass: `cargo test --workspace`
- [ ] Clippy clean: `cargo clippy --workspace -- -D warnings`
- [ ] Format clean: `cargo fmt --all -- --check`
- [ ] Audit clean: `cargo audit`
- [ ] Deny clean: `cargo deny check`
- [ ] Docker image builds: `docker build -t osmiridium:latest .`
- [ ] Release binaries built for all platforms
- [ ] Checksums generated
- [ ] SBOM generated
- [ ] Artifacts signed

## Deployment

### Docker Compose
```bash
# Start stack
docker compose up -d

# Verify health
curl http://localhost:9000/health

# Verify metrics
curl http://localhost:9000/metrics

# Run smoke test
docker compose exec party0 cargo test --workspace
```

### Kubernetes
```bash
# Apply manifests
kubectl apply -f deploy/kubernetes/

# Check pod status
kubectl get pods -l app=osmiridium

# Check logs
kubectl logs -l app=osmiridium

# Port-forward for testing
kubectl port-forward svc/osmiridium-api 9000:9000
```

## Post-deployment Verification

### Health Checks
- [ ] Health endpoint returns 200: `curl http://localhost:9000/health`
- [ ] Health includes version: `{"status":"ok","version":"0.1.0-alpha"}`
- [ ] Metrics endpoint returns data: `curl http://localhost:9000/metrics`

### Authentication
- [ ] Unauthenticated requests rejected: `curl -X POST http://localhost:9000/sessions`
- [ ] Wrong API key rejected: `curl -H "x-api-key: wrong" http://localhost:9000/sessions`
- [ ] Valid API key accepted: `curl -H "x-api-key: changeme" http://localhost:9000/sessions`

### Rate Limiting
- [ ] Rate limit enforced: Send 61 requests in 1 minute
- [ ] Rate limit headers returned: Check for X-RateLimit-* headers
- [ ] Health check exempt: Rate limit doesn't apply to /health

### Session Lifecycle
- [ ] Create session: `curl -X POST -H "x-api-key: changeme" -H "Content-Type: application/json" -d '{"name":"test","num_parties":3}' http://localhost:9000/sessions`
- [ ] Get session: `curl -H "x-api-key: changeme" http://localhost:9000/sessions/{id}`
- [ ] List sessions: `curl -H "x-api-key: changeme" http://localhost:9000/sessions`
- [ ] Add participant: `curl -X POST -H "x-api-key: changeme" -H "Content-Type: application/json" -d '{"party_id":0,"name":"alice","endpoint":"127.0.0.1:9001","role":"DataProvider"}' http://localhost:9000/sessions/{id}/participants`
- [ ] Cancel session: `curl -X POST -H "x-api-key: changeme" http://localhost:9000/sessions/{id}/cancel`

### Error Handling
- [ ] Invalid UUID returns 400: `curl -H "x-api-key: changeme" http://localhost:9000/sessions/invalid`
- [ ] Missing session returns 404: `curl -H "x-api-key: changeme" http://localhost:9000/sessions/00000000-0000-0000-0000-000000000000`
- [ ] Empty name returns 400: `curl -X POST -H "x-api-key: changeme" -H "Content-Type: application/json" -d '{"name":"","num_parties":3}' http://localhost:9000/sessions`
- [ ] Invalid num_parties returns 400: `curl -X POST -H "x-api-key: changeme" -H "Content-Type: application/json" -d '{"name":"test","num_parties":1}' http://localhost:9000/sessions`
- [ ] Invalid role returns 400: `curl -X POST -H "x-api-key: changeme" -H "Content-Type: application/json" -d '{"party_id":0,"name":"alice","endpoint":"127.0.0.1:9001","role":"invalid"}' http://localhost:9000/sessions/{id}/participants`

### Persistence
- [ ] Session persists across restart: Create session, restart, verify it exists
- [ ] Participant persists: Add participant, restart, verify it exists
- [ ] Corrupt file handled: Create invalid JSON in data dir, verify startup works

### Performance
- [ ] Health check latency < 10ms
- [ ] Session creation latency < 100ms
- [ ] Participant addition latency < 100ms
- [ ] No memory leaks during 1000 operations

### Security
- [ ] No secrets in logs: Check logs for API keys, passwords
- [ ] TLS works if enabled: `curl -k https://localhost:9443/health`
- [ ] mTLS works if enabled: Verify client certificates required

## Rollback Procedure

If issues detected:

1. Stop current deployment:
   ```bash
   # Docker
   docker compose down
   
   # Kubernetes
   kubectl delete -f deploy/kubernetes/
   ```

2. Deploy previous version:
   ```bash
   # Docker
   docker compose -f docker-compose.prev.yml up -d
   
   # Kubernetes
   kubectl apply -f deploy/kubernetes/prev/
   ```

3. Verify rollback:
   ```bash
   curl http://localhost:9000/health
   ```

4. Notify team and investigate
