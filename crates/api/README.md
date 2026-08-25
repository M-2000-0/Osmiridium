# osmiridium-api

REST + gRPC coordinator API.

- **REST (axum):** `POST /sessions`, `GET /sessions/:id`, `POST /sessions/:id/participants`, `POST /sessions/:id/execute`, `GET /sessions/:id/results`, `GET /health`, `GET /metrics` (Prometheus). Layers: body limit 1 MB → tracing → metrics → per-IP rate limit (`OSMOSMPC_RATE_LIMIT`) → API-key auth (`x-api-key` or `Bearer`, `OSMOSMPC_API_KEY`).
- **gRPC (tonic):** `CoordinatorService` (Health/CreateSession/AddParticipant/GetSession/DefineCircuit/ExecuteSession), shared `Coordinator` with REST.
- **Run:** `osmiridium verify --addr 0.0.0.0 --port 8080 --grpc-port 50051`

See `docs/api/openapi.yaml` and `crates/api/proto/osmiridium.proto`.

License: BUSL-1.1.
