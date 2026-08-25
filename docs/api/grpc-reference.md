# gRPC Reference

Proto: `crates/api/proto/osmiridium.proto` package `osmiridium.api.v1`, service `CoordinatorService`.

- `Health(HealthRequest) → HealthResponse {status}` — no auth.
- `CreateSession(CreateSessionRequest{name,num_parties}) → CreateSessionResponse{session_id}` — validates `name` len, `num_parties` 2..64.
- `AddParticipant(AddParticipantRequest{session_id,party_id,name,endpoint,role}) → AddParticipantResponse{ok}` — same endpoint/role/party_id validation as REST.
- `GetSession(GetSessionRequest{session_id}) → GetSessionResponse{session_id,name,status,num_participants}` — real session data.
- `DefineCircuit(DefineCircuitRequest{session_id,circuit:bytes(bincode)}) → DefineCircuitResponse{ok}` — attaches `ArithmeticCircuit`, only in `Created`/`Configured`.
- `ExecuteSession(ExecuteSessionRequest{session_id,inputs:[PartyInputs]}) → ExecuteSessionResponse{outputs:[PartyOutputs]}` — runs `execute_distributed` if participants have endpoints.

Shared `Coordinator` with REST (see `crates/api/src/lib.rs:389` `run_server_with_grpc`); disable gRPC with `--grpc-port 0` or `grpc_addr="-"`. Auth via `x-api-key`/`authorization` metadata (mirrors REST). Error mapping: `NOT_FOUND` → session unknown, `INVALID_ARGUMENT` → bad UUID/role, `PERMISSION_DENIED` → policy, `RESOURCE_EXHAUSTED` → rate limit, `INTERNAL` → protocol failure. Reflection/health not yet exposed (tracked).
