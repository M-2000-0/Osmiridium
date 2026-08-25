//! gRPC API for the Osmiridium SMPC platform.
//!
//! Provides a gRPC service for session lifecycle management and distributed
//! computation orchestration, mirroring the REST endpoints in `lib.rs`.

#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]

pub mod grpc {
    tonic::include_proto!("osmiridium.api.v1");
}

pub use grpc::coordinator_service_client::CoordinatorServiceClient;
pub use grpc::coordinator_service_server::{CoordinatorService, CoordinatorServiceServer};
pub use grpc::{
    AddParticipantRequest, AddParticipantResponse, CreateSessionRequest, CreateSessionResponse,
    DefineCircuitRequest, DefineCircuitResponse, ExecuteSessionRequest, ExecuteSessionResponse,
    GetSessionRequest, GetSessionResponse, HealthRequest, HealthResponse, PartyInputs,
    PartyOutputs,
};
use osmiridium_coordinator::Coordinator;
use osmiridium_protocol::crypto::field::Scalar;
use osmiridium_protocol::crypto::traits::ToBytes;
use osmiridium_protocol::ArithmeticCircuit;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

type SharedCoordinator = Arc<Mutex<Coordinator>>;

// ── gRPC auth & rate-limiting interceptor ──────────────────────────────────

/// API-key configuration shared by REST and gRPC servers.
#[derive(Clone, Debug)]
struct GrpcApiKeyConfig {
    key: String,
}

impl Default for GrpcApiKeyConfig {
    fn default() -> Self {
        Self {
            key: std::env::var("OSMOSMPC_API_KEY").unwrap_or_else(|_| "changeme".to_string()),
        }
    }
}

/// Simple per-IP rate limiter for gRPC (in-memory, 60s window).
struct GrpcRateLimiter {
    requests_per_minute: u32,
    counters: Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>,
}

impl GrpcRateLimiter {
    fn new() -> Self {
        Self {
            requests_per_minute: std::env::var("OSMOSMPC_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            counters: Mutex::new(std::collections::HashMap::new()),
        }
    }

    async fn check(&self, client_ip: &str) -> bool {
        let mut counters = self.counters.lock().await;
        let now = std::time::Instant::now();
        let entry = counters.entry(client_ip.to_string()).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (1, now);
            return true;
        }
        entry.0 += 1;
        entry.0 <= self.requests_per_minute
    }
}

static GRPC_RATE_LIMITER: OnceLock<GrpcRateLimiter> = OnceLock::new();

/// tonic interceptor that enforces API-key auth and per-IP rate limiting on
/// every gRPC RPC except Health.
///
/// Note: tonic 0.12 interceptors are synchronous and run per-service via
/// `with_interceptor`. Rate-limiting is done via an atomic counter with a
/// 60-second sliding window approximation (sufficient for launch).
fn grpc_auth_interceptor(req: Request<()>) -> Result<Request<()>, Status> {
    // Health check is exempt from auth and rate limiting.
    // tonic encodes the method name in the HTTP/2 :path pseudo-header.
    let is_health = req
        .metadata()
        .get(":path")
        .and_then(|v| v.to_str().ok())
        .map(|p| p.contains("Health"))
        .unwrap_or(false);
    if is_health {
        return Ok(req);
    }

    let config = GrpcApiKeyConfig::default();

    // Extract API key from metadata.
    let api_key = req
        .metadata()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req.metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        });

    match api_key {
        Some(key) if key == config.key => {
            // Auth passed — check rate limit.
            let limiter = GRPC_RATE_LIMITER.get_or_init(GrpcRateLimiter::new);
            // Extract client IP from x-forwarded-for or mark unknown.
            let client_ip = req
                .metadata()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            // We block on the async limiter via a new tokio runtime handle.
            // This is acceptable because tonic interceptors run on a tokio
            // worker thread already.
            let allowed = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(limiter.check(&client_ip))
            });
            if !allowed {
                tracing::warn!(client_ip = %client_ip, "gRPC rate limit exceeded");
                return Err(Status::resource_exhausted("rate limit exceeded"));
            }
            Ok(req)
        }
        Some(_) => Err(Status::unauthenticated("invalid API key")),
        None => Err(Status::unauthenticated("missing API key")),
    }
}

/// gRPC service implementation backed by the in-memory coordinator.
#[derive(Clone)]
pub struct CoordinatorGrpcService {
    coordinator: SharedCoordinator,
}

impl CoordinatorGrpcService {
    pub fn new(coordinator: SharedCoordinator) -> Self {
        Self { coordinator }
    }
}

fn scalar_to_hex(scalar: &Scalar) -> String {
    scalar
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn scalar_from_hex(s: &str) -> Result<Scalar, Status> {
    if !s.len().is_multiple_of(2) {
        return Err(Status::invalid_argument("odd-length hex scalar"));
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Status::invalid_argument("bad hex scalar"))
        })
        .collect::<Result<_, _>>()?;

    if bytes.len() < 32 {
        return Err(Status::invalid_argument("scalar must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    Scalar::from_bytes(&arr).map_err(|e| Status::invalid_argument(e.to_string()))
}

fn wire_inputs_to_map(inputs: &PartyInputs) -> Result<BTreeMap<usize, Scalar>, Status> {
    inputs
        .values
        .iter()
        .map(|(wire, value)| Ok((*wire as usize, scalar_from_hex(value)?)))
        .collect()
}

#[tonic::async_trait]
impl CoordinatorService for CoordinatorGrpcService {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".to_string(),
        }))
    }

    async fn create_session(
        &self,
        request: Request<CreateSessionRequest>,
    ) -> Result<Response<CreateSessionResponse>, Status> {
        let req = request.into_inner();
        let mut coord = self.coordinator.lock().await;

        let circuit = ArithmeticCircuit::new();
        let policy = osmiridium_coordinator::SessionPolicy::new(
            req.num_parties as usize,
            "grpc".to_string(),
        );

        let session_id = coord
            .create_session(req.name, circuit, policy)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateSessionResponse {
            session_id: session_id.to_string(),
        }))
    }

    async fn add_participant(
        &self,
        request: Request<AddParticipantRequest>,
    ) -> Result<Response<AddParticipantResponse>, Status> {
        let req = request.into_inner();
        let mut coord = self.coordinator.lock().await;

        let session_id = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session_id"))?;

        let role = match req.role.as_str() {
            "DataProvider" => osmiridium_coordinator::ParticipantRole::DataProvider,
            "ComputationRunner" => osmiridium_coordinator::ParticipantRole::ComputationRunner,
            "Auditor" => osmiridium_coordinator::ParticipantRole::Auditor,
            "Administrator" => osmiridium_coordinator::ParticipantRole::Administrator,
            _ => return Err(Status::invalid_argument("invalid role")),
        };

        let participant = osmiridium_coordinator::Participant {
            party_id: req.party_id as usize,
            name: req.name,
            endpoint: req.endpoint,
            role,
            joined_at: chrono::Utc::now(),
        };

        coord
            .add_participant(session_id, participant)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(AddParticipantResponse { ok: true }))
    }

    async fn get_session(
        &self,
        request: Request<GetSessionRequest>,
    ) -> Result<Response<GetSessionResponse>, Status> {
        let req = request.into_inner();
        let coord = self.coordinator.lock().await;

        let session_id = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session_id"))?;

        let status = coord
            .get_session_status(session_id)
            .map_err(|_| Status::not_found("session not found"))?;

        let session = coord
            .get_session(session_id)
            .map_err(|_| Status::not_found("session not found"))?;

        Ok(Response::new(GetSessionResponse {
            session_id: req.session_id,
            name: session.name,
            status: format!("{:?}", status),
            num_participants: session.participants.len() as u32,
        }))
    }

    async fn define_circuit(
        &self,
        request: Request<DefineCircuitRequest>,
    ) -> Result<Response<DefineCircuitResponse>, Status> {
        let req = request.into_inner();
        let mut coord = self.coordinator.lock().await;

        let session_id = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session_id"))?;

        let circuit: osmiridium_protocol::ArithmeticCircuit = bincode::deserialize(&req.circuit)
            .map_err(|e| Status::invalid_argument(format!("invalid circuit: {}", e)))?;

        coord
            .define_circuit(session_id, circuit)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DefineCircuitResponse { ok: true }))
    }

    async fn execute_session(
        &self,
        request: Request<ExecuteSessionRequest>,
    ) -> Result<Response<ExecuteSessionResponse>, Status> {
        let req = request.into_inner();
        let mut coord = self.coordinator.lock().await;

        let session_id = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session_id"))?;

        let inputs: Vec<BTreeMap<usize, Scalar>> = req
            .inputs
            .iter()
            .map(wire_inputs_to_map)
            .collect::<Result<_, _>>()?;

        let results = coord
            .execute_session_distributed(session_id, &inputs)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let outputs = results
            .into_iter()
            .enumerate()
            .map(|(party_id, map)| PartyOutputs {
                party_id: party_id as u32,
                values: map
                    .into_iter()
                    .map(|(wire, value)| (wire as u64, scalar_to_hex(&value)))
                    .collect(),
            })
            .collect();

        Ok(Response::new(ExecuteSessionResponse { outputs }))
    }
}

/// Build the tonic gRPC server bound to the given socket address, sharing the
/// provided coordinator with other servers in the same process.
pub async fn run_grpc_server_with_coordinator(
    addr: std::net::SocketAddr,
    coordinator: SharedCoordinator,
) -> Result<(), tonic::transport::Error> {
    use tonic::transport::Server;

    let service = CoordinatorGrpcService::new(coordinator);

    Server::builder()
        .add_service(CoordinatorServiceServer::with_interceptor(
            service,
            grpc_auth_interceptor,
        ))
        .serve(addr)
        .await
}

/// Convenience wrapper that creates its own coordinator.
pub async fn run_grpc_server(addr: std::net::SocketAddr) -> Result<(), tonic::transport::Error> {
    let coordinator = Arc::new(Mutex::new(Coordinator::new()));
    run_grpc_server_with_coordinator(addr, coordinator).await
}
