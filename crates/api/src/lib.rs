use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use osmiridium_coordinator::Coordinator;
use osmiridium_protocol::ArithmeticCircuit;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

pub mod grpc;
pub mod metrics;

use metrics::Metrics;

#[derive(Clone, Serialize)]
struct SessionInfo {
    id: String,
    name: String,
    status: String,
    num_participants: usize,
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    name: String,
    num_parties: usize,
}

#[derive(Deserialize)]
struct AddParticipantRequest {
    party_id: usize,
    name: String,
    endpoint: String,
    role: String,
}

/// Coordinator handle shared between REST and gRPC servers in one process.
pub type SharedCoordinator = Arc<Mutex<Coordinator>>;
/// API key configuration
#[derive(Clone, Debug)]
struct ApiKeyConfig {
    key: String,
    header_name: String,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            key: std::env::var("OSMOSMPC_API_KEY").unwrap_or_else(|_| "changeme".to_string()),
            header_name: "x-api-key".to_string(),
        }
    }
}

/// Authentication middleware
async fn auth_middleware(
    State(config): State<Arc<ApiKeyConfig>>,
    headers: HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Allow health and metrics without auth (metrics should be firewalled internally)
    let path = request.uri().path();
    if path == "/health" || path == "/metrics" {
        return Ok(next.run(request).await);
    }

    let api_key = headers
        .get(&config.header_name)
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        });

    match api_key {
        Some(key) if key == config.key => Ok(next.run(request).await),
        Some(_) => Err(StatusCode::UNAUTHORIZED),
        None => {
            // Return JSON error response for unauthenticated requests
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Rate limiting configuration
#[derive(Clone, Debug)]
struct RateLimitConfig {
    /// Max requests per minute per IP
    requests_per_minute: u32,
    /// Per-IP request tracker
    tracker: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u32>>>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: std::env::var("OSMOSMPC_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            tracker: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
}

/// Rate limiting middleware (simple in-memory, per-IP)
async fn rate_limit_middleware(
    State(config): State<Arc<RateLimitConfig>>,
    headers: HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip rate limiting for health check
    if request.uri().path() == "/health" || request.uri().path() == "/metrics" {
        return Ok(next.run(request).await);
    }

    // Extract client IP (simplified - in production use proper extractor)
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .unwrap_or("unknown")
        .to_string();

    // Check rate limit
    let mut tracker = config.tracker.lock().await;
    let count = tracker.entry(client_ip.clone()).or_insert(0);
    *count += 1;

    if *count > config.requests_per_minute {
        // Reset count after window expires (simple approach)
        // In production, use a proper time-based window
        tracing::warn!(client_ip = %client_ip, "Rate limit exceeded");
        Metrics::global()
            .rate_limited_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

/// Request metrics middleware (counts requests and errors)
async fn metrics_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    use std::sync::atomic::Ordering;
    Metrics::global()
        .requests_total
        .fetch_add(1, Ordering::Relaxed);
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        Metrics::global()
            .request_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }
    tracing::info!(path = %path, status = %status.as_u16(), "request handled");
    response
}

pub fn create_router() -> Router {
    let coordinator = Arc::new(Mutex::new(Coordinator::new()));
    create_router_with(coordinator)
}

/// Build the REST router on top of a caller-provided coordinator so it can be
/// shared with the gRPC server.
pub fn create_router_with(coordinator: SharedCoordinator) -> Router {
    let api_key_config = Arc::new(ApiKeyConfig::default());
    let rate_limit_config = Arc::new(RateLimitConfig::default());

    let auth_layer = middleware::from_fn_with_state(api_key_config.clone(), auth_middleware);
    let rate_limit_layer =
        middleware::from_fn_with_state(rate_limit_config.clone(), rate_limit_middleware);

    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/sessions", post(create_session))
        .route("/sessions/:id", get(get_session))
        .route("/sessions/:id/participants", post(add_participant))
        .route("/sessions/:id/execute", post(execute_session))
        .route("/sessions/:id/results", get(get_results))
        .layer(auth_layer)
        .layer(rate_limit_layer)
        .layer(middleware::from_fn(metrics_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
        .with_state(coordinator)
}

async fn health() -> &'static str {
    "ok"
}

/// Expose metrics in Prometheus text format
async fn metrics() -> axum::response::Response {
    let body = Metrics::global().render();
    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(body))
        .expect("static metrics body")
}

async fn create_session(
    State(coordinator): State<SharedCoordinator>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<SessionInfo>), StatusCode> {
    let mut coord = coordinator.lock().await;

    let circuit = ArithmeticCircuit::new();
    let policy = osmiridium_coordinator::SessionPolicy::new(req.num_parties, "api".to_string());

    let session_id = coord
        .create_session(req.name.clone(), circuit, policy)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status = coord
        .get_session_status(session_id)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Metrics::global()
        .active_sessions
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    Ok((
        StatusCode::CREATED,
        Json(SessionInfo {
            id: session_id.to_string(),
            name: req.name,
            status: format!("{:?}", status),
            num_participants: 0,
        }),
    ))
}

async fn get_session(
    State(coordinator): State<SharedCoordinator>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<SessionInfo>), StatusCode> {
    let coord = coordinator.lock().await;
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let status = coord
        .get_session_status(session_id)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    // Get real session data
    let session = coord
        .get_session(session_id)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok((
        StatusCode::OK,
        Json(SessionInfo {
            id,
            name: session.name,
            status: format!("{:?}", status),
            num_participants: session.participants.len(),
        }),
    ))
}

async fn add_participant(
    State(coordinator): State<SharedCoordinator>,
    Path(id): Path<String>,
    Json(req): Json<AddParticipantRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut coord = coordinator.lock().await;
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let role = match req.role.as_str() {
        "DataProvider" => osmiridium_coordinator::ParticipantRole::DataProvider,
        "ComputationRunner" => osmiridium_coordinator::ParticipantRole::ComputationRunner,
        "Auditor" => osmiridium_coordinator::ParticipantRole::Auditor,
        "Administrator" => osmiridium_coordinator::ParticipantRole::Administrator,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    use chrono::Utc;
    let participant = osmiridium_coordinator::Participant {
        party_id: req.party_id,
        name: req.name,
        endpoint: req.endpoint,
        role,
        joined_at: Utc::now(),
    };

    coord
        .add_participant(session_id, participant)
        .map_err(|e| match e {
            osmiridium_coordinator::CoordinatorError::SessionNotFound => StatusCode::NOT_FOUND,
            osmiridium_coordinator::CoordinatorError::AccessDenied => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    Ok(StatusCode::OK)
}

async fn execute_session(
    State(coordinator): State<SharedCoordinator>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ExecuteResponse>), StatusCode> {
    let mut coord = coordinator.lock().await;
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let result = coord
        .execute_session(session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Metrics::global()
        .executed_sessions_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    Ok((
        StatusCode::OK,
        Json(ExecuteResponse {
            results: result
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|s| {
                    use osmiridium_protocol::crypto::traits::ToBytes;
                    format!("{:x?}", s.to_bytes())
                })
                .collect(),
        }),
    ))
}

async fn get_results(
    State(coordinator): State<SharedCoordinator>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ExecuteResponse>), StatusCode> {
    let coord = coordinator.lock().await;
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Try to get real results from session
    let results = coord
        .get_session_results(session_id)
        .map_err(|_| StatusCode::NOT_FOUND)?
        .unwrap_or_default();

    Ok((
        StatusCode::OK,
        Json(ExecuteResponse {
            results: results
                .iter()
                .map(|s| {
                    use osmiridium_protocol::crypto::traits::ToBytes;
                    format!("{:x?}", s.to_bytes())
                })
                .collect(),
        }),
    ))
}

#[derive(Serialize)]
struct ExecuteResponse {
    results: Vec<String>,
}

pub async fn run_server(addr: &str) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = create_router();
    axum::serve(listener, app).await
}

/// Run the REST and gRPC servers side by side on one coordinator.
///
/// The gRPC task is spawned on the current runtime; if it stops (bind failure,
/// transport error) the fact is logged and REST keeps serving. Pass a gRPC
/// address of `"-"` to disable gRPC entirely.
pub async fn run_server_with_grpc(rest_addr: &str, grpc_addr: &str) -> std::io::Result<()> {
    let rest_listener = tokio::net::TcpListener::bind(rest_addr).await?;

    if grpc_addr == "-" {
        let app = create_router();
        return axum::serve(rest_listener, app).await;
    }

    let grpc_sockaddr: std::net::SocketAddr = grpc_addr.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid gRPC address {grpc_addr:?}: {e}"),
        )
    })?;

    let coordinator: SharedCoordinator = Arc::new(Mutex::new(Coordinator::new()));
    let app = create_router_with(coordinator.clone());

    let grpc_task = tokio::spawn(async move {
        if let Err(e) =
            crate::grpc::run_grpc_server_with_coordinator(grpc_sockaddr, coordinator).await
        {
            tracing::error!(error = %e, "gRPC server stopped");
        }
    });

    let result = axum::serve(rest_listener, app).await;
    grpc_task.abort();
    result
}
