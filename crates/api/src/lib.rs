//! REST + gRPC coordinator API.
//!
//! Axum router with tracing, 1 MiB body limit, per-IP rate limiting, and
//! `x-api-key`/`Bearer` auth; tonic gRPC service sharing the same
//! `Coordinator`. See `docs/api/openapi.yaml`.
//!
//! ```rust,no_run
//! use osmiridium_api::create_router;
//! let app = create_router();
//! ```

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

/// Standard JSON error response body.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: u16,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

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

#[derive(Clone, Debug)]
struct RateLimitEntry {
    count: u32,
    window_start: std::time::Instant,
}

/// Rate limiting configuration — per-IP sliding window (1 minute).
#[derive(Clone, Debug)]
struct RateLimitConfig {
    /// Max requests per minute per IP
    requests_per_minute: u32,
    /// Per-IP tracker: count + window start. Reset after 60s.
    tracker: Arc<tokio::sync::Mutex<std::collections::HashMap<String, RateLimitEntry>>>,
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

/// Rate limiting middleware — fixed window per IP, resets every 60s (#4).
async fn rate_limit_middleware(
    State(config): State<Arc<RateLimitConfig>>,
    headers: HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if request.uri().path() == "/health" || request.uri().path() == "/metrics" {
        return Ok(next.run(request).await);
    }

    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .unwrap_or("unknown")
        .to_string();

    {
        let mut tracker = config.tracker.lock().await;
        let now = std::time::Instant::now();
        let entry = tracker.entry(client_ip.clone()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });
        // Reset window after 60s
        if now.duration_since(entry.window_start).as_secs() >= 60 {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        if entry.count > config.requests_per_minute {
            tracing::warn!(client_ip = %client_ip, "Rate limit exceeded");
            Metrics::global()
                .rate_limited_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
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

/// Build the coordinator used by the shipped servers, enabling durable
/// session storage when `OSMOSMPC_DATA_DIR` is set.
fn build_coordinator() -> SharedCoordinator {
    let coordinator = match std::env::var("OSMOSMPC_DATA_DIR") {
        Ok(dir) => {
            tracing::info!(dir = %dir, "session persistence enabled");
            Coordinator::new().with_persistence(dir)
        }
        Err(_) => Coordinator::new(),
    };
    Arc::new(Mutex::new(coordinator))
}

pub fn create_router() -> Router {
    create_router_with(build_coordinator())
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
        .route("/sessions", get(list_sessions).post(create_session))
        .route("/sessions/:id", get(get_session))
        .route("/sessions/:id/participants", post(add_participant))
        .route("/sessions/:id/execute", post(execute_session))
        .route("/sessions/:id/results", get(get_results))
        .route("/sessions/:id/cancel", post(cancel_session))
        .layer(auth_layer)
        .layer(rate_limit_layer)
        .layer(middleware::from_fn(metrics_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
        .with_state(coordinator)
}

async fn health() -> axum::response::Response {
    let body = serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    });
    axum::response::Response::builder()
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("static health body")
}

/// List all sessions with optional state filter.
async fn list_sessions(
    State(coordinator): State<SharedCoordinator>,
) -> Result<(StatusCode, Json<Vec<SessionInfo>>), StatusCode> {
    let coord = coordinator.lock().await;
    let sessions = coord.list_sessions();
    let infos: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|s| SessionInfo {
            id: s.id.to_string(),
            name: s.name,
            status: format!("{:?}", s.status),
            num_participants: s.participants.len(),
        })
        .collect();
    Ok((StatusCode::OK, Json(infos)))
}

/// Cancel a session.
async fn cancel_session(
    State(coordinator): State<SharedCoordinator>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                code: 400,
                message: format!("invalid session id: {}", id),
                details: None,
            }),
        )
    })?;
    let mut coord = coordinator.lock().await;
    coord.cancel_session(session_id).map_err(|e| {
        (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "conflict".to_string(),
                code: 409,
                message: e.to_string(),
                details: None,
            }),
        )
    })?;
    Ok(StatusCode::OK)
}

/// Expose metrics in Prometheus text format
async fn metrics() -> axum::response::Response {
    let body = Metrics::global().render();
    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(body))
        .expect("static metrics body")
}

/// Request ID header for correlation.
const REQUEST_ID_HEADER: &str = "x-request-id";

async fn create_session(
    State(coordinator): State<SharedCoordinator>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<SessionInfo>), (StatusCode, Json<ErrorResponse>)> {
    let mut coord = coordinator.lock().await;

    // Validate inputs
    if req.name.is_empty() || req.name.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                code: 400,
                message: "name must be between 1 and 128 characters".to_string(),
                details: None,
            }),
        ));
    }
    if req.num_parties < 2 || req.num_parties > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                code: 400,
                message: "num_parties must be between 2 and 64".to_string(),
                details: None,
            }),
        ));
    }

    let circuit = ArithmeticCircuit::new();
    let policy = osmiridium_coordinator::SessionPolicy::new(req.num_parties, "api".to_string());

    let session_id = coord
        .create_session(req.name.clone(), circuit, policy)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "internal_error".to_string(),
                    code: 500,
                    message: "failed to create session".to_string(),
                    details: None,
                }),
            )
        })?;

    let status = coord.get_session_status(session_id).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                code: 404,
                message: "session not found".to_string(),
                details: None,
            }),
        )
    })?;

    Metrics::global()
        .active_sessions
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let request_id = headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    tracing::info!(session_id = %session_id, request_id = %request_id, "session created");

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
) -> Result<(StatusCode, Json<SessionInfo>), (StatusCode, Json<ErrorResponse>)> {
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                code: 400,
                message: format!("invalid session id: {}", id),
                details: None,
            }),
        )
    })?;

    let coord = coordinator.lock().await;
    let status = coord.get_session_status(session_id).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                code: 404,
                message: "session not found".to_string(),
                details: None,
            }),
        )
    })?;

    let session = coord.get_session(session_id).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".to_string(),
                code: 404,
                message: "session not found".to_string(),
                details: None,
            }),
        )
    })?;

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

/// Validate an endpoint string (host:port or IP:port format).
fn validate_endpoint(endpoint: &str) -> Result<(), StatusCode> {
    if endpoint.is_empty() || endpoint.len() > 256 {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Accept both socket addresses (127.0.0.1:9000) and hostnames (localhost:9000).
    let has_port = endpoint
        .rsplit(':')
        .next()
        .map(|p| p.parse::<u16>().is_ok())
        .unwrap_or(false);
    if !has_port {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

/// Validate party_id is within the valid range for the session.
fn validate_party_id(
    party_id: usize,
    session: &osmiridium_coordinator::ComputationSession,
) -> Result<(), StatusCode> {
    if party_id >= session.policy.access.max_participants {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Check for duplicate party_id
    if session.participants.iter().any(|p| p.party_id == party_id) {
        return Err(StatusCode::CONFLICT);
    }
    Ok(())
}

async fn add_participant(
    State(coordinator): State<SharedCoordinator>,
    Path(id): Path<String>,
    Json(req): Json<AddParticipantRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut coord = coordinator.lock().await;
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Validate inputs
    if req.name.is_empty() || req.name.len() > 128 {
        return Err(StatusCode::BAD_REQUEST);
    }
    validate_endpoint(&req.endpoint)?;

    let role = match req.role.as_str() {
        "DataProvider" => osmiridium_coordinator::ParticipantRole::DataProvider,
        "ComputationRunner" => osmiridium_coordinator::ParticipantRole::ComputationRunner,
        "Auditor" => osmiridium_coordinator::ParticipantRole::Auditor,
        "Administrator" => osmiridium_coordinator::ParticipantRole::Administrator,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // Validate party_id before inserting
    {
        let session = coord
            .get_session(session_id)
            .map_err(|_| StatusCode::NOT_FOUND)?;
        validate_party_id(req.party_id, &session)?;
    }

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
            osmiridium_coordinator::CoordinatorError::AlreadyStarted => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    Ok(StatusCode::OK)
}

async fn execute_session(
    State(coordinator): State<SharedCoordinator>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ExecuteResponse>), (StatusCode, Json<ErrorResponse>)> {
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                code: 400,
                message: format!("invalid session id: {}", id),
                details: None,
            }),
        )
    })?;

    let mut coord = coordinator.lock().await;

    let result = coord.execute_session(session_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "execution_error".to_string(),
                code: 500,
                message: "session execution failed".to_string(),
                details: Some(e.to_string()),
            }),
        )
    })?;

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
) -> Result<(StatusCode, Json<ExecuteResponse>), (StatusCode, Json<ErrorResponse>)> {
    let session_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                code: 400,
                message: format!("invalid session id: {}", id),
                details: None,
            }),
        )
    })?;

    let coord = coordinator.lock().await;
    let results = coord
        .get_session_results(session_id)
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not_found".to_string(),
                    code: 404,
                    message: "session not found".to_string(),
                    details: None,
                }),
            )
        })?
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

    let coordinator: SharedCoordinator = build_coordinator();
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
