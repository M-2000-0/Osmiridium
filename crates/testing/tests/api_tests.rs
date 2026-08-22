//! Integration tests for the API server.
//!
//! Requests to protected endpoints must carry the API key expected by the
//! auth middleware (default `changeme`, override with OSMOSMPC_API_KEY).

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use osmiridium_api::create_router;
use tower::ServiceExt;

const TEST_API_KEY: &str = "changeme";

#[tokio::test]
async fn test_api_health_check() {
    let router = create_router();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let _body = to_bytes(response.into_body(), 1024).await.unwrap();
}

#[tokio::test]
async fn test_api_create_session() {
    let router = create_router();

    let body = r#"{"name":"test_session","num_parties":3}"#;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sessions")
                .header("content-type", "application/json")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body_bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(body_str.contains("test_session"));
}

#[tokio::test]
async fn test_api_get_session_bad_id() {
    let router = create_router();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sessions/invalid-id")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_api_add_participant() {
    let router = create_router();

    // Create session
    let body = r#"{"name":"participant_test","num_parties":3}"#;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sessions")
                .header("content-type", "application/json")
                .header("x-api-key", TEST_API_KEY)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body_bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Extract session ID (simple parse)
    if let Some(start) = body_str.find("\"id\":\"") {
        if let Some(end) = body_str[start + 6..].find('"').map(|p| start + 6 + p) {
            let session_id = &body_str[start + 6..end];

            // Add first participant
            let participant = r#"{"party_id":0,"name":"alice","endpoint":"localhost:9000","role":"DataProvider"}"#;
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/sessions/{}/participants", session_id))
                        .header("content-type", "application/json")
                        .header("x-api-key", TEST_API_KEY)
                        .body(Body::from(participant))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }
}
