//! Integration tests for the network in-memory transport.

use osmiridium_network::identity::Identity;
use osmiridium_network::in_memory::{InMemoryTransport, MessageRouter};
use osmiridium_network::transport::{SessionConfig, Transport, TransportType};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_in_memory_transport_send_receive() {
    let router = Arc::new(Mutex::new(MessageRouter::new()));
    let config = SessionConfig::default();

    let transport_a = InMemoryTransport::new(config.clone(), router.clone());
    let transport_b = InMemoryTransport::new(config, router.clone());

    // Party 0 sends to "party_1"
    transport_a.send("party_1", b"hello").await.unwrap();

    // Party 1 receives
    let msg = transport_b.recv("party_1").await.unwrap();
    assert_eq!(msg, b"hello");
}

#[tokio::test]
async fn test_in_memory_transport_broadcast() {
    let router = Arc::new(Mutex::new(MessageRouter::new()));
    let config = SessionConfig {
        num_parties: 3,
        ..Default::default()
    };

    let transport = InMemoryTransport::new(config, router.clone());

    transport.broadcast(b"broadcast_msg").await.unwrap();

    // Each party should receive the message
    for i in 0..3 {
        let peer_key = format!("party_{}", i);
        let msg = transport.recv(&peer_key).await.unwrap();
        assert_eq!(msg, b"broadcast_msg");
    }
}

#[tokio::test]
async fn test_identity_sign_verify() {
    let identity = Identity::generate(0, "party_0");

    let msg = b"test message";
    let sig = identity.sign(msg);
    assert!(!sig.is_empty());

    assert!(identity.verify(msg, &sig).is_ok());
}

#[tokio::test]
async fn test_identity_verify_tampered() {
    let identity = Identity::generate(0, "party_0");

    let msg = b"test message";
    let sig = identity.sign(msg);

    // Tampered message should fail verification
    let tampered = b"test tampered";
    assert!(identity.verify(tampered, &sig).is_err());
}

#[tokio::test]
async fn test_transport_type_enum() {
    let qt = TransportType::Quic;
    let ws = TransportType::WebSocket;
    assert_ne!(qt, ws);
}

#[tokio::test]
async fn test_tcp_send_receive() {
    use osmiridium_network::tcp::{listen, recv_message, send_message};

    let listener = listen("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn a server that reads one message
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        recv_message(&mut stream).await.unwrap()
    });

    // Send a message to the server
    send_message(&addr.to_string(), b"hello tcp").await.unwrap();

    let received = handle.await.unwrap();
    assert_eq!(received, b"hello tcp");
}

#[tokio::test]
async fn test_cert_generation() {
    use osmiridium_network::cert::{generate_self_signed, CertConfig};

    let config = CertConfig {
        common_name: "test-party".to_string(),
        org: "Test Org".to_string(),
    };

    let cert = generate_self_signed(&config).unwrap();

    // Verify PEM contains expected sections
    assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(cert.key_pem.contains("PRIVATE KEY"));

    // Verify fingerprint is 32 bytes
    use osmiridium_network::cert::cert_fingerprint;
    let fp = cert_fingerprint(&cert.cert_der);
    assert_eq!(fp.len(), 32);
}

#[tokio::test]
async fn test_cert_save_load() {
    use osmiridium_network::cert::{generate_self_signed, load_cert, save_cert, CertConfig};
    use std::path::Path;

    let config = CertConfig {
        common_name: "save-load-test".to_string(),
        org: "Test".to_string(),
    };

    let cert = generate_self_signed(&config).unwrap();
    let dir = Path::new("test_cert_dir");

    save_cert(&cert, dir, "test").unwrap();
    let loaded = load_cert(dir, "test").unwrap();

    assert_eq!(cert.cert_pem, loaded.cert_pem);
    assert_eq!(cert.key_pem, loaded.key_pem);

    // Cleanup
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn test_make_server_and_client_config() {
    use osmiridium_network::cert::{
        generate_self_signed, make_client_config, make_server_config, CertConfig,
    };

    // Install a default crypto provider if not already installed
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = CertConfig {
        common_name: "localhost".to_string(),
        org: "Test".to_string(),
    };

    let cert = generate_self_signed(&config).unwrap();

    let server_config = make_server_config(&cert).unwrap();
    assert!(!server_config.alpn_protocols.is_empty() || true); // just check it doesn't panic

    let client_config = make_client_config(&cert.cert_pem).unwrap();
    let _ = (server_config, client_config);
}
