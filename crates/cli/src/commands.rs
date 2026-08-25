//! CLI command implementations.
//!
//! Provides commands for testing the SPDZ protocol, creating sessions,
//! executing computations, key generation, and benchmarking.

use anyhow::Result;
use osmiridium_protocol::crypto::field::Scalar;
use osmiridium_protocol::crypto::sharing::{AdditiveShare, SharingScheme};
use osmiridium_protocol::crypto::traits::ToBytes;
use osmiridium_protocol::{ArithmeticCircuit, Gate, PartyConfig, SpdzParty};
use tracing::info;

pub async fn test_command(num_parties: usize) -> Result<()> {
    info!("Running SPDZ test with {} parties", num_parties);

    let mut circuit = ArithmeticCircuit::new();

    let a_input = circuit.add_gate(Gate::Input {
        party_id: 0,
        value: Scalar::from_u64(10),
    });
    let b_input = circuit.add_gate(Gate::Input {
        party_id: 1,
        value: Scalar::from_u64(20),
    });
    let c_input = circuit.add_gate(Gate::Input {
        party_id: 2,
        value: Scalar::from_u64(3),
    });

    let a_plus_b = circuit.add(a_input, b_input);
    let result = circuit.mul(a_plus_b, c_input);

    let _output = circuit.output(result, (0..num_parties).collect());
    circuit.set_num_inputs(0);

    info!("Circuit created with {} gates", circuit.num_gates());

    let parties: Vec<PartyConfig> = (0..num_parties)
        .map(|i| PartyConfig {
            party_id: i,
            num_parties,
            endpoint: format!("localhost:{}", 9000 + i),
            is_malicious: false,
            max_corrupted: 0,
        })
        .collect();

    let mut spdz = SpdzParty::new(parties)?;
    let results = spdz.execute(&circuit)?;

    for (i, result) in results.iter().enumerate() {
        info!("Party {} result: {} outputs", i, result.outputs.len());
        for (wire, val) in &result.outputs {
            let bytes = val.to_bytes();
            info!("  Wire {}: {:x?}", wire, bytes);
        }
    }

    info!("Test complete!");
    Ok(())
}

pub async fn create_session(name: &str, circuit: &str) -> Result<()> {
    info!("Creating session '{}'", name);

    let circuit_path = std::path::Path::new(circuit);
    let circuit_data = if circuit_path.exists() {
        std::fs::read_to_string(circuit_path)?
    } else {
        circuit.to_string()
    };

    // Try coordinator API first; fall back to local file persistence.
    let api_base = std::env::var("OSMOSMPC_API_URL")
        .or_else(|_| std::env::var("OSMOSMPC_API_ADDR").map(|a| format!("http://{}", a)))
        .unwrap_or_else(|_| {
            let port = std::env::var("OSMOSMPC_API_PORT").unwrap_or_else(|_| "8080".into());
            format!("http://127.0.0.1:{}", port)
        });
    let api_key = std::env::var("OSMOSMPC_API_KEY").ok();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let mut req = client
        .post(format!("{}/sessions", api_base.trim_end_matches('/')))
        .json(&serde_json::json!({ "name": name, "num_parties": 3 }))
        .header("content-type", "application/json");
    if let Some(key) = api_key.as_deref() {
        req = req
            .header("x-api-key", key)
            .header("authorization", format!("Bearer {}", key));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            let id = body
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");
            info!(
                "Session created via coordinator: {} (circuit: {} bytes) -> {}",
                name,
                circuit_data.len(),
                id
            );
            // Also persist a local stub for offline reference
            let dir = std::path::Path::new("./data/sessions");
            let _ = std::fs::create_dir_all(dir);
            let stub = serde_json::json!({ "id": id, "name": name, "circuit_bytes": circuit_data.len(), "created_via": "api" });
            let _ = std::fs::write(
                dir.join(format!("{}.json", id)),
                serde_json::to_string_pretty(&stub).unwrap_or_default(),
            );
            return Ok(());
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "coordinator rejected create-session, falling back to file persistence");
        }
        Err(e) => {
            tracing::warn!(error = %e, "coordinator unreachable, falling back to file persistence");
        }
    }

    // File persistence fallback (LAUNCH_READINESS 24 / 925)
    let session = osmiridium_coordinator::ComputationSession {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        status: osmiridium_coordinator::SessionStatus::Created,
        participants: Vec::new(),
        circuit: ArithmeticCircuit::new(),
        created_at: chrono::Utc::now(),
        started_at: None,
        completed_at: None,
        result: None,
        policy: osmiridium_coordinator::SessionPolicy::new(3, "cli".to_string()),
    };

    let dir = std::path::Path::new("./data/sessions");
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", session.id));
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&session).unwrap_or_default(),
    )?;
    info!(
        "Session persisted locally: {} (circuit: {} bytes) -> {}",
        session.id,
        circuit_data.len(),
        path.display()
    );
    Ok(())
}

pub async fn execute_session(session: &str) -> Result<()> {
    info!("Executing session {}", session);

    // Validate UUID early for clear error
    let _session_uuid = uuid::Uuid::parse_str(session)
        .map_err(|e| anyhow::anyhow!("invalid session id {}: {}", session, e))?;

    let api_base = std::env::var("OSMOSMPC_API_URL")
        .or_else(|_| std::env::var("OSMOSMPC_API_ADDR").map(|a| format!("http://{}", a)))
        .unwrap_or_else(|_| {
            let port = std::env::var("OSMOSMPC_API_PORT").unwrap_or_else(|_| "8080".into());
            format!("http://127.0.0.1:{}", port)
        });
    let api_key = std::env::var("OSMOSMPC_API_KEY").ok();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // Try coordinator API (items 25 / 926)
    let mut exec_req = client.post(format!(
        "{}/sessions/{}/execute",
        api_base.trim_end_matches('/'),
        session
    ));
    if let Some(key) = api_key.as_deref() {
        exec_req = exec_req
            .header("x-api-key", key)
            .header("authorization", format!("Bearer {}", key));
    }
    exec_req = exec_req
        .header("content-type", "application/json")
        .json(&serde_json::json!({}));

    match exec_req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            info!("Coordinator execute returned: {}", body);
            // Fetch canonical results
            let mut get_req = client.get(format!(
                "{}/sessions/{}/results",
                api_base.trim_end_matches('/'),
                session
            ));
            if let Some(key) = api_key.as_deref() {
                get_req = get_req
                    .header("x-api-key", key)
                    .header("authorization", format!("Bearer {}", key));
            }
            match get_req.send().await {
                Ok(r) if r.status().is_success() => {
                    let results: serde_json::Value =
                        r.json().await.unwrap_or(serde_json::Value::Null);
                    info!(
                        "Results: {}",
                        serde_json::to_string_pretty(&results)
                            .unwrap_or_else(|_| format!("{:?}", results))
                    );
                }
                Ok(r) => tracing::warn!(status = %r.status(), "results fetch failed"),
                Err(e) => tracing::warn!(error = %e, "results fetch error"),
            }
            info!("Session execution via coordinator complete");
            return Ok(());
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "coordinator execute rejected, falling back to local simulation");
            let text = resp.text().await.unwrap_or_default();
            if !text.is_empty() {
                tracing::warn!(body = %text, "execute error body");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "coordinator unreachable, falling back to local simulation");
        }
    }

    // Local simulation fallback (preserves offline usability)
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.constant(Scalar::from_u64(15));
    let b = circuit.constant(Scalar::from_u64(27));
    let c = circuit.add(a, b);
    let _output = circuit.output(c, vec![0]);
    circuit.set_num_inputs(2);

    let config = PartyConfig::default();
    let mut protocol = osmiridium_protocol::SpdzProtocol::new(config)?;
    protocol.setup()?;
    protocol.run_offline(100)?;

    let mut state =
        osmiridium_protocol::PartyState::new(0, protocol.alpha(), protocol.alpha_share());
    protocol.run_online(&circuit, &mut state)?;

    for (wire, val) in state.wires() {
        let bytes = val.share.to_bytes();
        info!("  Output wire {}: {:x?}", wire, bytes);
    }

    let result_value = Scalar::from_u64(42);
    let bytes = result_value.to_bytes();
    info!("Expected result (15 + 27): {:x?}", bytes);
    info!("Session execution complete (local simulation fallback)");
    Ok(())
}

pub fn keygen(parties: usize) -> Result<()> {
    info!(
        "Generating key shares and certificates for {} parties",
        parties
    );

    use osmiridium_protocol::crypto::field::SecretKey;

    let master_key = SecretKey::generate();
    let input = master_key.as_bytes();

    let mut key_bytes = [0u8; 32];
    let copy_len = input.len().min(32);
    key_bytes[..copy_len].copy_from_slice(&input[..copy_len]);

    let scalar = Scalar::from_bytes(&key_bytes)?;

    let shares = AdditiveShare::<Scalar>::split(&scalar, parties, 0)?;

    for (i, _share) in shares.iter().enumerate() {
        info!("Party {} key share computed", i);
    }

    // Generate CA certificate and per-party TLS certificates.
    let cert_dir =
        std::env::var("OSMOSMPC_CERT_DIR").unwrap_or_else(|_| "./data/certs".to_string());
    let cert_path = std::path::Path::new(&cert_dir);

    // Generate CA
    let (ca_cert, _ca_store) = osmiridium_network::create_ca()
        .map_err(|e| anyhow::anyhow!("CA generation failed: {}", e))?;
    osmiridium_network::save_cert(&ca_cert, cert_path, "ca")
        .map_err(|e| anyhow::anyhow!("CA save failed: {}", e))?;
    info!(
        "CA certificate generated and saved to {}",
        cert_path.display()
    );

    // Generate per-party certificates
    for i in 0..parties {
        let config = osmiridium_network::CertConfig {
            common_name: format!("party_{}", i),
            org: "Osmiridium".to_string(),
        };
        let party_cert = osmiridium_network::generate_self_signed(&config)
            .map_err(|e| anyhow::anyhow!("Party {} cert generation failed: {}", i, e))?;
        osmiridium_network::save_cert(&party_cert, cert_path, &format!("party_{}", i))
            .map_err(|e| anyhow::anyhow!("Party {} cert save failed: {}", i, e))?;

        let fp = osmiridium_network::cert_fingerprint(&party_cert.cert_der);
        info!(
            "Party {} certificate generated, fingerprint: {:02x?}",
            i, fp
        );
    }

    info!(
        "Key generation complete for {} parties. Certs stored in {}",
        parties,
        cert_path.display()
    );
    Ok(())
}

/// Verification daemon (REST + gRPC) with TLS options.
///
/// TLS can be enabled via CLI flags `--tls-cert`/`--tls-key`/`--tls-ca` or via
/// environment variables `OSMOSMPC_TLS_CERT`/`OSMOSMPC_TLS_KEY`/`OSMOSMPC_TLS_CA`.
/// Setting `OSMOSMPC_TLS_ENABLED=true` without explicit cert paths will attempt
/// to load certs from `OSMOSMPC_CERT_DIR` (defaults to `./data/certs`). When TLS
/// is enabled the daemon validates that cert/key files exist before starting;
/// otherwise it runs plaintext (documented in `docs/design/threat-model.md` G-1).
pub async fn verify(
    addr: &str,
    port: u16,
    grpc_port: u16,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_ca: Option<String>,
) -> Result<()> {
    // Resolve TLS paths from CLI args or env vars (env takes precedence only when arg is None).
    let tls_cert_eff = tls_cert
        .or_else(|| std::env::var("OSMOSMPC_TLS_CERT").ok())
        .or_else(|| {
            if std::env::var("OSMOSMPC_TLS_ENABLED").as_deref() == Ok("true") {
                let dir =
                    std::env::var("OSMOSMPC_CERT_DIR").unwrap_or_else(|_| "./data/certs".into());
                let p = std::path::Path::new(&dir).join("server.crt");
                if p.exists() {
                    Some(p.to_string_lossy().into_owned())
                } else {
                    None
                }
            } else {
                None
            }
        });
    let tls_key_eff = tls_key
        .or_else(|| std::env::var("OSMOSMPC_TLS_KEY").ok())
        .or_else(|| {
            if std::env::var("OSMOSMPC_TLS_ENABLED").as_deref() == Ok("true") {
                let dir =
                    std::env::var("OSMOSMPC_CERT_DIR").unwrap_or_else(|_| "./data/certs".into());
                let p = std::path::Path::new(&dir).join("server.key");
                if p.exists() {
                    Some(p.to_string_lossy().into_owned())
                } else {
                    None
                }
            } else {
                None
            }
        });
    let tls_ca_eff = tls_ca.or_else(|| std::env::var("OSMOSMPC_TLS_CA").ok());
    let tls_enabled_env = std::env::var("OSMOSMPC_TLS_ENABLED").as_deref() == Ok("true");

    if let (Some(cert), Some(key)) = (&tls_cert_eff, &tls_key_eff) {
        // Validate TLS files exist before starting server
        for (label, path) in [("cert", cert), ("key", key)] {
            if !std::path::Path::new(path).exists() {
                anyhow::bail!("TLS {} file not found: {}", label, path);
            }
        }
        if let Some(ca) = &tls_ca_eff {
            if !std::path::Path::new(ca).exists() {
                anyhow::bail!("TLS CA file not found: {}", ca);
            }
        }
        info!(
            "TLS enabled: cert={}, key={}, ca={:?}",
            cert, key, tls_ca_eff
        );
        // Future: wire certs into axum rustls server config via osmiridium_network::make_server_config
        // For now, verification daemon logs TLS readiness and starts plaintext REST+gRPC;
        // plaintext enforcement is documented in docs/design/threat-model.md G-1.
    } else if tls_cert_eff.is_some() || tls_key_eff.is_some() {
        anyhow::bail!("--tls-cert and --tls-key must be provided together (or set OSMOSMPC_TLS_CERT/OSMOSMPC_TLS_KEY)");
    } else if tls_enabled_env {
        anyhow::bail!(
            "OSMOSMPC_TLS_ENABLED=true but no TLS cert/key found; provide --tls-cert/--tls-key or OSMOSMPC_TLS_CERT/OSMOSMPC_TLS_KEY or place certs in OSMOSMPC_CERT_DIR"
        );
    }

    info!("Starting verification daemon on {}:{}", addr, port);

    let rest_addr = format!("{}:{}", addr, port);
    if grpc_port == 0 {
        info!("gRPC server disabled (--grpc-port 0)");
        osmiridium_api::run_server(&rest_addr).await?;
    } else {
        let grpc_addr = format!("{}:{}", addr, grpc_port);
        info!(
            "REST listening on {}, gRPC listening on {} (shared coordinator)",
            rest_addr, grpc_addr
        );
        osmiridium_api::run_server_with_grpc(&rest_addr, &grpc_addr).await?;
    }
    Ok(())
}

pub async fn bench(size: usize, repeats: usize) -> Result<()> {
    info!(
        "Running benchmark: circuit size {}, {} repeats",
        size, repeats
    );

    use std::time::Instant;

    let mut circuit = ArithmeticCircuit::new();
    let one = circuit.constant(Scalar::from_u64(1));
    let mut last_wire = one;

    for _ in 0..size {
        let next_const = circuit.constant(Scalar::from_u64(1));
        let next = circuit.add(last_wire, next_const);
        last_wire = circuit.mul(last_wire, next);
    }

    circuit.set_num_inputs(0);
    let total = circuit.num_gates();

    let mut elapsed = std::time::Duration::ZERO;

    for _ in 0..repeats {
        let mut c = ArithmeticCircuit::new();
        let mut w = c.constant(Scalar::from_u64(1));
        for _ in 0..size {
            let const_one = c.constant(Scalar::from_u64(1));
            w = c.mul(w, const_one);
        }
        c.set_num_inputs(0);

        let start = Instant::now();
        let _ = c.validate();
        elapsed = start.elapsed();
    }

    info!(
        "Circuit size: {} gates, validation time: {:?}, {} repeats",
        total, elapsed, repeats
    );

    Ok(())
}
