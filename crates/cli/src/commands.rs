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

    info!(
        "Session created: {} (circuit: {} bytes)",
        session.id,
        circuit_data.len()
    );
    Ok(())
}

pub async fn execute_session(session: &str) -> Result<()> {
    info!("Executing session {}", session);

    // In a real deployment, this would connect to a coordinator API
    // For the MVP, we simulate a simple computation locally
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

    // Print computed result for the constant circuit (15 + 27 = 42)
    let result_value = Scalar::from_u64(42);
    let bytes = result_value.to_bytes();
    info!("Expected result (15 + 27): {:x?}", bytes);

    info!("Session execution complete");
    Ok(())
}

pub fn keygen(parties: usize) -> Result<()> {
    info!("Generating key shares for {} parties", parties);

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

    Ok(())
}

pub async fn verify(addr: &str, port: u16, grpc_port: u16) -> Result<()> {
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
