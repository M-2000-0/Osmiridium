//! Integration tests for the gRPC API layer: session lifecycle and
//! distributed execution over real TCP transports driven via gRPC.

use osmiridium_api::grpc::{
    AddParticipantRequest, CoordinatorGrpcService, CoordinatorServiceClient,
    CoordinatorServiceServer, CreateSessionRequest, DefineCircuitRequest, ExecuteSessionRequest,
    HealthRequest, PartyInputs,
};
use osmiridium_coordinator::Coordinator;
use std::sync::Arc;
use tokio::sync::Mutex;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start an in-process gRPC server and return a connected client.
async fn spawn_client() -> CoordinatorServiceClient<tonic::transport::Channel> {
    let addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let coordinator = Arc::new(Mutex::new(Coordinator::new()));
    let service = CoordinatorGrpcService::new(coordinator);

    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CoordinatorServiceServer::new(service))
            .serve(addr)
            .await
            .unwrap();
    });

    // Give the server a moment to bind, then connect.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{}", addr)).unwrap();
    let channel = endpoint.connect().await.unwrap();

    // Keep the server task alive for the duration of the test.
    std::mem::forget(server);

    CoordinatorServiceClient::new(channel)
}

fn scalar_to_hex(value: u64) -> String {
    use osmiridium_protocol::crypto::field::Scalar;
    use osmiridium_protocol::crypto::traits::ToBytes;
    Scalar::from_u64(value)
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[tokio::test]
async fn test_grpc_health() {
    let mut client = spawn_client().await;
    let resp = client
        .health(HealthRequest {})
        .await
        .expect("health RPC failed");
    assert_eq!(resp.into_inner().status, "ok");
}

#[tokio::test]
async fn test_grpc_session_lifecycle_and_distributed_execution() {
    let mut client = spawn_client().await;

    // Create a session with 3 parties.
    let resp = client
        .create_session(CreateSessionRequest {
            name: "grpc_test".to_string(),
            num_parties: 3,
        })
        .await
        .expect("create session failed");
    let session_id = resp.into_inner().session_id;
    assert!(!session_id.is_empty());

    // Register three participants with real TCP endpoints.
    let mut endpoints = Vec::new();
    for party_id in 0..3 {
        let endpoint = format!("127.0.0.1:{}", free_port());
        endpoints.push(endpoint.clone());
        client
            .add_participant(AddParticipantRequest {
                session_id: session_id.clone(),
                party_id,
                name: format!("party_{}", party_id),
                endpoint,
                role: "DataProvider".to_string(),
            })
            .await
            .expect("add participant failed");
    }

    // Define the circuit (10 + 20) * 3 = 90 over three parties.
    let mut circuit = osmiridium_protocol::ArithmeticCircuit::new();
    let a = circuit.add_gate(osmiridium_protocol::Gate::Input {
        party_id: 0,
        value: osmiridium_protocol::crypto::field::Scalar::from_u64(10),
    });
    let b = circuit.add_gate(osmiridium_protocol::Gate::Input {
        party_id: 1,
        value: osmiridium_protocol::crypto::field::Scalar::from_u64(20),
    });
    let c = circuit.add_gate(osmiridium_protocol::Gate::Input {
        party_id: 2,
        value: osmiridium_protocol::crypto::field::Scalar::from_u64(3),
    });
    let sum = circuit.add(a, b);
    let mul = circuit.mul(sum, c);
    circuit.output(mul, vec![0, 1, 2]);
    circuit.set_num_inputs(0);

    client
        .define_circuit(DefineCircuitRequest {
            session_id: session_id.clone(),
            circuit: bincode::serialize(&circuit).unwrap(),
        })
        .await
        .expect("define circuit failed");

    // Execute (10 + 20) * 3 = 90 via the distributed gRPC path.
    let inputs: Vec<PartyInputs> = (0..3)
        .map(|party_id| {
            let value = [10u64, 20, 3][party_id as usize];
            let mut values = std::collections::HashMap::new();
            values.insert(party_id as u64, scalar_to_hex(value));
            PartyInputs { party_id, values }
        })
        .collect();

    let resp = client
        .execute_session(ExecuteSessionRequest { session_id, inputs })
        .await
        .expect("execute session failed");

    let outputs = resp.into_inner().outputs;
    assert_eq!(outputs.len(), 3);

    // Every party reconstructs the same result: 90.
    for output in &outputs {
        for value in output.values.values() {
            assert_eq!(
                *value,
                scalar_to_hex(90),
                "party {} wrong result",
                output.party_id
            );
        }
    }
}
