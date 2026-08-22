//! Comprehensive test suite for the Osmiridium SMPC platform.

use osmiridium_crypto::field::Scalar;
use osmiridium_crypto::mac::{AuthenticatedShare, MacKey, ShareBundle};
use osmiridium_crypto::prss::Prss;
use osmiridium_crypto::sharing::{AdditiveShare, ShamirShare, SharingScheme};
use osmiridium_crypto::traits::ToBytes;
use osmiridium_protocol::offline::OfflinePhase;
use osmiridium_protocol::online::{OnlineConfig, OnlinePhase, PartyState};
use osmiridium_protocol::verification::{MacVerifier, Transcript, TranscriptEntry};
use osmiridium_protocol::{ArithmeticCircuit, PartyConfig, SpdzProtocol};

#[test]
fn test_scalar_arithmetic() {
    let a = Scalar::from_u64(10);
    let b = Scalar::from_u64(20);
    let sum = a + b;
    let diff = b - a;
    let product = a * b;

    assert_eq!(sum, Scalar::from_u64(30));
    assert_eq!(diff, Scalar::from_u64(10));
    assert_eq!(product, Scalar::from_u64(200));
}

#[test]
fn test_scalar_bytes_roundtrip() {
    let original = Scalar::from_u64(42);
    let bytes = original.to_bytes();
    let recovered = Scalar::from_bytes(&bytes).unwrap();
    assert_eq!(original, recovered);
}

#[test]
fn test_additive_sharing() {
    let secret = Scalar::from_u64(12345);
    let n = 3;
    let shares = AdditiveShare::<Scalar>::split(&secret, n, 0).unwrap();
    assert_eq!(shares.len(), n);

    let reconstructed = AdditiveShare::<Scalar>::reconstruct(&shares).unwrap();
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_additive_share_addition() {
    let a = Scalar::from_u64(100);
    let b = Scalar::from_u64(200);
    let expected_sum = Scalar::from_u64(300);

    let shares_a = AdditiveShare::<Scalar>::split(&a, 3, 0).unwrap();
    let shares_b = AdditiveShare::<Scalar>::split(&b, 3, 0).unwrap();

    let mut sum_shares = Vec::new();
    for (sa, sb) in shares_a.iter().zip(shares_b.iter()) {
        let sum = AdditiveShare::<Scalar>::add_shares(sa, sb).unwrap();
        sum_shares.push(sum);
    }

    let reconstructed = AdditiveShare::<Scalar>::reconstruct(&sum_shares).unwrap();
    assert_eq!(reconstructed, expected_sum);
}

#[test]
fn test_shamir_sharing() {
    let secret = Scalar::from_u64(99999);
    let n = 5;
    let threshold = 2;
    let shares = ShamirShare::<Scalar>::split(&secret, n, threshold).unwrap();
    assert_eq!(shares.len(), n);

    // Should reconstruct with threshold + 1 shares
    let reconstructed = ShamirShare::<Scalar>::reconstruct(&shares[..threshold + 1]).unwrap();
    assert_eq!(reconstructed, secret);

    // Should NOT reconstruct with fewer shares (different result)
    if threshold > 0 {
        let insufficient =
            ShamirShare::<Scalar>::reconstruct(&shares[..threshold]).unwrap_or(Scalar::zero());
        assert_ne!(insufficient, secret);
    }
}

#[test]
fn test_prss_share_generation() {
    let prss = Prss::new(0, 3);
    let share1 = prss.generate_share(0).unwrap();
    let share2 = prss.generate_share(1).unwrap();

    // Different counters should give different shares
    assert_ne!(share1, share2);
}

#[test]
fn test_mac_key_generation() {
    let key = MacKey::generate(3).unwrap();
    assert_eq!(key.shares.len(), 3);
}

#[test]
fn test_authenticated_share_verification() {
    let alpha = Scalar::from_u64(123);
    let share_value = Scalar::from_u64(456);

    let auth_share = AuthenticatedShare::authenticate(share_value, alpha, alpha, 0);

    let bundle = ShareBundle {
        shares: vec![auth_share],
    };

    // With a single party, the verification should pass
    // because mac = alpha * share, and alpha = alpha, value = share
    let result = bundle.verify_all();
    assert!(result.is_ok());
}

#[test]
fn test_share_bundle_reconstruction() {
    let alpha = Scalar::from_u64(42);
    let alpha_share1 = Scalar::from_u64(21);
    let alpha_share2 = Scalar::from_u64(21);
    let value = Scalar::from_u64(100);

    let share1 = AuthenticatedShare::authenticate(Scalar::from_u64(30), alpha, alpha_share1, 0);
    let share2 = AuthenticatedShare::authenticate(Scalar::from_u64(70), alpha, alpha_share2, 1);

    let bundle = ShareBundle {
        shares: vec![share1, share2],
    };

    let reconstructed = bundle.reconstruct().unwrap();
    assert_eq!(reconstructed, value);
}

#[test]
fn test_mac_tamper_detection() {
    let alpha = Scalar::from_u64(999);
    let alpha_share = alpha;

    let share1 = AuthenticatedShare::authenticate(Scalar::from_u64(10), alpha, alpha_share, 0);
    let share2 = AuthenticatedShare::authenticate(Scalar::from_u64(20), alpha, alpha_share, 1);
    let mut tampered = ShareBundle {
        shares: vec![share1, share2],
    };

    // Tamper with a share
    tampered.shares[0].share = Scalar::from_u64(50); // Changed from 10 to 50

    let result = tampered.verify_all();
    assert!(
        result.is_err(),
        "MAC verification should fail on tampered data"
    );
}

#[test]
fn test_circuit_creation() {
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.constant(Scalar::from_u64(5));
    let b = circuit.constant(Scalar::from_u64(3));
    let c = circuit.add(a, b);
    let _d = circuit.mul(c, a);

    assert_eq!(circuit.num_gates(), 4);
    assert_eq!(circuit.count_mul_gates(), 1);
}

#[test]
fn test_spdz_protocol_setup() {
    let config = PartyConfig {
        party_id: 0,
        num_parties: 3,
        endpoint: "localhost:8080".to_string(),
        is_malicious: false,
        max_corrupted: 0,
    };

    let mut protocol = SpdzProtocol::new(config).unwrap();
    protocol.setup().unwrap();

    assert_ne!(protocol.alpha_share(), Scalar::zero());
}

#[test]
fn test_spdz_online_phase() {
    // Create a simple circuit: output(a + b * c) with constants
    let mut circuit = ArithmeticCircuit::new();
    let a = circuit.constant(Scalar::from_u64(5));
    let b = circuit.constant(Scalar::from_u64(3));
    let c = circuit.constant(Scalar::from_u64(2));

    let bc = circuit.mul(b, c);
    let result = circuit.add(a, bc);
    let _output = circuit.output(result, vec![0]);
    circuit.set_num_inputs(3);

    // Setup
    let config = PartyConfig {
        party_id: 0,
        num_parties: 3,
        endpoint: "localhost:8080".to_string(),
        is_malicious: false,
        max_corrupted: 0,
    };

    let mut protocol = SpdzProtocol::new(config).unwrap();
    protocol.setup().unwrap();
    protocol.run_offline(10).unwrap();

    let mut state = PartyState::new(0, protocol.alpha(), protocol.alpha_share());

    let online = OnlinePhase::new(OnlineConfig::default());
    online
        .evaluate_circuit(&circuit, &mut state, protocol.preprocessing())
        .unwrap();

    assert!(state.wires().contains_key(&result));
}

#[test]
fn test_mac_verifier() {
    let alpha = Scalar::from_u64(42);
    let alpha_share1 = Scalar::from_u64(21);
    let alpha_share2 = Scalar::from_u64(21);
    let verifier = MacVerifier::new(alpha, 3);

    let share1 = AuthenticatedShare::authenticate(Scalar::from_u64(10), alpha, alpha_share1, 0);
    let share2 = AuthenticatedShare::authenticate(Scalar::from_u64(20), alpha, alpha_share2, 1);

    let bundle = ShareBundle {
        shares: vec![share1, share2],
    };

    let result = verifier.verify(&bundle).unwrap();
    assert!(result.passed);
}

#[test]
fn test_batch_mac_verification() {
    let alpha = Scalar::from_u64(42);
    let verifier = MacVerifier::new(alpha, 3);

    let share1 = AuthenticatedShare::authenticate(Scalar::from_u64(10), alpha, alpha, 0);
    let share2 = AuthenticatedShare::authenticate(Scalar::from_u64(20), alpha, alpha, 0);
    let share3 = AuthenticatedShare::authenticate(Scalar::from_u64(30), alpha, alpha, 0);

    let bundles = vec![
        ShareBundle {
            shares: vec![share1],
        },
        ShareBundle {
            shares: vec![share2],
        },
        ShareBundle {
            shares: vec![share3],
        },
    ];

    let result = verifier.batch_verify(&bundles).unwrap();
    assert!(result);
}

#[test]
fn test_transcript_creation() {
    let mut transcript = Transcript::new();
    transcript.add(TranscriptEntry::new(1, "test_op", 0, [0u8; 32], true));
    assert_eq!(transcript.len(), 1);
}

#[test]
fn test_fhe_ciphertext_creation() {
    use osmiridium_fhe::{FheParams, Plaintext, ThresholdFhe};

    let params = FheParams {
        threshold: 1,
        ..Default::default()
    };
    let (pk, sk_shares) = ThresholdFhe::keygen(params.clone()).unwrap();

    let fhe = ThresholdFhe::new(params.clone(), sk_shares[0].clone(), pk.clone());

    let plaintext = Plaintext::from_u64(42);
    let ct = fhe.encrypt(&plaintext).unwrap();
    let decrypted = fhe.decrypt(&ct).unwrap();
    assert_eq!(decrypted.value, plaintext.value);
}

#[test]
fn test_hybrid_computation() {
    use osmiridium_fhe::{HybridComputation, HybridConfig, HybridMode};

    let config = HybridConfig::default();
    let computation = HybridComputation::new(config, None);

    let mode = computation.select_mode(10, false);
    assert_eq!(mode, HybridMode::Fhe); // Depth 10 > threshold 5

    let mode = computation.select_mode(3, true);
    assert_eq!(mode, HybridMode::Spdz); // Requires interaction

    let mode = computation.select_mode(3, false);
    assert_eq!(mode, HybridMode::Fhe); // Low depth, no interaction
}

#[test]
fn test_offline_phase_triple_generation() {
    use osmiridium_protocol::offline::PreprocessingConfig;

    let config = PreprocessingConfig {
        num_parties: 3,
        num_triples: 10,
        num_random_shares: 10,
        ..Default::default()
    };

    let offline = OfflinePhase::new(config, 0);
    let alpha = Scalar::from_u64(123);
    let alpha_share = alpha; // Single-party simulation

    let triples = offline.generate_triples(alpha, alpha_share, 0, 5).unwrap();
    assert_eq!(triples.len(), 5);

    for triple in &triples {
        assert_eq!(triple.a_shares.len(), 1);
        assert_eq!(triple.b_shares.len(), 1);
        assert_eq!(triple.c_shares.len(), 1);
    }
}

#[test]
fn test_offline_phase_random_shares() {
    use osmiridium_protocol::offline::PreprocessingConfig;

    let config = PreprocessingConfig {
        num_parties: 3,
        num_triples: 10,
        num_random_shares: 10,
        ..Default::default()
    };

    let offline = OfflinePhase::new(config, 0);
    let alpha = Scalar::from_u64(123);
    let alpha_share = alpha;

    let shares = offline
        .generate_random_shares(alpha, alpha_share, 0, 5)
        .unwrap();
    assert_eq!(shares.len(), 5);
}

#[test]
fn test_beaver_triple_verification() {
    use osmiridium_protocol::offline::PreprocessingConfig;

    let config = PreprocessingConfig {
        num_parties: 3,
        num_triples: 10,
        num_random_shares: 10,
        ..Default::default()
    };

    let offline = OfflinePhase::new(config, 0);
    let alpha = Scalar::from_u64(123);
    let alpha_share = alpha;

    let triples = offline.generate_triples(alpha, alpha_share, 0, 5).unwrap();

    for triple in &triples {
        let result = triple.verify();
        assert!(result.is_ok());
    }
}

#[test]
fn test_coordinator_session_management() {
    use osmiridium_coordinator::{Coordinator, Participant, ParticipantRole};
    use osmiridium_protocol::ArithmeticCircuit;

    let mut coordinator = Coordinator::new();

    let circuit = ArithmeticCircuit::new();
    let policy = osmiridium_coordinator::policy::SessionPolicy::new(1, "test".to_string());

    let session_id = coordinator
        .create_session("test_session".to_string(), circuit, policy)
        .unwrap();

    let participant = Participant {
        party_id: 0,
        name: "party0".to_string(),
        endpoint: "localhost:8080".to_string(),
        role: ParticipantRole::DataProvider,
        joined_at: chrono::Utc::now(),
    };

    coordinator
        .add_participant(session_id, participant)
        .unwrap();

    let status = coordinator.get_session_status(session_id).unwrap();
    assert_eq!(
        status,
        osmiridium_coordinator::session::SessionStatus::Configured
    );
}

#[test]
fn test_policy_engine_access() {
    use osmiridium_coordinator::policy::{PolicyEngine, SessionPolicy};
    use osmiridium_coordinator::{Participant, ParticipantRole};

    let policy = SessionPolicy::default();
    let engine = PolicyEngine::new();

    let participant = Participant {
        party_id: 0,
        name: "test_party".to_string(),
        endpoint: "localhost:8080".to_string(),
        role: ParticipantRole::DataProvider,
        joined_at: chrono::Utc::now(),
    };

    let result = engine.check_access(&policy, &participant).unwrap();
    assert!(result);
}
