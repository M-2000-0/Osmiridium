//! Distributed SPDZ execution over a network transport.
//!
//! This module runs the SPDZ protocol across multiple parties connected by a
//! [`PartyChannel`]. Unlike the in-process [`SpdzParty`] simulator, every
//! phase exchanges real messages over the transport:
//!
//! - **Key agreement**: parties exchange additive shares of the MAC key and
//!   each reconstructs the full `alpha`.
//! - **Input sharing**: each party distributes authenticated shares of its
//!   input wires to the other parties.
//! - **Online evaluation**: addition/subtraction/scalar ops are local; each
//!   multiplication opens the masked values `e`/`f` over the network.
//! - **Output reconstruction**: parties exchange final wire shares and
//!   reconstruct the plaintext result with MAC verification.
//!
//! All phases are round-based and use [`PartyChannel`] primitives that work
//! uniformly over in-memory or TCP transports.

use crate::circuit::{ArithmeticCircuit, Gate, WireId};
use crate::crypto::field::Scalar;
use crate::crypto::mac::{AuthenticatedShare, MacShare};
use crate::crypto::sharing::SharingScheme;
use crate::offline::{BeaverTriple, PreprocessingMaterial};
use crate::{ProtocolError, ProtocolResult};
use osmiridium_network::channel::PartyChannel;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The MAC key share each party generates locally during key agreement.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct KeyShareMessage {
    share: Scalar,
}

/// A party's share of an opened value (e.g. `e` or `f` during multiplication).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct OpenShareMessage {
    wire: WireId,
    share: Scalar,
}

/// A party's share of an input wire.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct InputShareMessage {
    wire: WireId,
    share: Scalar,
}

/// A party's final output share for an output wire.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct OutputShareMessage {
    wire: WireId,
    share: Scalar,
    mac: Scalar,
}

/// A single distributed SPDZ party.
pub struct DistributedParty {
    channel: PartyChannel,
    party_id: usize,
    num_parties: usize,
    /// Full MAC key, reconstructed after key agreement.
    alpha: Scalar,
    /// This party's share of the MAC key.
    alpha_share: Scalar,
    /// Preprocessing material (Beaver triples).
    preprocessing: PreprocessingMaterial,
}

impl DistributedParty {
    /// Create a new distributed party bound to the given channel.
    pub fn new(channel: PartyChannel) -> Self {
        let party_id = channel.party_id();
        let num_parties = channel.num_parties();
        Self {
            channel,
            party_id,
            num_parties,
            alpha: Scalar::zero(),
            alpha_share: Scalar::zero(),
            preprocessing: PreprocessingMaterial::new(num_parties),
        }
    }

    pub fn party_id(&self) -> usize {
        self.party_id
    }

    pub fn num_parties(&self) -> usize {
        self.num_parties
    }

    /// Phase 1 — key agreement.
    ///
    /// Each party generates a random additive share of the MAC key, broadcasts
    /// it, and sums all received shares to obtain the full `alpha`. The
    /// protocol ensures `sum(alpha_i) == alpha` as required by the MAC scheme.
    pub async fn key_agreement(&mut self) -> ProtocolResult<Scalar> {
        // Use a deterministic PRSS-backed share for reproducibility; in a
        // production deployment this would come from a hardware/HSM RNG.
        let prss = crate::crypto::prss::MacKeyPrss::new(self.party_id, self.num_parties);
        let share = prss
            .generate_key_share(0)
            .map_err(|e| ProtocolError::Offline(format!("key share: {}", e)))?;

        let msg = KeyShareMessage { share };
        let received = self
            .channel
            .all_to_all::<KeyShareMessage, KeyShareMessage>(&msg)
            .await
            .map_err(|e| ProtocolError::Network(e.to_string()))?;

        let mut alpha = share;
        for (_, m) in received {
            alpha += m.share;
        }

        self.alpha = alpha;
        self.alpha_share = share;
        Ok(alpha)
    }

    /// Phase 2 — offline preprocessing.
    ///
    /// Each party generates authenticated Beaver triples locally via PRSS.
    /// Because PRSS is deterministic over a shared seed, all parties derive
    /// correlated shares of the same underlying values.
    pub fn run_offline(&mut self, num_triples: usize) -> ProtocolResult<()> {
        let offline = crate::offline::OfflinePhase::new(
            crate::offline::PreprocessingConfig {
                num_parties: self.num_parties,
                num_triples,
                ..Default::default()
            },
            self.party_id,
        );

        let triples = offline.generate_triples(self.alpha, self.alpha_share, 3000, num_triples)?;
        for triple in triples {
            self.preprocessing.add_triple(triple);
        }

        Ok(())
    }

    /// Phase 3 — input sharing.
    ///
    /// Each party takes ownership of the input wires marked with its
    /// `party_id`, splits each value additively, and sends one share to every
    /// other party. Returns a map of `wire -> authenticated share` that this
    /// party holds, ready for the online phase.
    pub async fn share_inputs(
        &self,
        circuit: &ArithmeticCircuit,
        inputs: &BTreeMap<WireId, Scalar>,
    ) -> ProtocolResult<BTreeMap<WireId, AuthenticatedShare>> {
        let mut my_shares: BTreeMap<WireId, AuthenticatedShare> = BTreeMap::new();

        // For each gate in the circuit:
        for (wire, gate) in circuit.gates().iter().enumerate() {
            let Gate::Input { party_id, value } = gate else {
                continue;
            };

            // Party owning this wire performs the split and distributes shares.
            if *party_id != self.party_id {
                continue;
            }

            let value = inputs.get(&wire).copied().unwrap_or(*value);
            let shares =
                crate::crypto::sharing::AdditiveShare::<Scalar>::split(&value, self.num_parties, 0)
                    .map_err(|e| ProtocolError::ShareComputation(e.to_string()))?;

            for (i, share) in shares.iter().enumerate() {
                let msg = InputShareMessage {
                    wire,
                    share: share.value,
                };
                if i == self.party_id {
                    let auth = AuthenticatedShare::authenticate(
                        share.value,
                        self.alpha,
                        self.alpha_share,
                        self.party_id,
                    );
                    my_shares.insert(wire, auth);
                } else {
                    self.channel
                        .send_msg(i, &msg)
                        .await
                        .map_err(|e| ProtocolError::Network(e.to_string()))?;
                }
            }
        }

        // Collect shares sent to us by the other parties.
        let incoming = self
            .channel
            .recv_all_msg::<InputShareMessage>()
            .await
            .map_err(|e| ProtocolError::Network(e.to_string()))?;
        for (_, msg) in incoming {
            let auth = AuthenticatedShare::authenticate(
                msg.share,
                self.alpha,
                self.alpha_share,
                self.party_id,
            );
            my_shares.insert(msg.wire, auth);
        }

        Ok(my_shares)
    }

    /// Phase 4 — online evaluation with network-opened multiplications.
    ///
    /// Evaluates the circuit on the party's own shares. For every
    /// multiplication gate, parties broadcast their local `e = x - a` and
    /// `f = y - b` shares, reconstruct the public values, and compute the
    /// resulting authenticated share locally.
    pub async fn run_online(
        &self,
        circuit: &ArithmeticCircuit,
        input_shares: BTreeMap<WireId, AuthenticatedShare>,
    ) -> ProtocolResult<BTreeMap<WireId, AuthenticatedShare>> {
        let mut state: BTreeMap<WireId, AuthenticatedShare> = input_shares;
        let mut triples_used = 0;

        for (wire, gate) in circuit.gates().iter().enumerate() {
            match gate {
                Gate::Input { .. } => { /* already in `state` */ }

                Gate::Const { value } => {
                    // A public constant is shared additively: each party holds
                    // value / n so that the sum reconstructs the constant.
                    let n_inv = Scalar::from_u64(self.num_parties as u64)
                        .invert()
                        .map_err(|e| ProtocolError::Offline(format!("invert n: {}", e)))?;
                    let auth = AuthenticatedShare::authenticate(
                        *value * n_inv,
                        self.alpha,
                        self.alpha_share,
                        self.party_id,
                    );
                    state.insert(wire, auth);
                }

                Gate::Add { left, right } => {
                    let a = state
                        .get(left)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", left)))?;
                    let b = state
                        .get(right)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", right)))?;
                    state.insert(wire, Self::local_add(a, b));
                }

                Gate::Sub { left, right } => {
                    let a = state
                        .get(left)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", left)))?;
                    let b = state
                        .get(right)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", right)))?;
                    state.insert(wire, Self::local_sub(a, b));
                }

                Gate::ScalarMul { input, scalar } => {
                    let a = state
                        .get(input)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", input)))?;
                    state.insert(wire, Self::local_scalar_mul(a, *scalar));
                }

                Gate::Neg { input } => {
                    let a = state
                        .get(input)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", input)))?;
                    state.insert(wire, Self::local_neg(a));
                }

                Gate::Mul { left, right } => {
                    let triple = self
                        .preprocessing
                        .triples
                        .get(triples_used)
                        .ok_or_else(|| {
                            ProtocolError::Online(format!(
                                "no triple available for mul at wire {}",
                                wire
                            ))
                        })?;
                    triples_used += 1;

                    let x = state
                        .get(left)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", left)))?;
                    let y = state
                        .get(right)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", right)))?;

                    let result = self.beaver_multiply_distributed(wire, x, y, triple).await?;
                    state.insert(wire, result);
                }

                Gate::Output { input, .. } => {
                    let a = state
                        .get(input)
                        .copied()
                        .ok_or_else(|| ProtocolError::Online(format!("wire {} missing", input)))?;
                    state.insert(wire, a);
                }

                Gate::Equal { .. } | Gate::GreaterThan { .. } => {
                    return Err(ProtocolError::Online(
                        "comparison gates not implemented in distributed phase".to_string(),
                    ));
                }
            }
        }

        Ok(state)
    }

    /// Distributed Beaver multiplication.
    ///
    /// Parties open `e = x - a` and `f = y - b` by broadcasting their shares,
    /// then compute `z = c + e*b + f*a + e*f` locally with the correct MAC.
    async fn beaver_multiply_distributed(
        &self,
        wire: WireId,
        x: AuthenticatedShare,
        y: AuthenticatedShare,
        triple: &BeaverTriple,
    ) -> ProtocolResult<AuthenticatedShare> {
        let a = triple
            .a_shares
            .first()
            .ok_or_else(|| ProtocolError::Offline("empty triple a_shares".to_string()))?;
        let b = triple
            .b_shares
            .first()
            .ok_or_else(|| ProtocolError::Offline("empty triple b_shares".to_string()))?;
        let c = triple
            .c_shares
            .first()
            .ok_or_else(|| ProtocolError::Offline("empty triple c_shares".to_string()))?;

        // Local shares of e and f.
        let e_share = x.share - a.share;
        let f_share = y.share - b.share;

        // Open e and f over the network.
        let e = self.open_value(wire * 2, e_share).await?;
        let f = self.open_value(wire * 2 + 1, f_share).await?;

        // z = c + e*b + f*a + e*f. The product e*f is a public constant in
        // additive sharing, so each party holds e*f/n of it.
        let n_inv = Scalar::from_u64(self.num_parties as u64)
            .invert()
            .map_err(|err| ProtocolError::Offline(format!("invert n: {}", err)))?;
        let z_share = c.share + e * b.share + f * a.share + e * f * n_inv;

        // mac_z = mac_c + e*mac_b + f*mac_a + e*f*alpha_share
        // (sum over parties: alpha*c + e*alpha*b + f*alpha*a + e*f*alpha = alpha*z)
        let mac_z = c.mac.mac + e * b.mac.mac + f * a.mac.mac + e * f * self.alpha_share;

        Ok(AuthenticatedShare::new(
            z_share,
            MacShare::new(mac_z, self.alpha_share),
            self.party_id,
        ))
    }

    /// Open a shared value: broadcast our share, sum all parties' shares.
    async fn open_value(&self, wire: WireId, share: Scalar) -> ProtocolResult<Scalar> {
        let msg = OpenShareMessage { wire, share };
        let received = self
            .channel
            .all_to_all::<OpenShareMessage, OpenShareMessage>(&msg)
            .await
            .map_err(|e| ProtocolError::Network(e.to_string()))?;

        let mut value = share;
        for (_, m) in received {
            value += m.share;
        }
        Ok(value)
    }

    /// Phase 5 — output reconstruction.
    ///
    /// Parties broadcast the shares of their output wires, reconstruct the
    /// plaintext, and verify the MACs.
    pub async fn reconstruct_outputs(
        &self,
        circuit: &ArithmeticCircuit,
        state: &BTreeMap<WireId, AuthenticatedShare>,
    ) -> ProtocolResult<BTreeMap<WireId, Scalar>> {
        let output_wires: Vec<WireId> = circuit
            .gates()
            .iter()
            .enumerate()
            .filter(|(_, g)| matches!(g, Gate::Output { .. }))
            .map(|(w, _)| w)
            .collect();

        let mut results = BTreeMap::new();
        for wire in output_wires {
            let my_share = state
                .get(&wire)
                .ok_or_else(|| ProtocolError::Reconstruction(format!("wire {} missing", wire)))?;

            // Collect all parties' shares and MACs for this wire.
            let mut shares = vec![my_share.share];
            let mut macs = vec![my_share.mac.mac];
            let received = self
                .channel
                .all_to_all::<OutputShareMessage, OutputShareMessage>(&OutputShareMessage {
                    wire,
                    share: my_share.share,
                    mac: my_share.mac.mac,
                })
                .await
                .map_err(|e| ProtocolError::Network(e.to_string()))?;
            for (_, m) in received {
                shares.push(m.share);
                macs.push(m.mac);
            }

            let mut value = Scalar::zero();
            for s in &shares {
                value += *s;
            }

            // MAC verification: sum(mac_i) == alpha * value
            let mut mac_sum = Scalar::zero();
            for m in &macs {
                mac_sum += *m;
            }
            if mac_sum != self.alpha * value {
                return Err(ProtocolError::MacVerification(wire.to_string()));
            }

            results.insert(wire, value);
        }

        Ok(results)
    }

    fn local_add(a: AuthenticatedShare, b: AuthenticatedShare) -> AuthenticatedShare {
        let share = a.share + b.share;
        let mac = a.mac.mac + b.mac.mac;
        let key_share = a.mac.key_share + b.mac.key_share;
        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    fn local_sub(a: AuthenticatedShare, b: AuthenticatedShare) -> AuthenticatedShare {
        let share = a.share - b.share;
        let mac = a.mac.mac - b.mac.mac;
        let key_share = a.mac.key_share + b.mac.key_share;
        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    fn local_scalar_mul(a: AuthenticatedShare, scalar: Scalar) -> AuthenticatedShare {
        let share = a.share * scalar;
        let mac = a.mac.mac * scalar;
        let key_share = a.mac.key_share;
        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    fn local_neg(a: AuthenticatedShare) -> AuthenticatedShare {
        let share = a.share.negate();
        let mac = a.mac.mac.negate();
        let key_share = a.mac.key_share;
        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    pub fn alpha(&self) -> Scalar {
        self.alpha
    }

    pub fn alpha_share(&self) -> Scalar {
        self.alpha_share
    }

    pub fn preprocessing(&self) -> &PreprocessingMaterial {
        &self.preprocessing
    }
}

/// Convenience: run a full distributed computation over a shared router.
///
/// Returns the reconstructed output per party (all parties compute the same
/// result, so any party's entry can be used).
pub async fn run_distributed(
    circuit: &ArithmeticCircuit,
    inputs: &[BTreeMap<WireId, Scalar>],
    transports: Vec<std::sync::Arc<dyn osmiridium_network::transport::Transport>>,
    num_parties: usize,
) -> ProtocolResult<Vec<BTreeMap<WireId, Scalar>>> {
    if transports.len() != num_parties {
        return Err(ProtocolError::NotEnoughParties(transports.len()));
    }

    let mut handles = Vec::new();
    for party_id in 0..num_parties {
        let circuit = circuit.clone();
        let inputs = inputs[party_id].clone();
        let transport = transports[party_id].clone();
        handles.push(tokio::spawn(async move {
            let channel = PartyChannel::new(transport, party_id, num_parties);
            let mut party = DistributedParty::new(channel);
            party.key_agreement().await?;
            party.run_offline(100)?;
            let shares = party.share_inputs(&circuit, &inputs).await?;
            let state = party.run_online(&circuit, shares).await?;
            party.reconstruct_outputs(&circuit, &state).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(
            handle
                .await
                .map_err(|e| ProtocolError::Network(format!("party task failed: {}", e)))??,
        );
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::field::Scalar;
    use osmiridium_network::channel::PartyChannel;
    use osmiridium_network::in_memory::{InMemoryTransport, MessageRouter};
    use osmiridium_network::transport::SessionConfig;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_router(_num_parties: usize) -> Arc<Mutex<MessageRouter>> {
        Arc::new(Mutex::new(MessageRouter::new()))
    }

    fn make_channel(
        router: Arc<Mutex<MessageRouter>>,
        party_id: usize,
        num_parties: usize,
    ) -> PartyChannel {
        let config = SessionConfig {
            num_parties,
            party_id,
            ..Default::default()
        };
        let transport = Arc::new(InMemoryTransport::new(config, router));
        PartyChannel::new(transport, party_id, num_parties)
    }

    #[tokio::test]
    async fn test_distributed_key_agreement() {
        let router = make_router(3);
        let mut parties: Vec<DistributedParty> = (0..3)
            .map(|i| DistributedParty::new(make_channel(router.clone(), i, 3)))
            .collect();

        let alphas: Vec<Scalar> =
            futures_util::future::join_all(parties.iter_mut().map(|p| p.key_agreement()))
                .await
                .into_iter()
                .map(|r| r.unwrap())
                .collect();

        // All parties must agree on the same alpha.
        assert_eq!(alphas[0], alphas[1]);
        assert_eq!(alphas[1], alphas[2]);

        // Sum of alpha shares equals the full alpha.
        let share_sum = parties
            .iter()
            .map(|p| p.alpha_share())
            .fold(Scalar::zero(), |acc, s| acc + s);
        assert_eq!(share_sum, alphas[0]);
    }

    #[tokio::test]
    async fn test_distributed_full_execution() {
        // Circuit: output((10 + 20) * 3)  => 90
        let mut circuit = ArithmeticCircuit::new();
        let a = circuit.add_gate(Gate::Input {
            party_id: 0,
            value: Scalar::from_u64(10),
        });
        let b = circuit.add_gate(Gate::Input {
            party_id: 1,
            value: Scalar::from_u64(20),
        });
        let c = circuit.add_gate(Gate::Input {
            party_id: 2,
            value: Scalar::from_u64(3),
        });
        let sum = circuit.add(a, b);
        let mul = circuit.mul(sum, c);
        circuit.output(mul, vec![0, 1, 2]);
        circuit.set_num_inputs(0);

        let router = make_router(3);
        let mut parties: Vec<DistributedParty> = (0..3)
            .map(|i| DistributedParty::new(make_channel(router.clone(), i, 3)))
            .collect();

        let _ = futures_util::future::join_all(parties.iter_mut().map(|p| p.key_agreement())).await;

        let _ = futures_util::future::join_all(parties.iter_mut().map(|p| async move {
            p.run_offline(10).unwrap();
        }))
        .await;

        let inputs: Vec<BTreeMap<WireId, Scalar>> = vec![
            BTreeMap::from([(a, Scalar::from_u64(10))]),
            BTreeMap::from([(b, Scalar::from_u64(20))]),
            BTreeMap::from([(c, Scalar::from_u64(3))]),
        ];

        // Input sharing is a barrier: all parties run concurrently.
        let shared: Vec<_> = futures_util::future::join_all(
            parties
                .iter()
                .zip(inputs.iter())
                .map(|(p, inputs)| p.share_inputs(&circuit, inputs)),
        )
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

        // Online phase is a barrier: all parties evaluate concurrently.
        let states: Vec<_> = futures_util::future::join_all(
            parties
                .iter()
                .zip(shared.iter())
                .map(|(p, shares)| p.run_online(&circuit, shares.clone())),
        )
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

        // Output reconstruction is a barrier too.
        let final_results: Vec<_> = futures_util::future::join_all(
            parties
                .iter()
                .zip(states.iter())
                .map(|(p, state)| p.reconstruct_outputs(&circuit, state)),
        )
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

        // Every party reconstructs the same result: 90.
        for results in &final_results {
            for v in results.values() {
                assert_eq!(*v, Scalar::from_u64(90));
            }
        }
    }
}
