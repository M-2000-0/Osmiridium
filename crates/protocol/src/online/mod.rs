//! Online phase of the SPDZ protocol.
//!
//! Evaluates arithmetic circuits on authenticated secret shares.
//! Additions are local; multiplications use Beaver triples.

use crate::circuit::{ArithmeticCircuit, Gate, WireId};
use crate::crypto::field::Scalar;
use crate::crypto::mac::{AuthenticatedShare, MacShare, ShareBundle};
use crate::offline::PreprocessingMaterial;
use crate::{ProtocolError, ProtocolResult};
use ark_std::{collections::BTreeMap, vec::Vec};
use serde::{Deserialize, Serialize};

/// The state of a party during online phase evaluation.
#[derive(Clone, Debug)]
pub struct PartyState {
    pub party_id: usize,
    /// Full MAC key (alpha), used to compute MACs
    pub alpha: Scalar,
    /// This party's MAC key share (alpha_i)
    pub alpha_share: Scalar,
    /// Wire values (authenticated shares) for each wire
    wires: BTreeMap<WireId, AuthenticatedShare>,
    /// Number of multiplication triples consumed
    triples_used: usize,
    /// Number of random shares consumed
    random_used: usize,
}

impl PartyState {
    pub fn new(party_id: usize, alpha: Scalar, alpha_share: Scalar) -> Self {
        Self {
            party_id,
            alpha,
            alpha_share,
            wires: BTreeMap::new(),
            triples_used: 0,
            random_used: 0,
        }
    }

    /// Set a wire value (for input gates).
    pub fn set_input(&mut self, wire: WireId, share: AuthenticatedShare) {
        self.wires.insert(wire, share);
    }

    /// Get a wire value.
    pub fn get_wire(&self, wire: WireId) -> Option<&AuthenticatedShare> {
        self.wires.get(&wire)
    }

    /// Number of triples consumed so far.
    pub fn triples_used(&self) -> usize {
        self.triples_used
    }

    /// Number of random shares consumed so far.
    pub fn random_used(&self) -> usize {
        self.random_used
    }

    pub fn mark_triple_used(&mut self) {
        self.triples_used += 1;
    }

    pub fn mark_random_used(&mut self) {
        self.random_used += 1;
    }

    /// Get a reference to all wire values.
    pub fn wires(&self) -> &BTreeMap<WireId, AuthenticatedShare> {
        &self.wires
    }

    /// Get all output wire values (shares).
    pub fn output_shares(&self) -> Vec<&AuthenticatedShare> {
        self.wires.values().collect()
    }
}

/// The result of an online phase computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Final wire values (for output wires)
    pub outputs: BTreeMap<WireId, Scalar>,
    /// Number of gates evaluated
    pub gates_evaluated: usize,
    /// Whether verification passed
    pub verified: bool,
}

/// Online phase orchestrator.
pub struct OnlinePhase {
    config: OnlineConfig,
}

/// Configuration for the online phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnlineConfig {
    /// Number of parties
    pub num_parties: usize,
    /// Number of bits of security
    pub security_param: usize,
    /// Whether to perform MAC checks at the end
    pub verify_macs: bool,
}

impl Default for OnlineConfig {
    fn default() -> Self {
        Self {
            num_parties: 3,
            security_param: 128,
            verify_macs: true,
        }
    }
}

impl OnlinePhase {
    pub fn new(config: OnlineConfig) -> Self {
        Self { config }
    }

    /// Evaluate a circuit on a single party's local shares.
    /// This computes locally; the result is a wire value (share + MAC).
    /// Multiplication gates require Beaver triples from preprocessing.
    pub fn evaluate_circuit(
        &self,
        circuit: &ArithmeticCircuit,
        state: &mut PartyState,
        preprocessing: &PreprocessingMaterial,
    ) -> ProtocolResult<()> {
        for (gate_idx, gate) in circuit.gates().iter().enumerate() {
            let wire_id: WireId = gate_idx;

            match gate {
                Gate::Input { party_id: _, value } => {
                    // In simulation mode, create authenticated share from the provided value.
                    // In production, inputs would be provided via a separate input-sharing protocol.
                    let share = AuthenticatedShare::authenticate(
                        *value,
                        state.alpha,
                        state.alpha_share,
                        state.party_id,
                    );
                    state.wires.insert(wire_id, share);
                }

                Gate::Const { value } => {
                    // Create an authenticated share of the constant
                    let share = AuthenticatedShare::authenticate(
                        *value,
                        state.alpha,
                        state.alpha_share,
                        state.party_id,
                    );
                    state.wires.insert(wire_id, share);
                }

                Gate::Add { left, right } => {
                    // Addition is local: just add the shares
                    let left_share = state
                        .get_wire(*left)
                        .ok_or_else(|| ProtocolError::Online(format!("Wire {} not found", left)))?;
                    let right_share = state.get_wire(*right).ok_or_else(|| {
                        ProtocolError::Online(format!("Wire {} not found", right))
                    })?;

                    if left_share.party_id != right_share.party_id {
                        return Err(ProtocolError::Online(
                            "Party IDs for addition don't match".to_string(),
                        ));
                    }

                    let result = Self::local_add(left_share, right_share);
                    state.wires.insert(wire_id, result);
                }

                Gate::Sub { left, right } => {
                    let left_share = state
                        .get_wire(*left)
                        .ok_or_else(|| ProtocolError::Online(format!("Wire {} not found", left)))?;
                    let right_share = state.get_wire(*right).ok_or_else(|| {
                        ProtocolError::Online(format!("Wire {} not found", right))
                    })?;

                    let result = Self::local_sub(left_share, right_share);
                    state.wires.insert(wire_id, result);
                }

                Gate::ScalarMul { input, scalar } => {
                    let input_share = state.get_wire(*input).ok_or_else(|| {
                        ProtocolError::Online(format!("Wire {} not found", input))
                    })?;

                    let result = Self::local_scalar_mul(input_share, *scalar);
                    state.wires.insert(wire_id, result);
                }

                Gate::Mul { left, right } => {
                    // Multiplication requires a Beaver triple
                    let triple_idx = state.triples_used;
                    if triple_idx >= preprocessing.num_triples() {
                        return Err(ProtocolError::Online(format!(
                            "Not enough Beaver triples: need {}, have {}",
                            triple_idx + 1,
                            preprocessing.num_triples()
                        )));
                    }

                    let triple = &preprocessing.triples[triple_idx];
                    let left_share = state
                        .get_wire(*left)
                        .ok_or_else(|| ProtocolError::Online(format!("Wire {} not found", left)))?;
                    let right_share = state.get_wire(*right).ok_or_else(|| {
                        ProtocolError::Online(format!("Wire {} not found", right))
                    })?;

                    // Beaver multiplication:
                    // 1. Open (a - x) and (b - y) — in real protocol, this requires interaction
                    // 2. Compute z = c + (a - x)*b + (b - y)*a + (a - x)*(b - y)
                    //
                    // For this single-party simulation, we use the triple's shares directly
                    let a_share = triple
                        .a_shares
                        .get(state.party_id)
                        .or_else(|| triple.a_shares.first())
                        .ok_or_else(|| {
                            ProtocolError::Online("No triple share available".to_string())
                        })?;
                    let b_share = triple
                        .b_shares
                        .get(state.party_id)
                        .or_else(|| triple.b_shares.first())
                        .ok_or_else(|| {
                            ProtocolError::Online("No triple share available".to_string())
                        })?;
                    let c_share = triple
                        .c_shares
                        .get(state.party_id)
                        .or_else(|| triple.c_shares.first())
                        .ok_or_else(|| {
                            ProtocolError::Online("No triple share available".to_string())
                        })?;

                    let result =
                        Self::beaver_multiply(left_share, right_share, a_share, b_share, c_share)?;

                    state.wires.insert(wire_id, result);
                    state.mark_triple_used();
                }

                Gate::Neg { input } => {
                    let input_share = state.get_wire(*input).ok_or_else(|| {
                        ProtocolError::Online(format!("Wire {} not found", input))
                    })?;
                    let result = Self::local_neg(input_share);
                    state.wires.insert(wire_id, result);
                }

                Gate::Output { input, parties: _ } => {
                    // Output gate: value should be revealed via reconstruction
                    let input_share = state.get_wire(*input).ok_or_else(|| {
                        ProtocolError::Online(format!("Wire {} not found", input))
                    })?;
                    state.wires.insert(wire_id, *input_share);
                }

                Gate::Equal { .. } | Gate::GreaterThan { .. } => {
                    return Err(ProtocolError::Online(
                        "Comparison gates not implemented in basic online phase".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Local addition of two authenticated shares.
    fn local_add(a: &AuthenticatedShare, b: &AuthenticatedShare) -> AuthenticatedShare {
        let share = a.share + b.share;
        let mac = a.mac.mac + b.mac.mac;
        let key_share = a.mac.key_share + b.mac.key_share;

        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    /// Local subtraction of two authenticated shares.
    fn local_sub(a: &AuthenticatedShare, b: &AuthenticatedShare) -> AuthenticatedShare {
        let share = a.share - b.share;
        let mac = a.mac.mac - b.mac.mac;
        let key_share = a.mac.key_share + b.mac.key_share;

        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    /// Local scalar multiplication.
    fn local_scalar_mul(a: &AuthenticatedShare, scalar: Scalar) -> AuthenticatedShare {
        let share = a.share * scalar;
        let mac = a.mac.mac * scalar;
        let key_share = a.mac.key_share;

        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    /// Local negation.
    fn local_neg(a: &AuthenticatedShare) -> AuthenticatedShare {
        let share = a.share.negate();
        let mac = a.mac.mac.negate();
        let key_share = a.mac.key_share;

        AuthenticatedShare::new(share, MacShare::new(mac, key_share), a.party_id)
    }

    /// Beaver multiplication protocol.
    ///
    /// Given: <[x]>, <[y]> and <[a]>, <[b]>, <[c]> where c = a*b
    /// Output: <[z]> where z = x*y
    ///
    /// Steps:
    /// 1. Compute <e> = <x> - <a> (local)
    /// 2. Compute <f> = <y> - <b> (local)
    /// 3. Open e and f (requires interaction in real protocol)
    /// 4. Compute <z> = <c> + e*[b] + f*[a] + e*f
    ///
    /// In this single-party simulation, we assume e and f are already opened
    /// (since we have the triple shares, we can compute them locally).
    fn beaver_multiply(
        x: &AuthenticatedShare,
        y: &AuthenticatedShare,
        a: &AuthenticatedShare,
        b: &AuthenticatedShare,
        c: &AuthenticatedShare,
    ) -> ProtocolResult<AuthenticatedShare> {
        // Step 1: Compute e = x - a (locally)
        let e_share = x.share - a.share;
        let e = e_share; // In real protocol, this is opened via MAC check

        // Step 2: Compute f = y - b (locally)
        let f_share = y.share - b.share;
        let f = f_share;

        // Step 4: z = c + e*b + f*a + e*f
        let z_share = c.share + e * b.share + f * a.share + e * f;

        // MAC for z:
        // mac_z = mac_c + e * mac_b + f * mac_a + e * f * alpha_share
        // The e*f*alpha_share term is the MAC of the public value e*f
        let alpha_share = c.mac.key_share;
        let mac_z = c.mac.mac + e * b.mac.mac + f * a.mac.mac + e * f * alpha_share;
        let key_share = alpha_share;

        Ok(AuthenticatedShare::new(
            z_share,
            MacShare::new(mac_z, key_share),
            x.party_id,
        ))
    }

    /// Reconstruct the final output from all parties' shares.
    pub fn reconstruct_output(
        &self,
        all_parties_shares: &[ShareBundle],
        _alpha: Scalar,
    ) -> ProtocolResult<Scalar> {
        if self.config.verify_macs {
            // Verify MACs before reconstruction
            for bundle in all_parties_shares {
                bundle.verify_all()?;
            }
        }

        let mut result = Scalar::zero();
        for bundle in all_parties_shares {
            result += bundle.reconstruct()?;
        }

        Ok(result)
    }

    /// Verify all MACs across all output wires.
    pub fn verify_all_macs(
        &self,
        wire_shares: &[ShareBundle],
        _alpha: Scalar,
    ) -> ProtocolResult<bool> {
        for bundle in wire_shares {
            bundle.verify_all()?;
        }
        Ok(true)
    }
}
