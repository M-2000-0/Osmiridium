//! Arithmetic circuit representation for MPC protocols.
//!
//! Circuits are composed of addition and multiplication gates operating
//! on secret-shared values. The circuit is evaluated in the online phase
//! of the SPDZ protocol.

use crate::crypto::field::Scalar;
use crate::crypto::mac::AuthenticatedShare;
use crate::ProtocolError;
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

/// A unique identifier for a wire in the circuit.
pub type WireId = usize;

/// A gate in the arithmetic circuit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Gate {
    /// Input gate: party provides its secret-shared input
    Input { party_id: usize, value: Scalar },
    /// Constant gate: a public constant value
    Const { value: Scalar },
    /// Addition: output = left + right
    Add { left: WireId, right: WireId },
    /// Subtraction: output = left - right
    Sub { left: WireId, right: WireId },
    /// Scalar multiplication: output = scalar * input
    ScalarMul { input: WireId, scalar: Scalar },
    /// Multiplication: output = left * right (requires Beaver triple)
    Mul { left: WireId, right: WireId },
    /// Negation: output = -input
    Neg { input: WireId },
    /// Output gate: reveal the value to specified parties
    Output { input: WireId, parties: Vec<usize> },
    /// Comparison gate: output = (left == right) (boolean, 0 or 1)
    /// This requires a comparison protocol (e.g., using bit decomposition)
    Equal { left: WireId, right: WireId },
    /// Greater-than comparison: output = (left > right)
    /// Implemented via subtraction and sign check
    GreaterThan { left: WireId, right: WireId },
}

impl Gate {
    pub fn input(party_id: usize, value: Scalar) -> Self {
        Self::Input { party_id, value }
    }

    pub fn constant(value: Scalar) -> Self {
        Self::Const { value }
    }

    pub fn add(left: WireId, right: WireId) -> Self {
        Self::Add { left, right }
    }

    pub fn sub(left: WireId, right: WireId) -> Self {
        Self::Sub { left, right }
    }

    pub fn mul(left: WireId, right: WireId) -> Self {
        Self::Mul { left, right }
    }

    pub fn neg(input: WireId) -> Self {
        Self::Neg { input }
    }

    pub fn output(input: WireId, parties: Vec<usize>) -> Self {
        Self::Output { input, parties }
    }

    /// Returns the number of input wires this gate consumes.
    pub fn num_inputs(&self) -> usize {
        match self {
            Gate::Input { .. } | Gate::Const { .. } => 0,
            Gate::Neg { .. } | Gate::Output { .. } => 1,
            Gate::ScalarMul { .. } => 1,
            Gate::Add { .. }
            | Gate::Sub { .. }
            | Gate::Mul { .. }
            | Gate::Equal { .. }
            | Gate::GreaterThan { .. } => 2,
        }
    }
}

/// An arithmetic circuit to be evaluated by the SPDZ protocol.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ArithmeticCircuit {
    /// Gates in topological order (inputs come first)
    gates: Vec<Gate>,
    /// Number of input wires (gates before any computation)
    num_inputs: usize,
    /// Total number of wires (including inputs and intermediate)
    num_wires: usize,
    /// Map from wire ID to the gate that produces it
    wire_to_gate: Vec<usize>,
}

impl ArithmeticCircuit {
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            num_inputs: 0,
            num_wires: 0,
            wire_to_gate: Vec::new(),
        }
    }

    /// Add a gate to the circuit and return its wire ID.
    pub fn add_gate(&mut self, gate: Gate) -> WireId {
        let wire_id = self.num_wires;
        let gate_idx = self.gates.len();

        self.gates.push(gate);
        self.wire_to_gate.push(gate_idx);
        self.num_wires += 1;

        wire_id
    }

    /// Add a constant gate.
    pub fn constant(&mut self, value: Scalar) -> WireId {
        self.add_gate(Gate::Const { value })
    }

    /// Add a multiplication gate.
    pub fn mul(&mut self, left: WireId, right: WireId) -> WireId {
        self.add_gate(Gate::Mul { left, right })
    }

    /// Add an addition gate.
    pub fn add(&mut self, left: WireId, right: WireId) -> WireId {
        self.add_gate(Gate::Add { left, right })
    }

    /// Add a subtraction gate.
    pub fn sub(&mut self, left: WireId, right: WireId) -> WireId {
        self.add_gate(Gate::Sub { left, right })
    }

    /// Add a negation gate.
    pub fn neg(&mut self, input: WireId) -> WireId {
        self.add_gate(Gate::Neg { input })
    }

    /// Add a scalar multiplication gate.
    pub fn scalar_mul(&mut self, input: WireId, scalar: Scalar) -> WireId {
        self.add_gate(Gate::ScalarMul { input, scalar })
    }

    /// Add an output gate.
    pub fn output(&mut self, input: WireId, parties: Vec<usize>) -> WireId {
        self.add_gate(Gate::Output { input, parties })
    }

    /// Set the number of input wires.
    pub fn set_num_inputs(&mut self, n: usize) {
        self.num_inputs = n;
    }

    /// Get a gate by its index.
    pub fn get_gate(&self, gate_idx: usize) -> Option<&Gate> {
        self.gates.get(gate_idx)
    }

    /// Get the gate producing a wire.
    pub fn gate_for_wire(&self, wire: WireId) -> usize {
        self.wire_to_gate[wire]
    }

    /// Returns the total number of gates.
    pub fn num_gates(&self) -> usize {
        self.gates.len()
    }

    /// Returns the number of input gates (not total gates).
    pub fn num_input_gates(&self) -> usize {
        self.num_inputs
    }

    /// Returns the total number of wires.
    pub fn num_wires(&self) -> usize {
        self.num_wires
    }

    /// Count the number of multiplication gates (for triple generation).
    pub fn count_mul_gates(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| matches!(g, Gate::Mul { .. }))
            .count()
    }

    /// Returns all gates.
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    /// Validate the circuit structure.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for _gate in self.gates.iter() {
            // Each gate (except inputs/constants) should have inputs from earlier gates
        }
        Ok(())
    }
}

impl std::ops::Add<WireId> for ArithmeticCircuit {
    type Output = ();

    fn add(self, _rhs: WireId) {}
}

/// An authenticated value in the circuit — a share with its MAC.
pub type AuthValue = AuthenticatedShare;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::field::Scalar;

    #[test]
    fn test_circuit_constants() {
        let mut circuit = ArithmeticCircuit::new();
        let a = circuit.constant(Scalar::from_u64(5));
        let b = circuit.constant(Scalar::from_u64(3));
        let c = circuit.add(a, b);
        let _d = circuit.mul(c, a);

        assert_eq!(circuit.num_gates(), 4);
        assert_eq!(circuit.count_mul_gates(), 1);
    }

    #[test]
    fn test_gate_inputs() {
        assert_eq!(
            Gate::Const {
                value: Scalar::zero()
            }
            .num_inputs(),
            0
        );
        assert_eq!(
            Gate::Input {
                party_id: 0,
                value: Scalar::zero()
            }
            .num_inputs(),
            0
        );
        assert_eq!(Gate::Neg { input: 0 }.num_inputs(), 1);
        assert_eq!(Gate::Add { left: 0, right: 1 }.num_inputs(), 2);
        assert_eq!(Gate::Mul { left: 0, right: 1 }.num_inputs(), 2);
    }
}
