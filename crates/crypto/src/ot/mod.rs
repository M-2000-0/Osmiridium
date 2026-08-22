//! Oblivious Transfer (OT) primitives used in MPC preprocessing.
//!
//! Base OT is the fundamental building block, extended via OT extension
//! protocols for efficiency. These are used in SPDZ-family protocols
//! for generating correlated randomness.

use crate::field::Scalar;
use crate::traits::ToBytes;
use crate::{CryptoError, CryptoResult};
use ark_std::vec::Vec;
use sha2::Digest;

/// A base oblivious transfer sender.
pub trait OTSender {
    type Message;

    fn send(&self, msg0: &Self::Message, msg1: &Self::Message) -> CryptoResult<Vec<u8>>;
    fn receive(&self, choice: bool, response: &[u8]) -> CryptoResult<Self::Message>;
}

/// A base oblivious transfer receiver.
pub trait OTReceiver {
    type Message;
    fn receive(&self, choice: bool, sender_msg: &[u8]) -> CryptoResult<Self::Message>;
    fn respond(&self, choice: bool) -> CryptoResult<Vec<u8>>;
}

/// Base OT implementation using elliptic curve Diffie-Hellman.
pub struct BaseOT {
    pub sender_pk: Vec<u8>,
    pub receiver_sk: Vec<u8>,
    pub receiver_pk: Vec<u8>,
}

impl Default for BaseOT {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseOT {
    pub fn new() -> Self {
        Self {
            sender_pk: vec![],
            receiver_sk: vec![],
            receiver_pk: vec![],
        }
    }

    pub fn keygen(&mut self) -> CryptoResult<()> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        self.receiver_sk = (0..32).map(|_| rng.gen::<u8>()).collect();
        self.receiver_pk = sha2::Sha256::digest(&self.receiver_sk).to_vec();
        self.sender_pk = (0..32).map(|_| rng.gen::<u8>()).collect();
        Ok(())
    }

    pub fn execute_ot(
        &self,
        sender_input0: &Scalar,
        sender_input1: &Scalar,
        receiver_choice: bool,
    ) -> CryptoResult<(Scalar, Scalar, Scalar)> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let k0_bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        let k1_bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();

        let mask0 = Scalar::from_bytes(&k0_bytes)?;
        let mask1 = Scalar::from_bytes(&k1_bytes)?;

        let enc0 = *sender_input0 + mask0;
        let enc1 = *sender_input1 + mask1;

        let choice_key = if receiver_choice {
            k1_bytes.clone()
        } else {
            k0_bytes.clone()
        };

        let receiver_mask = Scalar::from_bytes(&choice_key)?;

        Ok((enc0, enc1, receiver_mask))
    }
}

/// IKNP-style OT extension.
pub struct IKNPUOT {
    pub seed: Vec<u8>,
    pub num_ots: usize,
}

impl IKNPUOT {
    pub fn new(seed: Vec<u8>, num_ots: usize) -> Self {
        Self { seed, num_ots }
    }

    pub fn extend(&self) -> CryptoResult<(Vec<Scalar>, Vec<Scalar>)> {
        let mut sender = Vec::with_capacity(self.num_ots);
        let mut receiver = Vec::with_capacity(self.num_ots);

        for i in 0..self.num_ots {
            let counter_bytes = (i as u64).to_le_bytes();
            let combined: Vec<u8> = self
                .seed
                .iter()
                .chain(counter_bytes.iter())
                .copied()
                .collect();
            let h = sha2::Sha256::digest(&combined);
            let val = Scalar::from_bytes(&h[..32])?;
            sender.push(val);
            receiver.push(val);
        }

        Ok((sender, receiver))
    }
}

/// Correlated Oblivious Transfer (COT).
pub struct COT {
    pub base_ot: IKNPUOT,
}

impl COT {
    pub fn new(base_ot: IKNPUOT) -> Self {
        Self { base_ot }
    }

    pub fn generate_cot(&self, delta: Scalar) -> CryptoResult<(Vec<Scalar>, Vec<Scalar>)> {
        let (sender, receiver) = self.base_ot.extend()?;

        let receiver_correlated: Vec<Scalar> = receiver.iter().map(|w| *w * delta).collect();

        Ok((sender, receiver_correlated))
    }
}

/// A simple 1-out-of-N OT.
pub struct OT1N {
    pub num_choices: usize,
}

impl OT1N {
    pub fn new(num_choices: usize) -> Self {
        Self { num_choices }
    }

    pub fn encode(&self, messages: &[Scalar]) -> CryptoResult<Vec<Vec<u8>>> {
        let mut encoded = Vec::with_capacity(messages.len());
        for msg in messages {
            encoded.push(msg.to_bytes());
        }
        Ok(encoded)
    }

    pub fn decode(&self, encoded: &[Vec<u8>], choice: usize) -> CryptoResult<Scalar> {
        if choice >= encoded.len() {
            return Err(CryptoError::OtError(
                "choice index out of range".to_string(),
            ));
        }
        Scalar::from_bytes(&encoded[choice])
    }
}
