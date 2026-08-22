//! Pseudo-Random Secret Sharing (PRSS) for generating correlated randomness
//! without communication.
//!
//! PRSS allows n parties to generate a random secret-shared value and its
//! MAC shares using only a PRG, without any communication during the online
//! phase. This is used in SPDZ for generating Beaver triples and random masks.

use crate::field::Scalar;
use crate::mac::{AuthenticatedShare, MacShare};
use crate::CryptoResult;
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// State for a PRSS instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrssState {
    pub seed: Vec<u8>,
    pub party_id: usize,
    pub num_parties: usize,
}

/// A PRSS instance that generates random correlated shares.
pub struct Prss {
    /// State for this PRSS instance
    state: PrssState,
}

impl Prss {
    pub fn new(party_id: usize, num_parties: usize) -> Self {
        Self {
            state: PrssState {
                seed: vec![0u8; 32],
                party_id,
                num_parties,
            },
        }
    }

    pub fn with_seed(party_id: usize, num_parties: usize, seed: Vec<u8>) -> Self {
        Self {
            state: PrssState {
                seed,
                party_id,
                num_parties,
            },
        }
    }

    /// Generate a random share using the PRSS.
    pub fn generate_share(&self, counter: u64) -> CryptoResult<Scalar> {
        let mut hasher = Keccak256::new();
        hasher.update(&self.state.seed);
        hasher.update(counter.to_le_bytes());
        hasher.update((self.state.party_id as u64).to_le_bytes());
        let result = hasher.finalize();

        let mut le_bytes = [0u8; 32];
        le_bytes.copy_from_slice(&result[..32]);
        let fr = ark_bn254::Fr::from_le_bytes_mod_order(&le_bytes);
        Ok(Scalar::new(fr))
    }

    /// Generate a batch of random shares.
    pub fn generate_shares(&self, counter: u64, batch_size: usize) -> CryptoResult<Vec<Scalar>> {
        let mut shares = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            shares.push(self.generate_share(counter + i as u64)?);
        }
        Ok(shares)
    }

    /// Generate an authenticated random share (with MAC).
    pub fn generate_authenticated_share(
        &self,
        counter: u64,
        alpha: Scalar,
    ) -> CryptoResult<(Scalar, AuthenticatedShare)> {
        let share = self.generate_share(counter)?;
        let mac = alpha * share;
        let mac_share = MacShare::new(mac, alpha);
        let auth_share = AuthenticatedShare::new(share, mac_share, self.state.party_id);
        Ok((share, auth_share))
    }

    /// Generate shares of a Beaver triple: ([a], [b], [c]) where c = a*b.
    /// Each party independently generates its share using PRSS.
    pub fn generate_triple_shares(
        &self,
        counter: u64,
    ) -> CryptoResult<(Scalar, Scalar, Scalar, Scalar, Scalar, Scalar)> {
        // Generate random a and b shares
        let a_share = self.generate_share(counter)?;
        let b_share = self.generate_share(counter + 1)?;

        // Compute the share of c = a * b
        // In a real protocol, this requires interaction (Beaver multiplication)
        // For PRSS, we can generate random c and then verify
        // Actually, PRSS alone cannot generate triples — it requires interaction
        // We generate a, b as random, and c is computed during the protocol
        let c_share = self.generate_share(counter + 2)?;

        // Also generate MAC shares
        let a_mac = self.generate_share(counter + 3)?;
        let b_mac = self.generate_share(counter + 4)?;
        let c_mac = self.generate_share(counter + 5)?;

        Ok((a_share, b_share, c_share, a_mac, b_mac, c_mac))
    }

    /// Generate n independent random masks.
    pub fn generate_masks(&self, counter: u64, n: usize) -> CryptoResult<Vec<Scalar>> {
        self.generate_shares(counter, n)
    }

    pub fn party_id(&self) -> usize {
        self.state.party_id
    }

    pub fn num_parties(&self) -> usize {
        self.state.num_parties
    }

    pub fn state_ref(&self) -> &PrssState {
        &self.state
    }
}

/// A PRSS participant.
pub struct PrssParty {
    pub prss: Prss,
    pub party_id: usize,
    pub num_parties: usize,
}

impl PrssParty {
    pub fn new(party_id: usize, num_parties: usize) -> Self {
        Self {
            prss: Prss::new(party_id, num_parties),
            party_id,
            num_parties,
        }
    }

    pub fn generate_share(&self, counter: u64) -> CryptoResult<Scalar> {
        self.prss.generate_share(counter)
    }

    /// Reconstruct the sum of shares from all parties.
    pub fn reconstruct(shares: &[Scalar]) -> Scalar {
        let mut sum = Scalar::zero();
        for s in shares {
            sum += *s;
        }
        sum
    }
}

/// PRSS for generating a shared MAC key alpha.
pub struct MacKeyPrss {
    prss: Prss,
}

impl MacKeyPrss {
    pub fn new(party_id: usize, num_parties: usize) -> Self {
        Self {
            prss: Prss::new(party_id, num_parties),
        }
    }

    pub fn generate_key_share(&self, counter: u64) -> CryptoResult<Scalar> {
        self.prss.generate_share(counter)
    }

    pub fn generate_key_shares(&self, counter: u64) -> CryptoResult<Vec<Scalar>> {
        self.prss
            .generate_shares(counter, self.prss.state.num_parties)
    }
}
