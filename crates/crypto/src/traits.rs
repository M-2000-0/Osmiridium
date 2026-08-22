use crate::CryptoResult;
use ark_std::vec::Vec;

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> CryptoResult<Self>;
}

pub trait MpcEncode {
    fn mpc_encode(&self) -> Vec<u8>;
}

pub trait MpcHash {
    fn mpc_hash(&self) -> [u8; 32];
}
