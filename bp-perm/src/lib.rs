#![allow(non_snake_case)]

extern crate alloc;

use alloc::borrow::Borrow;
use alloc::vec::Vec;

use core::iter;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::VartimeMultiscalarMul;
use merlin::Transcript;

mod errors;
mod transcript;

pub use crate::errors::ProofError;
pub use crate::transcript::TranscriptProtocol;

#[derive(Clone, Debug)]
pub struct PermutationProof {
    pub(crate) L_vec: Vec<CompressedRistretto>,
    pub(crate) R_vec: Vec<CompressedRistretto>,
    pub(crate) a: Scalar,
    pub(crate) b: Scalar,
}

impl PermutationProof {
    /// Create Permutation Proof Based on Mr. Ke's arithmetic circuits

    pub fn create(
        transcript: &mut Transcript,
        Q: &RistrettoPoint,
        G_factors: &[Scalar],
        H_factors: &[Scalar],
        mut G_vec: Vec<RistrettoPoint>,
        mut H_vec: Vec<RistrettoPoint>,
        mut a_vec: Vec<Scalar>,
        mut b_vec: Vec<Scalar>,
    ) -> PermutationProof {
        let mut L_vec = Vec::with_capacity(5);
        let mut R_vec = Vec::with_capacity(5);

        PermutationProof{
            L_vec: L_vec,
            R_vec: R_vec,
            a: a_vec[0],
            b: b_vec[0],
        }
    }
}
