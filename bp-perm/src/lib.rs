#![allow(non_snake_case)]

extern crate alloc;

use alloc::borrow::Borrow;
use alloc::vec::Vec;

use core::iter;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand::prelude::*;
use bulletproofs::BulletproofGens;
use bulletproofs::ProofError;


#[derive(Clone, Debug)]
pub struct ArithmeticCircuitProof {
    L_vec: Vec<Scalar>
}

impl ArithmeticCircuitProof {
    /// Create Permutation Proof Based on Mr. Ke's arithmetic circuits

    pub fn create(
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        mut G_vec: Vec<RistrettoPoint>,
        mut H_vec: Vec<RistrettoPoint>,
        mut W_L: Vec<Vec<Scalar>>,
        mut W_R: Vec<Vec<Scalar>>,
        mut W_O: Vec<Vec<Scalar>>,
        mut W_V: Vec<Vec<Scalar>>,
        mut c: Vec<Scalar>,
        mut a_L: Vec<Scalar>,
        mut a_R: Vec<Scalar>,
        mut a_O: Vec<Scalar>,
        mut gamma: Vec<Scalar>

    ) -> ArithmeticCircuitProof {
        let mut rng = rand::thread_rng();
        let mut L_vec = Vec::with_capacity(5);

        ArithmeticCircuitProof{
            L_vec: L_vec,
        }
    }
}
