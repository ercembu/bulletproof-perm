#![allow(non_snake_case)]

extern crate alloc;

use alloc::borrow::Borrow;
use alloc::vec::Vec;

use core::iter;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::{VartimeMultiscalarMul, MultiscalarMul};
use merlin::Transcript;
use rand::prelude::*;
use bulletproofs::{BulletproofGens, BulletproofGensShare, PedersenGens};
use bulletproofs::ProofError;


#[derive(Clone, Debug)]
pub struct ArithmeticCircuitProof {
    L_vec: Vec<Scalar>
}

impl ArithmeticCircuitProof {
    /// Create Permutation Proof Based on Mr. Ke's arithmetic circuits

    pub fn create(
        transcript: &mut Transcript,
        G_factors: &[Scalar],
        H_factors: &[Scalar],
        mut G_vec: Vec<RistrettoPoint>,
        mut H_vec: Vec<RistrettoPoint>,
        mut W_L: Vec<Vec<Scalar>>,
        mut W_R: Vec<Vec<Scalar>>,
        mut W_O: Vec<Vec<Scalar>>,
        mut W_V: Vec<Vec<Scalar>>,
        mut c_vec: Vec<Scalar>,
        mut a_L_vec: Vec<Scalar>,
        mut a_R_vec: Vec<Scalar>,
        mut a_O_vec: Vec<Scalar>,
        mut gamma: Vec<Scalar>

    ) -> ArithmeticCircuitProof {
        /// temporary resolution while debugging
        let mut L_vec = Vec::with_capacity(5);

        let mut G = &mut G_vec[..];
        let mut H = &mut H_vec[..];
        let mut c = &mut c_vec[..];
        let mut a_L = &mut a_L_vec[..];
        let mut a_R = &mut a_R_vec[..];
        let mut a_O = &mut a_O_vec[..];

        let mut n = G.len();

        assert_eq!(H.len(), n);
        assert_eq!(W_L[0].len(), n);
        assert_eq!(W_R[0].len(), n);
        assert_eq!(W_O[0].len(), n);
        assert_eq!(a_L.len(), n);
        assert_eq!(a_R.len(), n);
        assert_eq!(a_O.len(), n);

        let mut m = gamma.len();

        assert_eq!(W_V[0].len(), m);

        let Q = W_L.len();

        assert_eq!(W_R.len(), Q);
        assert_eq!(W_L.len(), Q);
        assert_eq!(W_O.len(), Q);
        assert_eq!(W_V.len(), Q);

        let mut rng = rand::thread_rng();

        let alpha = Scalar::random(&mut rng);
        let beta = Scalar::random(&mut rng);
        let ro = Scalar::random(&mut rng);

        let A_I = RistrettoPoint::vartime_multiscalar_mul(
                                        iter::once(alpha)
                                            .chain(a_L_vec.into_iter())
                                            .chain(a_R_vec.into_iter()),
                                        iter::once(h)
                                            .chain(G_vec.iter())
                                            .chain(H_vec.iter())
        );

        ArithmeticCircuitProof{
            L_vec: L_vec,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_first(n: usize, m: usize) {
        let mut rng = rand::thread_rng();

        let bp_gens = BulletproofGens::new(n,1);
        let Q = n / 2;

        let G: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let H: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();

        let pedersen_gens = PedersenGens::default();
        let g = pedersen_gens.B;
        let h = pedersen_gens.B_blinding;

        let w_r: Vec<Vec<Scalar>> = vec![vec![Scalar(1); Q]; n];
        let w_l: Vec<Vec<Scalar>> = vec![vec![Scalar(1); Q]; n];
        let w_o: Vec<Vec<Scalar>> = vec![vec![Scalar(1); Q]; n];

        let w_v: Vec<Vec<Scalar>> = vec![vec![Scalar(1); Q]; m];

        let c: Vec<Scalar> = vec![Scalar(1); Q];

        let a_l: Vec<Scalar> = vec![Scalar(1); n];
        let a_r: Vec<Scalar> = vec![Scalar(1); n];
        let a_o: Vec<Scalar> = vec![Scalar(1); n];

        let gamma: Vec<Scalar> = vec![Scalar(1); m];
    }
}
