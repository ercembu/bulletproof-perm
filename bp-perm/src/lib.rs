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

pub trait TranscriptProtocol {
    fn arithmetic_domain_sep(&mut self, n: u64);

    fn append_scalar(&mut self, label: &'static [u8], scalar:&Scalar);

    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);

    fn validate_and_append_point(&mut self, label: &'static [u8], point: &CompressedRistretto,) 
        -> Result<(), ProofError>;

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn arithmetic_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"acp v1");
        self.append_u64(b"n", n);
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }
    fn validate_and_append_point(
                &mut self,
                label: &'static [u8],
                point: &CompressedRistretto,
            ) -> Result<(), ProofError> {
        use curve25519_dalek_ng::traits::IsIdentity;

        if point.is_identity() {
            Err(ProofError::VerificationError)
        } else {
            Ok(self.append_message(label, point.as_bytes()))
        }
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }


}

#[derive(Clone, Debug)]
pub struct ArithmeticCircuitProof {
    L_vec: Vec<Scalar>
}

impl ArithmeticCircuitProof {
    /// Create Permutation Proof Based on Mr. Ke's arithmetic circuits

    pub fn create(
        transcript: &mut Transcript,
        g: RistrettoPoint,
        h: RistrettoPoint,
        G_factors: &Vec<Scalar>,
        H_factors: &Vec<Scalar>,
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
        let mut rng_2 = rand::thread_rng();

        transcript.arithmetic_domain_sep(n as u64);

        let alpha = Scalar::random(&mut rng);
        let beta = Scalar::random(&mut rng);
        let ro = Scalar::random(&mut rng);


        let A_I = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(alpha)
                .chain(a_L_vec.into_iter()
                                .zip(G_factors.into_iter())
                                .map(|(a_L_i, g)| a_L_i * g)
                )
                .chain(a_R_vec.into_iter()
                                .zip(H_factors.into_iter())
                                .map(|(a_R_i, h)| a_R_i * h)
                ),
            iter::once(h) 
                .chain(G.into_iter().map(|g| *g))
                .chain(H.into_iter().map(|h| *h))
        )
        .compress();

        let A_O = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(beta)
                .chain(a_O_vec.into_iter()
                                .zip(G_factors.into_iter())
                                .map(|(a_O_i, g)| a_O_i * g)
                ),
            iter::once(h)
                .chain(G.into_iter().map(|g| *g))
        )
        .compress();

        let s_l = (0..n).map(|_| Scalar::random(&mut rng));
        let s_r = (0..n).map(|_| Scalar::random(&mut rng_2));

        let S = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(ro)
                .chain(s_l.into_iter()
                            .zip(G_factors.into_iter())
                            .map(|(s_l_i, g)| s_l_i * g)
                )
                .chain(s_r.into_iter()
                            .zip(H_factors.into_iter())
                            .map(|(s_r_i, h)| s_r_i * h)
                ),
            iter::once(h)
                .chain(G.into_iter().map(|g| *g))
                .chain(H.into_iter().map(|h| *h))
        ).compress();
        ///First prover done
        ///P -> V: A_I, A_O, S
        transcript.append_point(b"A_I", &A_I);
        transcript.append_point(b"A_O", &A_O);
        transcript.append_point(b"S", &S);


        let y = Scalar::random(&mut rng);
        let z = Scalar::random(&mut rng);
        ///V -> P: y,z
        transcript.append_scalar(b"y", &y);
        transcript.append_scalar(b"z", &z);

        ///P and V compute:
                
                                

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

        let mut trans = Transcript::new(b"test");

        let G_factors: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let H_factors: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        let mut G: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let mut H: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();

        let pedersen_gens = PedersenGens::default();
        let g = pedersen_gens.B;
        let h = pedersen_gens.B_blinding;

        let w_r: Vec<Vec<Scalar>> = (0..n).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();
        let w_l: Vec<Vec<Scalar>> = (0..n).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();
        let w_o: Vec<Vec<Scalar>> = (0..n).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();

        let w_v: Vec<Vec<Scalar>> = (0..m).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();

        let c: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        let a_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let a_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let a_o: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        let gamma: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        let proof = ArithmeticCircuitProof::create(
                                                &mut trans,
                                                g,
                                                h,
                                                &G_factors,
                                                &H_factors,
                                                G.clone(),
                                                H.clone(),
                                                w_r.clone(),
                                                w_l.clone(),
                                                w_o.clone(),
                                                w_v.clone(),
                                                c.clone(),
                                                a_l.clone(),
                                                a_r.clone(),
                                                a_o.clone(),
                                                gamma.clone()
                                            );

    }
}
