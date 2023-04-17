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

///Structs
pub struct Poly6 {
    pub t1: Scalar,
    pub t2: Scalar,
    pub t3: Scalar,
    pub t4: Scalar,
    pub t5: Scalar,
    pub t6: Scalar,
}

impl Poly6 {
    pub fn eval(&self, x: Scalar) -> Scalar {
        x * (self.t1 + x * (self.t2 + x * (self.t3 + x * (self.t4 + x * (self.t5 + x * self.t6)))))
    }
}


pub struct VecPoly3(
    pub Vec<Scalar>,
    pub Vec<Scalar>,
    pub Vec<Scalar>,
    pub Vec<Scalar>,
);

impl VecPoly3 {
    pub fn zero(n: usize) -> Self {
        VecPoly3(
            vec![Scalar::zero(); n],
            vec![Scalar::zero(); n],
            vec![Scalar::zero(); n],
            vec![Scalar::zero(); n],
        )
    }

    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6 {
        let t1 = inner_product(&lhs.1, &rhs.0);
        let t2 = inner_product(&lhs.1, &rhs.1) + inner_product(&lhs.2, &rhs.0);
        let t3 = inner_product(&lhs.2, &rhs.1) + inner_product(&lhs.3, &rhs.0);
        let t4 = inner_product(&lhs.1, &rhs.3) + inner_product(&lhs.3, &rhs.1);
        let t5 = inner_product(&lhs.2, &rhs.3);
        let t6 = inner_product(&lhs.3, &rhs.3);

        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }

    pub fn eval(&self, x: Scalar) -> Vec<Scalar> {
        let n = self.0.len();
        let mut out = vec![Scalar::zero(); n];
        for i in 0..n {
            out[i] = self.0[i] + x * (self.1[i] + x * (self.2[i] + x * self.3[i]));
        }
        out
    }
}


///Util functions

pub fn hadamard_V(a: &Vec<Scalar>, b: &Vec<Scalar>) -> Vec<Scalar> {
    let a_len = a.len();

    if a_len != b.len() {
        panic!("hadamard_V(a, b): a and b should have same size");
    }

    let mut out: Vec<Scalar> = (0..a.len()).map(|_| Scalar::one()).collect();

    for i in 0..a_len {
        out[i] *= a[i] * b[i];
    }

    out
}

pub fn vm_mult(a: &Vec<Scalar>, b: &Vec<Vec<Scalar>>) -> Vec<Scalar> {
    let a_len = a.len();
    let b_len = b[0].len();

    if a_len != b_len {
        panic!("vm_mult(a,b): a -> 1xm, b -> mxn needs to be");
    }

    let mut out: Vec<Scalar> = (0..a_len).map(|_| Scalar::zero()).collect();
    
    for i in 0..a_len {
        let col: Vec<Scalar> = (0..a_len).map(|j| b[i][j]).collect();
        out[i] += inner_product(&a, &col);
    }

    out
}

pub fn mv_mult(a: &Vec<Vec<Scalar>>, b: &Vec<Scalar>) -> Vec<Scalar> {
    let b_len = b.len();
    let a_len = a.len();

    if a_len != b_len {
        panic!("mv_mult(a,b): a->nxm, b->mx1 needs to be");
    }

    let mut out: Vec<Scalar> = vec![Scalar::zero(); a[0].len()];

    for i in 0..a[0].len() {
        out[i] = inner_product(&(a[i]), b);
    }

    out
}

pub fn lm_mult(a: &[Scalar], b: &Vec<Vec<Scalar>>) -> Vec<Scalar> {
    let m = Vec::from(a);
    vm_mult(&m, b)
}

pub fn exp_iter(x:Scalar) -> ScalarExp {
    let next_exp_x = Scalar::one();
    ScalarExp { x, next_exp_x }
}

pub fn inner_product(a: &Vec<Scalar>, b: &Vec<Scalar>) -> Scalar {
    let mut out = Scalar::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths dont match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out

}

/// Iterator for Scalar exponentiation
pub struct ScalarExp {
    x: Scalar,
    next_exp_x: Scalar,
}

impl Iterator for ScalarExp {
    type Item = Scalar;

    fn next(&mut self) -> Option<Scalar> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}


///Transcript protocol for merlin
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
                .chain(a_L.into_iter()
                                .zip(G_factors.into_iter())
                                .map(|(a_L_i, g)| &*a_L_i * g)
                )
                .chain(a_R.into_iter()
                                .zip(H_factors.into_iter())
                                .map(|(a_R_i, h)| &*a_R_i * h)
                ),
            iter::once(h) 
                .chain(G.into_iter().map(|g| *g))
                .chain(H.into_iter().map(|h| *h))
        )
        .compress();

        let A_O = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(beta)
                .chain(a_O.into_iter()
                                .zip(G_factors.into_iter())
                                .map(|(a_O_i, g)| &*a_O_i * g)
                ),
            iter::once(h)
                .chain(G.into_iter().map(|g| *g))
        )
        .compress();

        let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng_2)).collect();

        let S = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(ro)
                .chain(s_l.iter()
                            .zip(G_factors.into_iter())
                            .map(|(s_l_i, g)| s_l_i * g)
                )
                .chain(s_r.iter()
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


        let mut rng_3 = rand::thread_rng();
        let y = Scalar::random(&mut rng_3);

        let mut rng_4 = rand::thread_rng();
        let z = Scalar::random(&mut rng_4);
        ///V -> P: y,z
        //transcript.append_scalar(b"y", &y);
        //transcript.append_scalar(b"z", &z);

        ///P and V compute:
        //Figure out how to power Scalars, maybe a trait?
        let mut y_iter = exp_iter(y);
        let y_n : Vec<Scalar> = iter::once(
                        Scalar::zero())
                            .chain((0..n-1)
                                .map(|_| y_iter.next().unwrap()))
                                .collect();
        let y_n_inv :Vec<Scalar> = y_n.iter()
                                        .map(|k| k.invert())
                                        .collect();

        let mut z_iter = exp_iter(z);
        let z_q : Vec<Scalar> = (0..Q).map(|_| z_iter.next()
                                        .unwrap())
                                        .collect();



        ///left of inner product
        let z_W_R = vm_mult(&z_q, &W_R);
        let l_in = hadamard_V(&y_n_inv, &z_W_R);

        ///right of inner product
        let z_W_L = vm_mult(&z_q, &W_L);

        let sigma_y_z = inner_product(&l_in, &z_W_L);

        ///P computes:
        ///L(X)
        let mut l_x: VecPoly3 = VecPoly3::zero(n);
        l_x.1 = a_L.into_iter()
            .zip(l_in.iter())
            .map(|(k, l)| *k + l)
            .collect();
        l_x.2 = a_O.into_iter().map(|k| *k).collect();
        l_x.3 = s_l.into_iter().map(|k| k).collect();

        ///R(X)
        let mut r_x: VecPoly3 = VecPoly3::zero(n);
        r_x.0 = vm_mult(&z_q, &W_O).iter()
            .zip(y_n.iter())
            .map(|(k,l)| k - l)
            .collect();
        r_x.1 = hadamard_V(&y_n, &a_R.to_vec())
            .iter()
            .zip(
                vm_mult(&z_q, &W_L)
                .iter())
            .map(|(k,l)| k + l).collect();
        r_x.3 = hadamard_V(&y_n, &s_r)
            .into_iter()
            .map(|k| k).collect();

        ///T(X)
        let t_x = VecPoly3::special_inner_product(&l_x, &r_x);

        let wl = mv_mult(&W_L, &(a_L.to_vec()));
        let wr = mv_mult(&W_R, &(a_R.to_vec()));
        let wo = mv_mult(&W_O, &(a_O.to_vec()));

        let w: Vec<Scalar> = wl.iter()
            .zip(wr.iter())
            .zip(wo.iter())
            .map(|((l, r), o)| l+r+o)
            .collect();

        //Time for t_2



                
                                

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
