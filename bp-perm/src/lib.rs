#![allow(non_snake_case)]

extern crate alloc;

mod util;
use crate::util::{*};

mod poly;
use crate::poly::{*};

mod weights;
use crate::weights::{*};

use alloc::borrow::Borrow;
use alloc::vec::Vec;

use core::iter;
use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::traits::{VartimeMultiscalarMul, MultiscalarMul};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::prelude::*;
use bulletproofs::{BulletproofGens, BulletproofGensShare, PedersenGens};
use bulletproofs::ProofError;





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
        mut V_vec: Vec<RistrettoPoint>,
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

    ) -> Result<(), ProofError> {

        let mut V = &mut V_vec[..];
        let mut G = &mut G_vec[..];
        let mut H = &mut H_vec[..];
        let mut c = &mut c_vec[..];
        let mut a_L = &mut a_L_vec[..];
        let mut a_R = &mut a_R_vec[..];
        let mut a_O = &mut a_O_vec[..];

        let mut n = G.len();

        assert_eq!(H.len(), n);
        assert_eq!(W_L.len(), n);
        assert_eq!(W_R.len(), n);
        assert_eq!(W_O.len(), n);
        assert_eq!(a_L.len(), n);
        assert_eq!(a_R.len(), n);
        assert_eq!(a_O.len(), n);

        let mut m = gamma.len();

        assert_eq!(W_V.len(), m);

        let Q = W_L[0].len();

        assert_eq!(W_R[0].len(), Q);
        assert_eq!(W_L[0].len(), Q);
        assert_eq!(W_O[0].len(), Q);
        assert_eq!(W_V[0].len(), Q);

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


        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
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
        let z_q : Vec<Scalar> = (1..=Q).map(|_| z_iter.next()
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

        //Time for t_2 = d(y,z) + <z_q, c + W_V.v>
        let input_hadamard_product = inner_product(&a_L.to_vec(), &hadamard_V(&a_R.to_vec(), &y_n));
        let t_2 = input_hadamard_product + inner_product(&z_q, &w) + sigma_y_z - inner_product(&a_O.to_vec(), &y_n);


        //P -> V: T_1, T_2, T_3, T_4, T_5, T_6
        let tau_1 = Scalar::random(&mut rng);
        let t_1 = t_x.eval(Scalar::one());
        let T_1: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(t_1)
                .chain(iter::once(tau_1))
            ,iter::once(g)
                .chain(iter::once(h))
        ).compress();
        transcript.append_point(b"T1", &T_1);

        let tau_3 = Scalar::random(&mut rng);
        let three = Scalar::one() + Scalar::one() + Scalar::one();
        let t_3 = t_x.eval(three);
        let T_3: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(t_3)
                .chain(iter::once(tau_3))
            ,iter::once(g)
                .chain(iter::once(h))
        ).compress();
        transcript.append_point(b"T3", &T_3);

        let tau_4 = Scalar::random(&mut rng);
        let four = three + Scalar::one();
        let t_4 = t_x.eval(four);
        let T_4: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(t_4)
                .chain(iter::once(tau_4))
            ,iter::once(g)
                .chain(iter::once(h))
        ).compress();
        transcript.append_point(b"T4", &T_3);

        let tau_5 = Scalar::random(&mut rng);
        let five = four + Scalar::one();
        let t_5 = t_x.eval(five);
        let T_5: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(t_5)
                .chain(iter::once(tau_5))
            ,iter::once(g)
                .chain(iter::once(h))
        ).compress();
        transcript.append_point(b"T5", &T_5);

        let tau_6 = Scalar::random(&mut rng);
        let six = five + Scalar::one();
        let t_6 = t_x.eval(six);
        let T_6: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(t_6)
                .chain(iter::once(tau_6))
            ,iter::once(g)
                .chain(iter::once(h))
        ).compress();
        transcript.append_point(b"T6", &T_6);

        let Ts = [T_1, T_3, T_4, T_5, T_6];

        //V: x <- Z
        let x = transcript.challenge_scalar(b"x");

        //V -> P: x
        //P computes:
        let l = l_x.eval(x);
        let r = r_x.eval(x);
        let t = inner_product(&l, &r);

        let mut tau_x = Scalar::zero();
        tau_x += (tau_1 * x) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
        tau_x += (tau_3 * scalar_exp(&x, 3)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
        tau_x += (tau_4 * scalar_exp(&x, 4)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
        tau_x += (tau_5 * scalar_exp(&x, 5)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
        tau_x += (tau_6 * scalar_exp(&x, 6)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));

        let mu = alpha * x + beta * scalar_exp(&x, 2) + ro * scalar_exp(&x, 3);

        //P -> V: tau_x, mu, t, l, r
        transcript.append_scalar(b"TX", &tau_x);
        transcript.append_scalar(b"mu", &mu);
        ///transcript.append_scalar(b"l", &l);
        ///transcript.append_scalar(b"r", &r);
        transcript.append_scalar(b"t", &t);

        //V computes and checks
        let h_: Vec<RistrettoPoint> = y_n_inv.iter().zip(H.iter()).map(|(y, h)| *h * y).collect();
        //find W_L z_W_L
        //find W_R z_W_R
        //find W_0
        //then the checks
        let weights_L: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
            z_W_L.into_iter(),
            h_.iter()
        );

        let weights_R: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
            l_in.iter(),
            G.iter().map(|g| *g)
        );

        let weights_O: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
            vm_mult(&z_q, &W_O).iter(),
            h_.iter()
        );

        //Check if t holds with sent data
        if t != inner_product(&l, &r) {
            return Err(ProofError::VerificationError);
        } 

        let g_exp = scalar_exp(&x, 2) * (inner_product(&z_q, &c_vec) + sigma_y_z);
        let v_exp = vm_mult(&z_q, &W_V).into_iter().map(|i| scalar_exp(&x, 2) * i);
        let t_exp = iter::once(x).chain((3..=6).map(|i| scalar_exp(&x, i))); 

        let gt_htau_cand: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(g_exp)
                .chain(v_exp)
                .chain(t_exp)
            ,
            iter::once(g)
                .chain(V.into_iter().map(|v| *v))
                .chain(Ts.iter().map(|t| t.decompress().unwrap()))
        );

        let gt_htau: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
            [t, tau_x],
            [g, h]
        );

        //if gt_htau != gt_htau_cand {
        //    return Err(ProofError::VerificationError);
        //}


        let neg_y_n: Vec<Scalar> = y_n.iter().map(|i| -i).collect();
        let P: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
            [x, scalar_exp(&x, 2)].iter()
                .chain(
                    neg_y_n.iter()
                ).chain(
                    [x, x, Scalar::one(), scalar_exp(&x, 3)].iter()
                ),
            [A_I.decompress().unwrap(), A_O.decompress().unwrap()].iter()
                .chain(
                    h_.iter()
                ).chain(
                    [weights_L, weights_R, weights_O, S.decompress().unwrap()].iter()
                )
        );

        let cand_P: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(mu)
                .chain(l.into_iter())
                .chain(r.into_iter()),
            iter::once(h)
                .chain(G.iter().map(|i| *i))
                .chain(H.iter().map(|i| *i))
        );

        //if P != cand_P {
        //    return Err(ProofError::VerificationError);
        //}

        Ok(())




    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn test_first(n: usize, m: usize) {
        let mut rng = rand::thread_rng();

        let bp_gens = BulletproofGens::new(n,1);
        let pd_gen = PedersenGens{
                        B: RistrettoPoint::random(&mut rng),
                        B_blinding: RistrettoPoint::random(&mut rng)
        };

        let Q = 2 * n;
        let k = n / 2; //card count 

        let mut trans = Transcript::new(b"test");

        let G_factors: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let H_factors: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        let mut G: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let mut H: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let v: Vec<Scalar> = create_variables(k);
        let mut V: Vec<RistrettoPoint> = commit_variables(&v, &pd_gen);
        //(0..m).map(|_| RistrettoPoint::random(&mut rng)).collect();

        let pedersen_gens = PedersenGens::default();
        let g = pedersen_gens.B;
        let h = pedersen_gens.B_blinding;

        let w_r: Vec<Vec<Scalar>> = (0..n).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();
        let w_l: Vec<Vec<Scalar>> = (0..n).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();
        let w_o: Vec<Vec<Scalar>> = (0..n).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();

        let w_v: Vec<Vec<Scalar>> = (0..m).map(|_| (0..Q).map(|_| Scalar::random(&mut rng)).collect()).collect();

        let c: Vec<Scalar> = create_constants(Q);

        let a_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let a_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let a_o: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        let gamma: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

        let proof = ArithmeticCircuitProof::create(
                                                &mut trans,
                                                g,
                                                h,
                                                &G_factors,
                                                &H_factors,
                                                V.clone(),
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
        assert!(proof.is_ok());

    }

    #[test]
    fn test_1() {
        test_first(6, 7);
    }
}
