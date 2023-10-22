#![allow(non_snake_case)]

extern crate alloc;

mod util;
use crate::util::{*};

mod poly;
use crate::poly::{*};

mod weights;
use crate::weights::{*};

mod transcript_protocol;
use crate::transcript_protocol::TranscriptProtocol;

mod circuit_lib;
use crate::circuit_lib::ACProof;

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




/*
impl ArithmeticCircuitProof {
    // Create Permutation Proof Based on Mr. Ke's arithmetic circuits

    pub fn left() {

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

        if gt_htau != gt_htau_cand {
            return Err(ProofError::VerificationError);
        }


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

        if P != cand_P {
            return Err(ProofError::VerificationError);
        }

        Ok(())




    }
}
*/

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

        let G_factors: Vec<Scalar> = (0..n).map(|_| Scalar::one()).collect();

        let rand_chal = exp_iter(&Scalar::random(&mut rng));
        let H_factors: Vec<Scalar> = rand_chal.take(n).collect();

        let mut G: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let mut H: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let v: Vec<Scalar> = create_variables(k);
        let mut V: Vec<RistrettoPoint> = commit_variables(&v, &pd_gen);

        let g = pd_gen.B;
        let h = pd_gen.B_blinding;

        let (w_r, w_l, w_o, w_v) = create_weights(k);

        let c: Vec<Scalar> = create_constants(Q);

        let (a_l, a_r, a_o) = create_a(&v);

        let gamma: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

        let ace = ACProof::ACEssentials {
            g_base: g,
            h_base: h,
            G_factors: G_factors,
            H_factors: H_factors,
            G_vec: G.clone(),
            H_vec: H.clone(),
            W_L: w_l.clone(),
            W_R: w_r.clone(),
            W_O: w_o.clone(),
            W_V: w_v.clone(),
            c_vec: c.clone(),
            ..Default::default()
        };

        let prover = ACProof::ACProver {
            a_L: a_l.clone(),
            a_R: a_r.clone(),
            a_O: a_o.clone(),
            gamma: gamma.clone(),
            ..Default::default()
        };

        let mut proof = ACProof::ArithmeticCircuitProof::create(&mut trans, ace.clone(), prover.clone());
        let (y, z) = proof.challenge_wit_and_const(&mut trans);

        let (y_n, z_q, sigma_y_z) = proof.compute_per_challenges(&y, &z);

        let tem = proof.commit_Ts(&mut trans, &y_n, &z_q, &sigma_y_z);

        let XX = proof.random_chall_x(&mut trans);

        proof.blinding_values(&mut trans, &XX, &z_q);

        let ver = proof.verify(&mut trans, &z_q, &sigma_y_z, &XX, &V, &tem);
        assert!(ver.is_ok());

    }

    #[test]
    fn test_1() {
        test_first(6, 7);
    }
}
