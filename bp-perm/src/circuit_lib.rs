
pub mod ACProof {
    extern crate alloc;

    use alloc::borrow::Borrow;
    use alloc::vec::Vec;

    use core::iter;
    use std::collections::HashMap;
    use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek_ng::traits::{VartimeMultiscalarMul, MultiscalarMul};
    use curve25519_dalek_ng::scalar::Scalar;
    use merlin::Transcript;
    use rand::prelude::*;
    use bulletproofs::{BulletproofGens, BulletproofGensShare, PedersenGens};
    use bulletproofs::ProofError;

    use crate::transcript_protocol::TranscriptProtocol;
    use crate::util::{*};
    use crate::poly::{*};
    
    #[derive(Clone, Debug, Default)]
    pub struct ACEssentials {
        pub g_base: RistrettoPoint,
        pub h_base: RistrettoPoint,
        pub G_factors: Vec<Scalar>,
        pub H_factors: Vec<Scalar>,
        pub G_vec: Vec<RistrettoPoint>,
        pub H_vec: Vec<RistrettoPoint>,
        pub W_L: Vec<Vec<Scalar>>,
        pub W_R: Vec<Vec<Scalar>>,
        pub W_O: Vec<Vec<Scalar>>,
        pub W_V: Vec<Vec<Scalar>>,
        pub c_vec: Vec<Scalar>,
        pub n: usize,
        pub Q: usize,
        pub m: usize,
    }

    #[derive(Clone, Debug, Default)]
    pub struct ACProver {
        pub a_L: Vec<Scalar>,
        pub a_R: Vec<Scalar>,
        pub a_O: Vec<Scalar>,
        pub gamma: Vec<Scalar>,
        pub scalar_map: HashMap<String, Scalar>,
        pub point_map: HashMap<String, RistrettoPoint>,
            
    }

    #[derive(Clone, Debug, Default)]
    pub struct ArithmeticCircuitProof {
        core: ACEssentials,
        prover_: ACProver,
    }

    impl ArithmeticCircuitProof {

        pub fn create(
            trans: &mut Transcript,
            core: ACEssentials,
            prover: ACProver

        ) -> ArithmeticCircuitProof {

            //let V = &core.V_vec[..];
            let G = &core.G_vec[..];
            let H = &core.H_vec[..];
            let c = &core.c_vec[..];
            let a_L = &prover.a_L[..];
            let a_R = &prover.a_R[..];
            let a_O = &prover.a_O[..];

            let n = G.len();

            assert_eq!(H.len(), n);
            assert_eq!(core.W_L.len(), n);
            assert_eq!(core.W_R.len(), n);
            assert_eq!(core.W_O.len(), n);
            assert_eq!(a_L.len(), n);
            assert_eq!(a_R.len(), n);
            assert_eq!(a_O.len(), n);

            let m = prover.gamma.len();

            assert_eq!(core.W_V.len(), m);

            let Q = core.W_L[0].len();

            assert_eq!(core.W_R[0].len(), Q);
            assert_eq!(core.W_L[0].len(), Q);
            assert_eq!(core.W_O[0].len(), Q);
            assert_eq!(core.W_V[0].len(), Q);

            let mut rng = rand::thread_rng();
            let mut rng_2 = rand::thread_rng();

            trans.arithmetic_domain_sep(n as u64);

            let alpha = Scalar::random(&mut rng);
            let beta = Scalar::random(&mut rng);
            let ro = Scalar::random(&mut rng);


            //Commitments to inputs and outputs
            let A_I = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(alpha)
                    .chain(a_L.into_iter()
                                    .zip(core.G_factors.iter())
                                    .map(|(a_L_i, g)| &*a_L_i * g)
                    )
                    .chain(a_R.into_iter()
                                    .zip(core.H_factors.iter())
                                    .map(|(a_R_i, h)| &*a_R_i * h)
                    ),
                iter::once(core.h_base) 
                    .chain(G.into_iter().map(|g| *g))
                    .chain(H.into_iter().map(|h| *h))
            )
            .compress();

            let A_O = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(beta)
                    .chain(a_O.into_iter()
                                    .zip(core.G_factors.iter())
                                    .map(|(a_O_i, g)| &*a_O_i * g)
                    ),
                iter::once(core.h_base)
                    .chain(G.into_iter().map(|g| *g))
            )
            .compress();

            //Blinding vectors
            let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng_2)).collect();

            let S = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(ro)
                    .chain(s_l.iter()
                                .zip(core.G_factors.iter())
                                .map(|(s_l_i, g)| s_l_i * g)
                    )
                    .chain(s_r.iter()
                                .zip(core.H_factors.iter())
                                .map(|(s_r_i, h)| s_r_i * h)
                    ),
                iter::once(core.h_base)
                    .chain(G.into_iter().map(|g| *g))
                    .chain(H.into_iter().map(|h| *h))
            ).compress();
            ///P -> V: A_I, A_O, S
            trans.append_point(b"A_I", &A_I);
            trans.append_point(b"A_O", &A_O);
            trans.append_point(b"S", &S);

            ArithmeticCircuitProof{core, prover_: prover}
            
        }

        pub fn store_point(
            &mut self,
            label: &str,
            point: RistrettoPoint
        ) {
            self.prover_.point_map.insert(String::from(label), point);
        }
        pub fn store_scalar(
            &mut self,
            label: &str,
            scalar: Scalar
        ) {
            self.prover_.scalar_map.insert(String::from(label), scalar);
        }

        pub fn get_scalar(
            &mut self,
            label: &str,
        ) -> &Scalar {
            self.prover_.scalar_map.get(&String::from(label)).unwrap()
        }

        pub fn get_point(
            &mut self,
            label: &str
        ) -> &RistrettoPoint {
            self.prover_.point_map.get(&String::from(label)).unwrap()
        }

        pub fn challenge_wit_and_const(
            &self, 
            trans: &mut Transcript
        ) -> (Scalar, Scalar) {
            (trans.challenge_scalar(b"y"), trans.challenge_scalar(b"z"))
        }

        pub fn compute_per_challenges(
            &mut self,
            y: &Scalar, 
            z: &Scalar
        ) -> (Vec<Scalar>, Vec<Scalar>, Scalar){
            let n = self.core.G_vec.len();
            let m = self.prover_.gamma.len();
            let Q = self.core.W_L[0].len();
                
            self.core.n = n;
            self.core.m = m;
            self.core.Q = Q;

            let mut y_iter = exp_iter(y);
            let y_n : Vec<Scalar> = (0..self.core.n)
                                    .map(|_| y_iter.next().unwrap())
                                    .collect();
            let y_n_inv :Vec<Scalar> = y_n.iter()
                                            .map(|k| k.invert())
                                            .collect();

            let mut z_iter = exp_iter(z);
            let z_q : Vec<Scalar> = (1..=self.core.Q).map(|_| z_iter.next()
                                            .unwrap())
                                            .collect();



            ///left of inner product
            let z_W_R = vm_mult(&z_q, &self.core.W_R);
            let l_in = hadamard_V(&y_n_inv, &z_W_R);

            ///right of inner product
            let z_W_L = vm_mult(&z_q, &self.core.W_L);

            let sigma_y_z = inner_product(&l_in, &z_W_L);

            //TODO: Create a dump for prover for storage and quick access

            (y_n, z_q, sigma_y_z)
        }

        pub fn commit_Ts(
                &mut self, 
                y_n: &Vec<Scalar>, 
                z_q: &Vec<Scalar>, 
                sigma_y_z: &Scalar
        ) -> Vec<CompressedRistretto> {
            ///P computes:
            ///L(X)
            /*
            let mut l_x: VecPoly3 = VecPoly3::zero(n);
            l_x.1 = self.prover_.a_L.into_iter()
                .zip(l_in.iter())
                .map(|(k, l)| *k + l)
                .collect();
            l_x.2 = self.prover_.a_O.into_iter().map(|k| *k).collect();
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

            Vector::from([T_1, T_3, T_4, T_5, T_6])
            */
            Vec::new()
        }
        
    }
}
