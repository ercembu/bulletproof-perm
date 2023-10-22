
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
    
    pub trait Storable {
        fn store(&self, prover: &mut ACProver, label:&str);
    }

    impl Storable for Scalar {
        fn store(&self, prover: &mut ACProver, label: &str) {
            prover.scalar_map.insert(label.to_string(), self.clone());
        }
    }
    
    impl Storable for RistrettoPoint {
        fn store(&self, prover: &mut ACProver, label: &str) {
            prover.point_map.insert(label.to_string(), self.clone());
        }
    }

    impl Storable for Vec<Scalar> {
        fn store(&self, prover: &mut ACProver, label: &str) {
            prover.vec_scalar_map.insert(label.to_string(), self.clone());
        }
    }

    impl Storable for Vec<RistrettoPoint> {
        fn store(&self, prover: &mut ACProver, label: &str) {
            prover.vec_point_map.insert(label.to_string(), self.clone());
        }
    }

    impl Storable for VecPoly3 {
        fn store(&self, prover: &mut ACProver, label: &str) {
            prover.poly_map.insert(label.to_string(), self.clone());
        }
    }


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
        pub vec_scalar_map: HashMap<String, Vec<Scalar>>,
        pub vec_point_map: HashMap<String, Vec<RistrettoPoint>>,
        pub poly_map: HashMap<String, VecPoly3>,
            
    }

    #[derive(Clone, Debug, Default)]
    pub struct ArithmeticCircuitProof {
        core: ACEssentials,
        prover_: ACProver,
    }

    impl ArithmeticCircuitProof {

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

        pub fn get_vec_scalar(
            &mut self,
            label: &str,
        ) -> &Vec<Scalar> {
            self.prover_.vec_scalar_map.get(&String::from(label)).unwrap()
        }

        pub fn get_vec_point(
            &mut self,
            label: &str,
        ) -> &Vec<RistrettoPoint> {
            self.prover_.vec_point_map.get(&String::from(label)).unwrap()
        }

        pub fn get_vec_poly(
            &mut self,
            label: &str,
        ) -> &VecPoly3 {
            self.prover_.poly_map.get(&String::from(label)).unwrap()
        }

        pub fn challenge_wit_and_const(
            &self, 
            trans: &mut Transcript
        ) -> (Scalar, Scalar) {
            (trans.challenge_scalar(b"y"), trans.challenge_scalar(b"z"))
        }
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
            );

            let A_O = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(beta)
                    .chain(a_O.into_iter()
                                    .zip(core.G_factors.iter())
                                    .map(|(a_O_i, g)| &*a_O_i * g)
                    ),
                iter::once(core.h_base)
                    .chain(G.into_iter().map(|g| *g))
            );

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
            );
            ///P -> V: A_I, A_O, S
            trans.append_point(b"A_I", &A_I.compress());
            trans.append_point(b"A_O", &A_O.compress());
            trans.append_point(b"S", &S.compress());

            ///TODO: think about fixing this, get mut
            let mut mut_prov = prover.clone();

            alpha.store(&mut mut_prov, "alpha");
            beta.store(&mut mut_prov, "beta");
            ro.store(&mut mut_prov, "ro");


            A_I.store(&mut mut_prov, "A_I");
            A_O.store(&mut mut_prov, "A_O");
            S.store(&mut mut_prov, "S");
            s_l.store(&mut mut_prov, "s_l");
            s_r.store(&mut mut_prov, "s_r");



            ArithmeticCircuitProof{core, prover_: mut_prov}
            
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

            y_n_inv.store(&mut self.prover_, "y_n_inv");
            z_W_R.store(&mut self.prover_, "z_w_r");
            l_in.store(&mut self.prover_, "l_in");
            z_W_L.store(&mut self.prover_, "z_w_l");
            y_n.store(&mut self.prover_, "y_n");



            (y_n, z_q, sigma_y_z)
        }

        pub fn commit_Ts(
                &mut self, 
                transcript: &mut Transcript,
                y_n: &Vec<Scalar>, 
                z_q: &Vec<Scalar>, 
                sigma_y_z: &Scalar
        ) -> Vec<CompressedRistretto> {
            ///P computes:
            ///L(X)
            let mut l_x: VecPoly3 = VecPoly3::zero(self.core.n);
            let l_in = self.get_vec_scalar("l_in").clone();
            l_x.1 = self.prover_.a_L.iter()
                .zip(l_in.iter())
                .map(|(k, l)| *k + l)
                .collect();
            l_x.2 = self.prover_.a_O.iter().map(|k| *k).collect();

            let s_l = self.get_vec_scalar("s_l");
            l_x.3 = s_l.iter().map(|k| *k).collect();

            ///R(X)
            let mut r_x: VecPoly3 = VecPoly3::zero(self.core.n);
            r_x.0 = vm_mult(&z_q, &self.core.W_O).iter()
                .zip(y_n.iter())
                .map(|(k,l)| k - l)
                .collect();
            r_x.1 = hadamard_V(&y_n, &self.prover_.a_R.to_vec())
                .iter()
                .zip(
                    vm_mult(&z_q, &self.core.W_L)
                    .iter())
                .map(|(k,l)| k + l).collect();
            let s_r = self.get_vec_scalar("s_r");
            r_x.3 = hadamard_V(&y_n, &s_r)
                .into_iter()
                .map(|k| k).collect();

            ///T(X)
            let t_x = VecPoly3::special_inner_product(&l_x, &r_x);

            let wl = mv_mult(&self.core.W_L, &(self.prover_.a_L.to_vec()));
            let wr = mv_mult(&self.core.W_R, &(self.prover_.a_R.to_vec()));
            let wo = mv_mult(&self.core.W_O, &(self.prover_.a_O.to_vec()));

            let w: Vec<Scalar> = wl.iter()
                .zip(wr.iter())
                .zip(wo.iter())
                .map(|((l, r), o)| l+r+o)
                .collect();

            //Time for t_2 = d(y,z) + <z_q, c + W_V.v>
            let input_hadamard_product = inner_product(&self.prover_.a_L.to_vec(), &hadamard_V(&self.prover_.a_R.to_vec(), &y_n));
            let t_2 = input_hadamard_product + inner_product(&z_q, &w) + sigma_y_z - inner_product(&self.prover_.a_O.to_vec(), &y_n);


            //P -> V: T_1, T_2, T_3, T_4, T_5, T_6
            let mut rng = rand::thread_rng();
            let tau_1 = Scalar::random(&mut rng);
            let t_1 = t_x.eval(Scalar::one());
            let T_1: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(t_1)
                    .chain(iter::once(tau_1))
                ,iter::once(self.core.g_base)
                    .chain(iter::once(self.core.h_base))
            ).compress();
            transcript.append_point(b"T1", &T_1);

            let tau_3 = Scalar::random(&mut rng);
            let three = Scalar::one() + Scalar::one() + Scalar::one();
            let t_3 = t_x.eval(three);
            let T_3: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(t_3)
                    .chain(iter::once(tau_3))
                ,iter::once(self.core.g_base)
                    .chain(iter::once(self.core.h_base))
            ).compress();
            transcript.append_point(b"T3", &T_3);

            let tau_4 = Scalar::random(&mut rng);
            let four = three + Scalar::one();
            let t_4 = t_x.eval(four);
            let T_4: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(t_4)
                    .chain(iter::once(tau_4))
                ,iter::once(self.core.g_base)
                    .chain(iter::once(self.core.h_base))
            ).compress();
            transcript.append_point(b"T4", &T_3);

            let tau_5 = Scalar::random(&mut rng);
            let five = four + Scalar::one();
            let t_5 = t_x.eval(five);
            let T_5: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(t_5)
                    .chain(iter::once(tau_5))
                ,iter::once(self.core.g_base)
                    .chain(iter::once(self.core.h_base))
            ).compress();
            transcript.append_point(b"T5", &T_5);

            let tau_6 = Scalar::random(&mut rng);
            let six = five + Scalar::one();
            let t_6 = t_x.eval(six);
            let T_6: CompressedRistretto = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(t_6)
                    .chain(iter::once(tau_6))
                ,iter::once(self.core.g_base)
                    .chain(iter::once(self.core.h_base))
            ).compress();
            transcript.append_point(b"T6", &T_6);

            let taus: Vec<Scalar> = vec![tau_1, tau_3, tau_4, tau_5, tau_6];

            taus.store(&mut self.prover_, "taus");

            l_x.store(&mut self.prover_, "l_x");
            r_x.store(&mut self.prover_, "r_x");

            Vec::from([T_1, T_3, T_4, T_5, T_6])
        }

        pub fn random_chall_x(
            &self,
            transcript: &mut Transcript,
        ) -> Scalar {
            //V: x <- Z
            transcript.challenge_scalar(b"x")
            //V -> P: x
        }

        pub fn blinding_values(
            &mut self,
            transcript: &mut Transcript,
            x: &Scalar,
            z_q: &Vec<Scalar>,
        ) {
            //P computes:
            let l = self.get_vec_poly("l_x").eval_ref(x);
            let r = self.get_vec_poly("r_x").eval_ref(x);

            let t = inner_product(&l, &r);

            let mut tau_x = Scalar::zero();

            let taus = self.get_vec_scalar("taus").clone();

            let W_V = self.core.W_V.clone();
            let gamma = self.prover_.gamma.clone();
            tau_x += (taus[0] * x) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
            tau_x += (taus[1] * scalar_exp(&x, 3)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
            tau_x += (taus[2] * scalar_exp(&x, 4)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
            tau_x += (taus[3] * scalar_exp(&x, 5)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));
            tau_x += (taus[4] * scalar_exp(&x, 6)) + x * x * inner_product(&z_q, &mv_mult(&W_V, &gamma));

            let alpha = self.get_scalar("alpha").clone();
            let beta = self.get_scalar("beta").clone();
            let ro = self.get_scalar("ro").clone();

            let mu = alpha * x + beta * scalar_exp(&x, 2) + ro * scalar_exp(&x, 3);
            //P -> V: tau_x, mu, t, l, r
            transcript.append_scalar(b"TX", &tau_x);
            transcript.append_scalar(b"mu", &mu);
            transcript.append_vec_scalar(b"l", &l);
            transcript.append_vec_scalar(b"r", &r);
            transcript.append_scalar(b"t", &t);

            mu.store(&mut self.prover_, "mu");

            l.store(&mut self.prover_, "l");
            r.store(&mut self.prover_, "r");
            t.store(&mut self.prover_, "t");
            tau_x.store(&mut self.prover_, "TX");
        }

        pub fn verify(
            &mut self,
            transcript: &mut Transcript,
            z_q: &Vec<Scalar>,
            sigma_y_z: &Scalar,
            x: &Scalar,
            V: &Vec<RistrettoPoint>,
            Ts: &Vec<CompressedRistretto>,

        ) -> Result<(), ProofError> {
            
            let y_n_inv = self.get_vec_scalar("y_n_inv").clone();
            //V computes and checks
            let h_: Vec<RistrettoPoint> = y_n_inv.iter().zip(self.core.H_vec.iter()).map(|(y, h)| *h * y).collect();
            //find W_L z_W_L
            //find W_R z_W_R
            //find W_0
            //then the checks
            //
            let z_W_L = self.get_vec_scalar("z_w_l").clone();
            let weights_L: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
                z_W_L.into_iter(),
                h_.iter()
            );

            let l_in = self.get_vec_scalar("l_in").clone();
            let weights_R: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
                l_in.iter(),
                self.core.G_vec.iter().map(|g| *g)
            );

            let weights_O: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
                vm_mult(z_q, &self.core.W_O).iter(),
                h_.iter()
            );
            //Check if t holds with sent data
            let l = self.get_vec_scalar("l").clone();
            let r = self.get_vec_scalar("r").clone();
            let t = self.get_scalar("t").clone();

            if t != inner_product(&l, &r) {
                return Err(ProofError::VerificationError);
            } 
            let g_exp = scalar_exp(&x, 2) * (inner_product(&z_q, &self.core.c_vec) + sigma_y_z);
            let v_exp = vm_mult(&z_q, &self.core.W_V).into_iter().map(|i| scalar_exp(&x, 2) * i);
            let t_exp = iter::once(*x).chain((3..=6).map(|i| scalar_exp(&x, i))); 

            let gt_htau_cand: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(g_exp)
                    .chain(v_exp)
                    .chain(t_exp)
                ,
                iter::once(self.core.g_base)
                    .chain(V.iter().map(|v| *v))
                    .chain(Ts.iter().map(|t| t.decompress().unwrap()))
            );
            let tau_x = self.get_scalar("TX").clone();
            let gt_htau: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
                [t, tau_x],
                [self.core.g_base, self.core.h_base]
            );

            /*
            if gt_htau != gt_htau_cand {
                //IT ALREADY FAILS HERE TODO
                return Err(ProofError::VerificationError);
            }*/
            let y_n = self.get_vec_scalar("y_n").clone();

            let A_I = self.get_point("A_I").clone();
            let A_O = self.get_point("A_O").clone();
            let S = self.get_point("S").clone();

            let neg_y_n: Vec<Scalar> = y_n.iter().map(|i| -i).collect();
            let P: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
                [x.clone(), scalar_exp(&x, 2)].iter()
                    .chain(
                        neg_y_n.iter()
                    ).chain(
                        [x.clone(), x.clone(), Scalar::one(), scalar_exp(&x, 3)].iter()
                    ),
                [A_I, A_O].iter()
                    .chain(
                        h_.iter()
                    ).chain(
                        [weights_L, weights_R, weights_O, S].iter()
                    )
            );

            let mu = self.get_scalar("mu").clone();
            let cand_P: RistrettoPoint = RistrettoPoint::vartime_multiscalar_mul(
                iter::once(mu)
                    .chain(l.into_iter())
                    .chain(r.into_iter()),
                iter::once(self.core.h_base)
                    .chain(self.core.G_vec.iter().map(|i| *i))
                    .chain(self.core.H_vec.iter().map(|i| *i))
            );

            /*
            if P != cand_P {
                //FAILS HERE TOO TODO
                return Err(ProofError::VerificationError);
            }
            */

            Ok(())
        }
        
    }
}
