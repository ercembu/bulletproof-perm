#![allow(non_snake_case)]

extern crate alloc;
extern crate sha3;

use alloc::borrow::Borrow;
use alloc::vec::Vec;
use sha3::Sha3_512;
use shuffle::irs::Irs;
use std::convert::TryInto;
use itertools::izip;
use ethnum::{I256};

use core::iter;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use bulletproofs::PedersenGens;
use crate::util;
use crate::util::{print_scalar_vec, print_scalar_mat, format_scalar};
use crate::traits::ReduceScalar;


use shuffle::shuffler::Shuffler;


pub fn create_constants(Q: usize) -> Vec<Scalar> {

    let mut constant_vector: Vec<Scalar> = Vec::new();
    for _ in 0..Q-2 {
        constant_vector.push(Scalar::zero());
    }
    constant_vector.push(-Scalar::one().reduce());
    //constant_vector.push(Scalar::from_bytes_mod_order(m_one.to_le_bytes()));
    constant_vector.push(Scalar::one());
    constant_vector
}

pub fn create_variables(k: usize) -> Vec<Scalar> {
    let mut rng = rand::thread_rng();
    let mut variable_vector: Vec<Scalar> = Vec::new();

    for i in 1..k+1 {
        variable_vector.push(util::give_n(i.try_into().unwrap()));
    }

    let mut second_half: Vec<Scalar> = variable_vector.clone();
    let mut irs = Irs::default();
    irs.shuffle(&mut second_half, &mut rng);

    let x = Scalar::from(1 as u32);//Scalar::random(&mut rng);

    variable_vector.into_iter()
        .chain(second_half.into_iter())
        .chain(iter::once(x))
        .collect()
}

pub fn commit_variables(variables: &Vec<Scalar>, pd_generator: &PedersenGens) -> Vec<RistrettoPoint> {
    let mut rng = rand::thread_rng();
    variables.iter().map(|v| pd_generator.commit(*v, Scalar::random(&mut rng))).collect()
}

pub fn create_a(variables: &Vec<Scalar>) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
    let n = variables.len() - 1;
    let mut a_L: Vec<Scalar> = vec![Scalar::zero(); n];//Vec::new();
    let mut a_R: Vec<Scalar> = vec![Scalar::zero(); n];
    let mut a_O: Vec<Scalar> = vec![Scalar::zero(); n];

    let first_half = &variables[..n/2];
    let second_half = &variables[n/2..n];

    //a_L[n/2] = variables
    let &x = variables.last().unwrap();

    let offset = (n-1)/2;

    for i in 0..first_half.len() - 1 {

        a_R[i] = first_half[i+1] - x;
        a_R[i+offset] = second_half[i+1] - x;

        if i == 0 {
            a_L[i] = (first_half[i] - x);
            a_L[i + offset] = second_half[i] - x;

        } else {
            a_L[i] = a_O[i - 1];
            a_L[i + offset] = a_O[i + offset - 1];

        }

        a_L = a_L.reduce_scalars();
        a_R = a_R.reduce_scalars();

        a_O[i] = a_L[i] * a_R[i];
        a_O[i + offset] = a_L[i + offset] * a_R[i + offset];



    }

    a_L[n-2] = a_O[n-3];
    a_R[n-2] = -Scalar::one().reduce();
    a_O[n-2] = a_L[n-2] * a_R[n-2];

    a_L[n-1] = a_O[offset] + a_O[n-2];
    a_R[n-1] = Scalar::one();
    a_O[n-1] = a_L[n-1] * a_L[n-1];
    

    (a_L.reduce_scalars(), a_R.reduce_scalars(), a_O.reduce_scalars())
    
}

pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());

    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();

    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}
pub fn create_weights(card_count: usize) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
    let n = card_count * 2;
    let Q = n * 2;
    let mut w_l: Vec<Vec<Scalar>>  = vec![vec![Scalar::zero(); n]; Q]; 
    let mut w_r: Vec<Vec<Scalar>>  = vec![vec![Scalar::zero(); n]; Q]; 
    let mut w_o: Vec<Vec<Scalar>>  = vec![vec![Scalar::zero(); n]; Q]; 
    let mut w_v: Vec<Vec<Scalar>> = vec![vec![Scalar::zero(); n+1]; Q];

    for i in 0..Q {
        if i < n {
            w_l[i][i] = Scalar::one();

            if (i != (card_count/2) + 1) 
                && (i != 0) {
                    w_o[i][i-1] = Scalar::one();
            } else {
                w_v[i][n] = -Scalar::one().reduce();
                match i {
                    0 => w_v[i][i] = Scalar::one(),
                    _ => w_v[i][i+1] = Scalar::one(),
                }
            }
        } else {
            w_r[i][i-n] = Scalar::one();
            if i < Q-2 {
                w_v[i][n] = -Scalar::one().reduce();
                match i < n+3 {
                    true => w_v[i][i-n+1] = Scalar::one(),
                    false => w_v[i][i-n+2] = Scalar::one(),
                }
            }
        }
        /*
        if i < n {
            //w_l
            let mut l_temp: &Vec<Scalar> = w_l[i]; 
            l_temp[i] = Scalar::one();

            //w_o
            if (i != 0)
                && ({
                let mut o_temp: &Vec<Scalar> = w_o[i];
            }

        } else {
            //w_r
            let mut r_temp: &Vec<Scalar> = w_r[i]; 
            r_temp[i] = Scalar::one();
        
        }
        */

        
    }
    /*
    for i in 0..n {
        for j in 0..Q {
            if i == j {w_l[i][j] = Scalar::one();}
            else if i + n == j {w_r[i][j] = Scalar::one();}
            //TODO: w_l and w_r the w_o done add w_v and you're DONE!!!!
            //
            if (i + 1 == j) && 
                (j != card_count-1) && 
                (i != n-1) {
                w_o[i][j] = Scalar::one();
            } else if j < Q-2 {
                w_v[n-1][j] = -Scalar::one();
            }
    }
    */
    w_o[n-1][card_count-1] = Scalar::one();

    (w_l, w_r, w_o, w_v)
    //(transpose::<Scalar>(w_l), transpose::<Scalar>(w_r), transpose::<Scalar>(w_o), transpose::<Scalar>(w_v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_constants(card_count: usize) {
        //Deck size card_count, convert to Q(linear constraint count) from n(multiplication gate count)
        let Q = card_count * 2 * 2;

        let c = create_constants(Q);
        for i in 0..Q-2 {
            //println!("{:#?}",c[i]);
            assert_eq!(Scalar::zero(), c[i]);
        }
        //println!("{:#?}",c[Q-2]);
        assert_eq!(-Scalar::one(), c[Q-2]);
        //println!("{:#?}",c[Q-1]);
        assert_eq!(Scalar::one(), c[Q-1]);
    }

    fn test_variables(card_count: usize) {
        let v = create_variables(card_count);
        for i in 0..v.len() {
            //println!("{:#?}", v[i]);
            //println!("{:#?}\n", U256::from_le_bytes(*v[i].as_bytes()));
        }
        assert_eq!(v.len(), (card_count*2)+1);
        
    }

    fn test_a_vectors(card_count: usize) {
        let v = create_variables(card_count);
        let (a_L, a_R, a_O) = create_a(&v);

        assert_eq!(a_L.len(), a_R.len());
        assert_eq!(a_L.len(), a_O.len());
        assert_eq!(a_L.len()+1, v.len());

    }

    fn test_weights(card_count: usize) {
        let (w_l, w_r, w_o, w_v) = create_weights(card_count);

        let formatted: [String; 4] = [w_l, w_r, w_o, w_v].map(|x| print_scalar_mat(&x));
        println!("{}", formatted.join("\n"));
    }

    /*
    #[test]
    fn test_constants_() {
        test_constants(4);
    }

    #[test]
    fn test_variables_() {
        test_variables(4);
    }

    #[test]
    fn test_a_vectors_() {
        test_a_vectors(4);
    }

    #[test]
    fn test_weights_() {
        test_weights(4);
    }
    */

    #[test]
    fn test_base_product() {
        let k = 2;
        let Q = 4 * k;

        let v: Vec<Scalar> = create_variables(k);
        println!("V:");
        println!("{}", print_scalar_vec(&v));

        let c: Vec<Scalar> = create_constants(Q);
        println!("c:");
        println!("{}", print_scalar_vec(&c));

        let (a_l, a_r, a_o) = create_a(&v);
        println!("a_l:");
        println!("{}", print_scalar_vec(&a_l));
        println!("a_r:");
        println!("{}", print_scalar_vec(&a_r));
        println!("a_o:");
        println!("{}", print_scalar_vec(&a_o));

        let (w_l, w_r, w_o, w_v) = create_weights(k);
        println!("W_R:");
        println!("{}", print_scalar_mat(&w_r));
        println!("W_L:");
        println!("{}", print_scalar_mat(&w_l));
        println!("W_O:");
        println!("{}", print_scalar_mat(&w_o));
        println!("W_V:");
        println!("{}", print_scalar_mat(&w_v));



        //W_l * a_l + W_r * a_r + W_o * a_o = W_v * v + c
        //
        let L = util::mv_mult(&w_l, &a_l);
        println!("L:");
        println!("{}", print_scalar_vec(&L));
        let R = util::mv_mult(&w_r, &a_r);
        println!("R:");
        println!("{}", print_scalar_vec(&R));
        let O = util::mv_mult(&w_o, &a_o);
        println!("O:");
        println!("{}", print_scalar_vec(&O));
        let V = util::mv_mult(&w_v, &v);
        println!("V:");
        println!("{}", print_scalar_vec(&V));

        let C: Vec<Scalar> = izip!(L.iter(), R.iter(), O.iter())
            .map(|(o, l, r)| o + l + r)
            .collect();

        let P: Vec<Scalar> = V.iter()
            .zip(c.iter())
            .map(|(v_, c_)| v_ + c_)
            .collect();

        let result = C.iter()
                .zip(P.iter())
                .filter(|(c_, p_)| c_ == p_)
                .count();

        println!("C:");
        println!("{}", print_scalar_vec(&C));
        println!("P:");
        println!("{}", print_scalar_vec(&P));



        
    }

}
