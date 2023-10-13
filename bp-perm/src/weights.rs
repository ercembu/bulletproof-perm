#![allow(non_snake_case)]

extern crate alloc;
extern crate sha3;

use alloc::borrow::Borrow;
use alloc::vec::Vec;
use sha3::Sha3_512;
use shuffle::irs::Irs;
use std::convert::TryInto;
use ethnum::U256;

use core::iter;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use bulletproofs::PedersenGens;
use crate::util;

use shuffle::shuffler::Shuffler;

pub fn create_constants(Q: usize) -> Vec<Scalar> {

    let mut constant_vector: Vec<Scalar> = Vec::new();
    for _ in 0..Q-2 {
        constant_vector.push(Scalar::zero());
    }
    constant_vector.push(-Scalar::one());
    constant_vector.push(Scalar::one());
    constant_vector
}

pub fn create_variables(k: usize) -> Vec<Scalar> {
    let mut rng = rand::thread_rng();
    let mut variable_vector: Vec<Scalar> = Vec::new();

    for i in 0..k {
        variable_vector.push(util::give_n(i.try_into().unwrap()));
    }

    let mut second_half: Vec<Scalar> = variable_vector.clone();
    let mut irs = Irs::default();
    irs.shuffle(&mut second_half, &mut rng);

    let x = Scalar::random(&mut rng);

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
            a_L[i] = first_half[i] - x;
            a_L[i + offset] = second_half[i] - x;

        } else {
            a_L[i] = a_O[i - 1];
            a_L[i + offset] = a_O[i + offset - 1];

        }

        a_O[i] = a_L[i] * a_R[i];
        a_O[i + offset] = a_L[i + offset] * a_R[i + offset];

    }

    a_L[n-2] = a_O[n-3];
    a_R[n-2] = -Scalar::one();
    a_O[n-2] = a_L[n-2] * a_L[n-2];

    a_L[n-1] = a_O[offset] + a_O[n-2];
    a_R[n-1] = Scalar::one();
    a_O[n-1] = a_L[n-1] * a_L[n-1];
    

    (a_L, a_R, a_O)
    
}

pub fn create_weights(card_count: usize) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
    let n = card_count * 2;
    let Q = n * 2;
    let mut w_l: Vec<Vec<Scalar>>  = vec![vec![Scalar::zero(); Q]; n]; 
    let mut w_r: Vec<Vec<Scalar>>  = vec![vec![Scalar::zero(); Q]; n]; 
    let mut w_o: Vec<Vec<Scalar>>  = vec![vec![Scalar::zero(); Q]; n]; 
    let mut w_v: Vec<Vec<Scalar>> = vec![vec![Scalar::zero(); Q]; n+1];

    for i in 0..n {
        for j in 0..Q {
            if i == j {w_l[i][j] = Scalar::one();}
            else if i + n == j {w_r[i+n][j] = Scalar::one();}
            //TODO: w_l and w_r done add the w_o and w_v and you're DONE!!!!
        }
    }

    (w_l, w_r, w_o, w_v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_constants(card_count: usize) {
        //Deck size card_count, convert to Q(linear constraint count) from n(multiplication gate count)
        let Q = card_count * 2 * 2;

        let c = create_constants(Q);
        for i in 0..Q-2 {
            println!("{:#?}",c[i]);
            assert_eq!(Scalar::zero(), c[i]);
        }
        println!("{:#?}",c[Q-2]);
        assert_eq!(-Scalar::one(), c[Q-2]);
        println!("{:#?}",c[Q-1]);
        assert_eq!(Scalar::one(), c[Q-1]);
    }

    fn test_variables(card_count: usize) {
        let v = create_variables(card_count);
        for i in 0..v.len() {
            println!("{:#?}", v[i]);
            println!("{:#?}\n", U256::from_le_bytes(*v[i].as_bytes()));
        }
        assert_eq!(v.len(), (card_count*2)+1);
        
    }

    fn test_a_vectors(card_count: usize) {
        let v = create_variables(card_count);
        let (a_L, a_R, a_O) = create_a(&v);

        assert_eq!(a_L.len(), a_R.len());
        assert_eq!(a_L.len(), a_O.len());
        assert_eq!(a_L.len()+1, v.len());

        let a = create_weights(card_count);

    }

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

}
