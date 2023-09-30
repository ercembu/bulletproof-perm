#![allow(non_snake_case)]

extern crate alloc;
extern crate sha3;

use alloc::borrow::Borrow;
use alloc::vec::Vec;
use sha3::Sha3_512;
use shuffle::irs::Irs;

use core::iter;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::RistrettoPoint;

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

pub fn create_variables(k: usize) -> Vec<RistrettoPoint> {
    let mut rng = rand::thread_rng();
    let mut variable_vector: Vec<RistrettoPoint> = Vec::new();

    for i in 0..k {
        variable_vector.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(
                                                &i.to_string()
                                                    .as_bytes()));
    }

    let mut second_half: Vec<RistrettoPoint> = variable_vector.clone();
    let mut irs = Irs::default();
    irs.shuffle(&mut second_half, &mut rng);

    let x = RistrettoPoint::random(&mut rng);

    variable_vector.into_iter()
        .chain(second_half.into_iter())
        .chain(iter::once(x))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_constants(k: usize) {
        //Deck size k, convert to Q(linear constraint count) from n(multiplication gate count)
        let Q = k * 2 * 2;

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

    #[test]
    fn test_1() {
        test_constants(4);
    }

}
