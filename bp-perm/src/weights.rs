#![allow(non_snake_case)]

extern crate alloc;

use alloc::borrow::Borrow;
use alloc::vec::Vec;

use core::iter;
use curve25519_dalek_ng::scalar::Scalar;

pub fn create_constants(Q: usize) -> Vec<Scalar> {

    let mut constant_vector: Vec<Scalar> = Vec::new();
    for n in 0..Q-2 {
        constant_vector.push(Scalar::zero());
    }
    constant_vector.push(-Scalar::one());
    constant_vector.push(Scalar::one());
    constant_vector
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
