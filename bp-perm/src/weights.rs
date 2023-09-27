#![allow(non_snake_case)]

extern crate alloc;

use alloc::borrow::Borrow;
use alloc::vec::Vec;

use core::iter;
use curve25519_dalek_ng::scalar::Scalar;

fn create_constants(Q: usize) -> Vec<Scalar> {

    let mut constant_vector: Vec<Scalar> = Vec::new();
    for n in 0..Q-2 {
        constant_vector.push(Scalar::zero());
    }
    constant_vector.push(-Scalar::one());
    constant_vector.push(Scalar::one());
    constant_vector
}
