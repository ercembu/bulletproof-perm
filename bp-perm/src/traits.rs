#![allow(non_snake_case)]

extern crate alloc;

use curve25519_dalek_ng::scalar::Scalar;

pub trait ReduceScalar {
    fn reduce_scalars(&mut self) -> Self;
}

impl ReduceScalar for Vec<Scalar> {
    fn reduce_scalars(&mut self) -> Self {
        self.iter()
            .map(|s| s.reduce())
            .collect()
    }
}
