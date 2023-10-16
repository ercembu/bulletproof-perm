#![allow(non_snake_case)]

use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use bulletproofs::ProofError;

extern crate alloc;
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
