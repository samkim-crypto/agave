use {
    crate::errors::TranscriptError,
    curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, traits::IsIdentity},
    merlin::Transcript,
};

pub trait TranscriptProtocol {
    /// Append a domain separator for an `n`-bit range proof
    fn range_proof_domain_separator(&mut self, n: u64);

    /// Append a domain separator for a length-`n` inner product proof.
    fn inner_product_proof_domain_separator(&mut self, n: u64);

    /// Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);

    /// Append a `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);

    /// Append a domain separator for ciphertext-ciphertext equality proof.
    fn ciphertext_ciphertext_equality_proof_domain_separator(&mut self);

    /// Append a domain separator for ciphertext-commitment equality proof.
    fn ciphertext_commitment_equality_proof_domain_separator(&mut self);

    /// Append a domain separator for zero-balance proof.
    fn zero_balance_proof_domain_separator(&mut self);

    /// Append a domain separator for grouped ciphertext validity proof.
    fn grouped_ciphertext_validity_proof_domain_separator(&mut self);

    /// Append a domain separator for batched grouped ciphertext validity proof.
    fn batched_grouped_ciphertext_validity_proof_domain_separator(&mut self);

    /// Append a domain separator for fee sigma proof.
    fn fee_sigma_proof_domain_separator(&mut self);

    /// Append a domain separator for public-key proof.
    fn pubkey_proof_domain_separator(&mut self);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), TranscriptError>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn range_proof_domain_separator(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"range-proof");
        self.append_u64(b"n", n);
    }

    fn inner_product_proof_domain_separator(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"inner-product");
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
    ) -> Result<(), TranscriptError> {
        if point.is_identity() {
            Err(TranscriptError::ValidationError)
        } else {
            self.append_message(label, point.as_bytes());
            Ok(())
        }
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn ciphertext_ciphertext_equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"ciphertext-ciphertext-equality-proof")
    }

    fn ciphertext_commitment_equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"ciphertext-commitment-equality-proof")
    }

    fn zero_balance_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"zero-balance-proof")
    }

    fn grouped_ciphertext_validity_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"validity-proof")
    }

    fn batched_grouped_ciphertext_validity_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"batched-validity-proof")
    }

    fn fee_sigma_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"fee-sigma-proof")
    }

    fn pubkey_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"pubkey-proof")
    }
}
