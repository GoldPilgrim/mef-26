// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Typed wrappers around audited cryptographic primitives.

mod aead;
mod kdf;
mod random;
mod secret;

pub use aead::{AeadSuite, Ciphertext, open, seal, seal_with_nonce};
pub use kdf::{blake3_id, ct_eq, derive_aead_key, derive_secret};
pub use random::random_bytes;
pub use secret::{AeadKey, Secret};

#[cfg(test)]
mod tests {
    use super::{AeadKey, AeadSuite, blake3_id, ct_eq, derive_aead_key, open, seal, seal_with_nonce};
    use crate::{MefError, Result};

    const KEY: [u8; 32] = [7_u8; 32];

    #[test]
    fn every_aead_suite_round_trips() -> Result<()> {
        let key = AeadKey::from_bytes(KEY);
        for suite in [
            AeadSuite::Aes256Gcm,
            AeadSuite::Aes256GcmSiv,
            AeadSuite::ChaCha20Poly1305,
            AeadSuite::XChaCha20Poly1305,
        ] {
            let ciphertext = seal(&key, suite, b"mef aad", b"confidential payload")?;
            assert_eq!(open(&key, &ciphertext, b"mef aad")?, b"confidential payload");
        }
        Ok(())
    }

    #[test]
    fn aes_gcm_siv_rejects_tampering_and_wrong_aad() -> Result<()> {
        let key = AeadKey::from_bytes(KEY);
        let mut ciphertext =
            seal_with_nonce(&key, AeadSuite::Aes256GcmSiv, &[9_u8; 12], b"correct aad", b"payload")?;
        assert_eq!(open(&key, &ciphertext, b"wrong aad"), Err(MefError::AuthenticationFailed));
        ciphertext.tamper_first_byte_for_test();
        assert_eq!(open(&key, &ciphertext, b"correct aad"), Err(MefError::AuthenticationFailed));
        Ok(())
    }

    #[test]
    fn authentication_failure_is_uniform_for_tampering_and_wrong_aad() -> Result<()> {
        let key = AeadKey::from_bytes(KEY);
        let mut ciphertext =
            seal_with_nonce(&key, AeadSuite::XChaCha20Poly1305, &[9_u8; 24], b"correct aad", b"payload")?;
        assert_eq!(open(&key, &ciphertext, b"wrong aad"), Err(MefError::AuthenticationFailed));
        ciphertext.tamper_first_byte_for_test();
        assert_eq!(open(&key, &ciphertext, b"correct aad"), Err(MefError::AuthenticationFailed));
        Ok(())
    }

    #[test]
    fn hkdf_labels_are_domain_separated() -> Result<()> {
        let first = derive_aead_key(b"salt", "chain-a", b"input")?;
        let second = derive_aead_key(b"salt", "chain-b", b"input")?;
        assert!(!ct_eq(first.as_bytes(), second.as_bytes()));
        Ok(())
    }

    #[test]
    fn blake3_identifier_is_length_delimited_and_domain_separated() -> Result<()> {
        let one = blake3_id("sid", &[b"ab", b"c"])?;
        let two = blake3_id("sid", &[b"a", b"bc"])?;
        let three = blake3_id("other", &[b"ab", b"c"])?;
        assert_ne!(one, two);
        assert_ne!(one, three);
        Ok(())
    }

    #[test]
    fn explicit_nonce_must_match_suite() {
        let key = AeadKey::from_bytes(KEY);
        assert_eq!(
            seal_with_nonce(&key, AeadSuite::Aes256GcmSiv, &[0_u8; 24], b"", b"payload"),
            Err(MefError::InvalidLength)
        );
    }
}
