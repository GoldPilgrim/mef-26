// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Ed25519 identity signing and strict verification.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use super::{DhPublicKey, SIGNATURE_LEN};
use crate::{MefError, Result, crypto::random_bytes};

const IDENTITY_KEY_LEN: usize = 32;

/// An Ed25519 public verification key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityPublicKey([u8; IDENTITY_KEY_LEN]);

impl IdentityPublicKey {
    /// Parses an Ed25519 public key from its 32-byte canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] for a noncanonical public key.
    pub fn from_bytes(bytes: [u8; IDENTITY_KEY_LEN]) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| MefError::InvalidFrame)?;
        Ok(Self(bytes))
    }

    /// Returns the canonical 32-byte public-key encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; IDENTITY_KEY_LEN] {
        self.0
    }

    /// Strictly verifies an application-defined protocol transcript signature.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::AuthenticationFailed`] for an invalid signature and
    /// [`MefError::InvalidFrame`] for an invalid public key encoding.
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(&self.0).map_err(|_| MefError::InvalidFrame)?;
        verifying_key
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| MefError::AuthenticationFailed)
    }

    /// Strictly verifies a signed-prekey transcript signature.
    pub(crate) fn verify_prekey(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
        self.verify(message, signature)
    }
}

/// An Ed25519 identity signing key. The wrapped implementation zeroizes private material.
pub struct IdentityKeyPair {
    signing: SigningKey,
    public: IdentityPublicKey,
}

impl IdentityKeyPair {
    /// Generates a fresh identity key from the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::RandomnessUnavailable`] if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(random_bytes()?))
    }

    /// Rehydrates an identity key from a 32-byte seed held in an approved secure store.
    #[must_use]
    pub fn from_seed(mut seed: [u8; IDENTITY_KEY_LEN]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let public = IdentityPublicKey(signing.verifying_key().to_bytes());
        Self { signing, public }
    }

    /// Returns the public identity key.
    #[must_use]
    pub const fn public(&self) -> IdentityPublicKey {
        self.public
    }

    /// Signs an application-defined protocol transcript using Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }

    /// Signs a signed-prekey record using Ed25519.
    #[must_use]
    pub fn sign_prekey(&self, key_id: u32, prekey: DhPublicKey, expires_at_unix: u64) -> [u8; SIGNATURE_LEN] {
        self.sign(&super::prekey::transcript(key_id, prekey, expires_at_unix))
    }
}

impl core::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("IdentityKeyPair([REDACTED])")
    }
}
