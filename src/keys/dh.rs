// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! X25519 key material and fail-closed key agreement.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{MefError, Result, crypto::random_bytes};

/// Fixed byte length of X25519 keys and shared secrets.
pub(crate) const DH_KEY_LEN: usize = 32;

/// Public half of an X25519 key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhPublicKey([u8; DH_KEY_LEN]);

impl DhPublicKey {
    /// Creates a public key from exactly 32 canonical wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DH_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical 32-byte public-key encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; DH_KEY_LEN] {
        self.0
    }
}

/// Secret half of an X25519 key pair. Bytes are zeroized when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DhSecretKey([u8; DH_KEY_LEN]);

impl DhSecretKey {
    /// Generates a new X25519 secret using the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::RandomnessUnavailable`] if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    /// Constructs a secret key from serialization material held by an approved secure store.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DH_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns a copy for internal encrypted-state persistence only.
    pub(crate) const fn copy_bytes(&self) -> [u8; DH_KEY_LEN] {
        self.0
    }

    /// Derives the corresponding X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> DhPublicKey {
        let secret = StaticSecret::from(self.0);
        DhPublicKey(PublicKey::from(&secret).to_bytes())
    }

    /// Performs a fail-closed X25519 agreement and rejects a non-contributory result.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::NonContributoryKeyAgreement`] for a low-order peer key.
    pub fn diffie_hellman(&self, peer: DhPublicKey) -> Result<[u8; DH_KEY_LEN]> {
        let secret = StaticSecret::from(self.0);
        let peer_public = PublicKey::from(peer.0);
        let shared = secret.diffie_hellman(&peer_public);
        if !shared.was_contributory() {
            return Err(MefError::NonContributoryKeyAgreement);
        }
        Ok(shared.to_bytes())
    }
}

impl core::fmt::Debug for DhSecretKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DhSecretKey([REDACTED])")
    }
}

/// An X25519 key pair held by one protocol endpoint.
#[derive(Debug)]
pub struct DhKeyPair {
    secret: DhSecretKey,
    public: DhPublicKey,
}

impl DhKeyPair {
    /// Generates a fresh X25519 key pair.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::RandomnessUnavailable`] if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let secret = DhSecretKey::generate()?;
        Ok(Self::from_secret(secret))
    }

    /// Rehydrates a key pair from a secret-key record held in an approved secure store.
    #[must_use]
    pub fn from_secret(secret: DhSecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Returns the X25519 secret bytes for internal encrypted-state persistence only.
    pub(crate) const fn secret_bytes(&self) -> [u8; DH_KEY_LEN] {
        self.secret.copy_bytes()
    }

    /// Returns the public half of this pair.
    #[must_use]
    pub const fn public(&self) -> DhPublicKey {
        self.public
    }

    /// Performs a fail-closed agreement with a peer public key.
    ///
    /// # Errors
    ///
    /// Propagates a non-contributory X25519 agreement failure.
    pub fn diffie_hellman(&self, peer: DhPublicKey) -> Result<[u8; DH_KEY_LEN]> {
        self.secret.diffie_hellman(peer)
    }

    /// Consumes the pair and returns its secret half for transfer to an approved secure store.
    #[must_use]
    pub fn into_secret(self) -> DhSecretKey {
        self.secret
    }
}
