// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Signed X25519 prekeys for asynchronous session establishment.

use super::{DhPublicKey, IdentityKeyPair, IdentityPublicKey, SIGNATURE_LEN};
use crate::{MefError, PROTOCOL_ID, Result, crypto::blake3_id};

const DH_KEY_LEN: usize = 32;

/// A signed X25519 prekey for asynchronous session establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPrekey {
    key_id: u32,
    public: DhPublicKey,
    expires_at_unix: u64,
    signature: [u8; SIGNATURE_LEN],
}

impl SignedPrekey {
    /// Reconstructs a signed-prekey record from canonical authenticated wire fields.
    #[must_use]
    pub const fn from_parts(
        key_id: u32,
        public: DhPublicKey,
        expires_at_unix: u64,
        signature: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self { key_id, public, expires_at_unix, signature }
    }

    /// Creates and signs a prekey from an X25519 public key.
    #[must_use]
    pub fn issue(identity: &IdentityKeyPair, key_id: u32, public: DhPublicKey, expires_at_unix: u64) -> Self {
        Self {
            key_id,
            public,
            expires_at_unix,
            signature: identity.sign_prekey(key_id, public, expires_at_unix),
        }
    }

    /// Verifies the record signature and validity window against an identity public key.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::AuthenticationFailed`] for expiry or an invalid signature.
    pub fn verify(&self, identity: IdentityPublicKey, now_unix: u64) -> Result<()> {
        if now_unix > self.expires_at_unix {
            return Err(MefError::AuthenticationFailed);
        }
        identity.verify_prekey(&transcript(self.key_id, self.public, self.expires_at_unix), &self.signature)
    }

    /// Returns the stable prekey identifier.
    #[must_use]
    pub const fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Returns the X25519 public prekey.
    #[must_use]
    pub const fn public(&self) -> DhPublicKey {
        self.public
    }

    /// Returns the exclusive expiration timestamp in Unix seconds.
    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Returns the detached Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> [u8; SIGNATURE_LEN] {
        self.signature
    }
}

/// Produces a stable, domain-separated 32-byte identity fingerprint.
///
/// # Errors
///
/// Propagates BLAKE3 identifier input validation failures.
pub fn identity_fingerprint(identity: IdentityPublicKey) -> Result<[u8; 32]> {
    blake3_id("identity-fingerprint-v1", &[&identity.to_bytes()])
}

pub(crate) fn transcript(key_id: u32, prekey: DhPublicKey, expires_at_unix: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(PROTOCOL_ID.len() + 1 + 16 + 4 + DH_KEY_LEN + 8);
    output.extend_from_slice(PROTOCOL_ID.as_bytes());
    output.push(0);
    output.extend_from_slice(b"signed-prekey-v1");
    output.extend_from_slice(&key_id.to_be_bytes());
    output.extend_from_slice(&prekey.to_bytes());
    output.extend_from_slice(&expires_at_unix.to_be_bytes());
    output
}
