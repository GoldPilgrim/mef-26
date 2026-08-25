// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Secret byte wrappers with redacted debugging and deterministic zeroization.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::random::fill_secure;
use crate::Result;

/// Fixed byte length of MEF-26 symmetric secrets.
pub(crate) const KEY_LEN: usize = 32;

/// A 256-bit AEAD key that zeroizes its contents when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; KEY_LEN]);

impl AeadKey {
    /// Creates an AEAD key from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generates a fresh key from the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`crate::MefError::RandomnessUnavailable`] if the system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        let mut key = [0_u8; KEY_LEN];
        fill_secure(&mut key)?;
        Ok(Self(key))
    }

    /// Exposes the key only to internal audited primitive wrappers.
    pub(crate) const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for AeadKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AeadKey([REDACTED])")
    }
}

/// A domain-separated 32-byte secret used by internal key schedules.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret([u8; KEY_LEN]);

impl Secret {
    /// Creates a secret from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns a copy intended only for a downstream audited primitive wrapper.
    pub(crate) const fn copy_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}
