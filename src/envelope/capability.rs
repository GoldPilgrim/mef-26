// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Opaque recipient routing and replay identifiers.

use crate::{
    Result,
    crypto::{blake3_id, random_bytes},
};

/// Wire length of a mailbox routing capability.
pub(crate) const CAPABILITY_LEN: usize = 32;
/// Wire length of a transport replay identifier.
pub(crate) const TRANSPORT_ID_LEN: usize = 16;

/// A random, unlinkable recipient routing capability for a delivery mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxCapability([u8; CAPABILITY_LEN]);

impl MailboxCapability {
    /// Generates a fresh random mailbox capability.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating-system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    /// Constructs a capability from an already authenticated out-of-band record.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CAPABILITY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the opaque random routing capability bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; CAPABILITY_LEN] {
        self.0
    }

    /// Returns a BLAKE3 storage identifier suitable for server-side lookup.
    ///
    /// # Errors
    ///
    /// Propagates BLAKE3 identifier validation failures.
    pub fn storage_id(self) -> Result<[u8; 32]> {
        blake3_id("mailbox-capability-v1", &[&self.0])
    }
}

/// A unique opaque identifier used for recipient-side replay detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportMessageId([u8; TRANSPORT_ID_LEN]);

impl TransportMessageId {
    /// Generates a fresh transport message identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating-system CSPRNG fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(random_bytes()?))
    }

    /// Parses an identifier from canonical wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TRANSPORT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns canonical identifier bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; TRANSPORT_ID_LEN] {
        self.0
    }
}
