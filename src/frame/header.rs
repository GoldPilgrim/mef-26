// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Immutable authenticated fields of an MEF-26 inner frame.

use crate::{MefError, Result};

/// Wire length of a session identifier.
pub(crate) const SESSION_ID_LEN: usize = 32;
/// Wire length of an X25519 ratchet public key.
pub(crate) const RATCHET_PUBLIC_LEN: usize = 32;

/// Semantic type of an authenticated MEF-26 inner frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameKind {
    /// The first ratchet message sent alongside an asynchronous handshake.
    Init = 1,
    /// A regular encrypted application message.
    Message = 2,
    /// An encrypted delivery acknowledgement.
    Ack = 3,
    /// An encrypted protocol control message.
    Control = 4,
    /// An authenticated request to discard and re-establish a session.
    Reset = 5,
}

impl FrameKind {
    /// Parses a stable wire identifier into a frame kind.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] for an unknown kind.
    pub const fn from_id(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Init),
            2 => Ok(Self::Message),
            3 => Ok(Self::Ack),
            4 => Ok(Self::Control),
            5 => Ok(Self::Reset),
            _ => Err(MefError::InvalidFrame),
        }
    }

    /// Returns the stable wire identifier for this kind.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }
}

/// All non-secret fields authenticated in an MEF-26 inner frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameHeader {
    kind: FrameKind,
    session_id: [u8; SESSION_ID_LEN],
    ratchet_public: [u8; RATCHET_PUBLIC_LEN],
    previous_chain_len: u32,
    message_number: u32,
}

impl FrameHeader {
    /// Creates an immutable frame header that is bound as AEAD associated data.
    #[must_use]
    pub const fn new(
        kind: FrameKind,
        session_id: [u8; SESSION_ID_LEN],
        ratchet_public: [u8; RATCHET_PUBLIC_LEN],
        previous_chain_len: u32,
        message_number: u32,
    ) -> Self {
        Self { kind, session_id, ratchet_public, previous_chain_len, message_number }
    }

    /// Returns the session identifier bound to this header.
    #[must_use]
    pub const fn session_id(self) -> [u8; SESSION_ID_LEN] {
        self.session_id
    }

    /// Returns the sender ratchet public key bound to this header.
    #[must_use]
    pub const fn ratchet_public(self) -> [u8; RATCHET_PUBLIC_LEN] {
        self.ratchet_public
    }

    /// Returns the previous sending-chain length declared by the sender.
    #[must_use]
    pub const fn previous_chain_len(self) -> u32 {
        self.previous_chain_len
    }

    /// Returns the message sequence number within the sender chain.
    #[must_use]
    pub const fn message_number(self) -> u32 {
        self.message_number
    }

    /// Returns the authenticated semantic kind of the frame.
    #[must_use]
    pub const fn kind(self) -> FrameKind {
        self.kind
    }
}
