// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Error types for MEF-26.

use thiserror::Error;

/// Errors returned by MEF-26 public APIs.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MefError {
    /// An AEAD authentication tag failed verification or input was malformed.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// A protocol frame was malformed, noncanonical, oversized, or used an unsupported version.
    #[error("invalid frame")]
    InvalidFrame,
    /// A caller supplied an unsupported AEAD suite identifier.
    #[error("unsupported cipher suite")]
    UnsupportedSuite,
    /// A supplied value had an invalid length.
    #[error("invalid length")]
    InvalidLength,
    /// An X25519 exchange produced a non-contributory shared secret.
    #[error("non-contributory key agreement")]
    NonContributoryKeyAgreement,
    /// An HKDF expansion request was rejected.
    #[error("key derivation failed")]
    KeyDerivationFailed,
    /// The operating-system cryptographic random-number generator failed.
    #[error("secure randomness unavailable")]
    RandomnessUnavailable,
    /// A ratchet message counter cannot advance without overflow.
    #[error("message counter exhausted")]
    CounterExhausted,
    /// The allowed skipped-message-key resource limit was exceeded.
    #[error("skipped-message limit exceeded")]
    SkippedKeyLimitExceeded,
    /// A transport envelope exceeded its declared expiration timestamp.
    #[error("envelope expired")]
    EnvelopeExpired,
    /// A replayed outer transport message was rejected.
    #[error("replay detected")]
    ReplayDetected,
    /// A requested message key has already been consumed.
    #[error("message key already consumed")]
    MessageKeyConsumed,
    /// The current session state cannot decrypt the received message.
    #[error("ratchet state mismatch")]
    RatchetStateMismatch,
    /// A persisted ratchet state is older than the durable rollback floor.
    #[error("persisted state rollback detected")]
    StateRollbackDetected,
    /// The operation would violate a protocol state-machine invariant.
    #[error("invalid state transition")]
    InvalidState,
}
