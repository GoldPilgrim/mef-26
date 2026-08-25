// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! MEF-26 is a security-focused core library for building 1:1 E2EE messengers.
//!
//! The crate intentionally wraps vetted cryptographic implementations instead of
//! implementing cryptographic primitives. It provides strict types, domain
//! separation, bounded message processing, and state-machine components.

/// Cryptographic primitives and typed wrappers.
pub mod crypto;
/// Opaque transport envelopes and mailbox capabilities.
pub mod envelope;
/// Error types returned by MEF-26.
pub mod error;
/// Canonical authenticated wire frames.
pub mod frame;
/// Authenticated asynchronous X25519 prekey handshake profile.
pub mod handshake;
/// Typed X25519 and Ed25519 key material plus signed prekeys.
pub mod keys;
/// Optional ML-KEM-768 primitive adapter; this does not by itself define a PQ handshake.
#[cfg(feature = "pq")]
pub mod pq;
/// Stateful DH and symmetric ratchet for 1:1 sessions.
pub mod ratchet;

/// Public error type used by MEF-26 APIs.
pub use error::MefError;

/// The protocol identifier used for all MEF-26 domain-separation labels.
pub const PROTOCOL_ID: &str = "MEF-26";
/// Version of the additive language-binding ABI exposed by MEF-26 packages.
pub const ABI_VERSION: u32 = 1;
/// Copyright holder named in source and package notices.
pub const COPYRIGHT_HOLDER: &str = "GoldPilgrim";
/// Canonical project home used by package metadata and source offers.
pub const PROJECT_HOME: &str = "https://github.com/GoldPilgrim";
/// The maximum number of skipped message keys retained by the ratchet.
pub const MAX_SKIPPED_KEYS: usize = 1024;
/// The maximum accepted ciphertext body size in bytes.
pub const MAX_CIPHERTEXT_LEN: usize = 1 << 20;
/// The maximum accepted associated-data size in bytes.
pub const MAX_AAD_LEN: usize = 1 << 16;

/// Convenience result type used throughout this crate.
pub type Result<T> = core::result::Result<T, error::MefError>;
