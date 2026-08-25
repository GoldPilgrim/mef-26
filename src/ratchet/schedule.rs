// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Domain-separated ratchet key schedule and bounded skipped-key derivation.

use crate::{
    MAX_SKIPPED_KEYS, MefError, Result,
    crypto::{AeadKey, Secret, derive_aead_key, derive_secret},
};

const ROOT_LABEL: &str = "ratchet-root-v1";
const ROOT_CHAIN_LABEL: &str = "ratchet-root-chain-v1";
const CHAIN_KEY_LABEL: &str = "ratchet-chain-next-v1";
const MESSAGE_KEY_LABEL: &str = "ratchet-message-key-v1";

/// A derived message key associated with its sequence number.
pub(crate) type SkippedKeys = Vec<(u32, AeadKey)>;
/// Result of deriving one target message and intervening skipped keys.
pub(crate) type DerivedMessage = (Secret, AeadKey, SkippedKeys);

/// Advances a symmetric chain exactly once and derives one message key.
pub(crate) fn chain_step(chain_key: &Secret) -> Result<(Secret, AeadKey)> {
    let bytes = chain_key.copy_bytes();
    Ok((derive_secret(&bytes, CHAIN_KEY_LABEL, &[2])?, derive_aead_key(&bytes, MESSAGE_KEY_LABEL, &[1])?))
}

/// Advances the root key using a contributory X25519 output.
pub(crate) fn root_step(root_key: &Secret, dh_output: &[u8; 32]) -> Result<(Secret, Secret)> {
    let root_bytes = root_key.copy_bytes();
    let next_root = derive_secret(&root_bytes, ROOT_LABEL, dh_output)?;
    let chain_key = derive_secret(&next_root.copy_bytes(), ROOT_CHAIN_LABEL, dh_output)?;
    Ok((next_root, chain_key))
}

/// Advances a chain until `end_exclusive`, retaining bounded skipped keys.
pub(crate) fn derive_range(
    chain_key: &Secret,
    start: u32,
    end_exclusive: u32,
    existing_skipped: usize,
) -> Result<(Secret, SkippedKeys)> {
    if end_exclusive < start {
        return Err(MefError::RatchetStateMismatch);
    }
    let additional =
        usize::try_from(u64::from(end_exclusive - start)).map_err(|_| MefError::SkippedKeyLimitExceeded)?;
    if existing_skipped.checked_add(additional).filter(|total| *total <= MAX_SKIPPED_KEYS).is_none() {
        return Err(MefError::SkippedKeyLimitExceeded);
    }
    let mut current = Secret::from_bytes(chain_key.copy_bytes());
    let mut skipped = Vec::with_capacity(additional);
    for number in start..end_exclusive {
        let (next, key) = chain_step(&current)?;
        current = next;
        skipped.push((number, key));
    }
    Ok((current, skipped))
}

/// Derives a target message key and all skipped keys before it.
pub(crate) fn derive_for_message(
    chain_key: &Secret,
    current_count: u32,
    target: u32,
    existing_skipped: usize,
) -> Result<DerivedMessage> {
    let (before_target, skipped) = derive_range(chain_key, current_count, target, existing_skipped)?;
    let (next_chain, message_key) = chain_step(&before_target)?;
    Ok((next_chain, message_key, skipped))
}
