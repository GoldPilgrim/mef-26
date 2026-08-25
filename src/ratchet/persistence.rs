// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Versioned encrypted persistence for ratchet state.
//!
//! Persistence is intentionally explicit: the host supplies a 256-bit key from a platform secure
//! store and a stable per-account/per-device context. The record has a monotonic generation that
//! the host must compare against durable trusted metadata to detect rollback.

use zeroize::Zeroize;

use super::{RatchetState, state::SkippedMessageKey};
use crate::{
    MAX_AAD_LEN, MAX_SKIPPED_KEYS, MefError, Result,
    crypto::{AeadKey, AeadSuite, Ciphertext, Secret, open, seal},
    keys::{DhKeyPair, DhPublicKey, DhSecretKey},
};

const MAGIC: [u8; 3] = *b"MRS";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 3 + 1 + 8 + 1 + 4;
const PLAINTEXT_FIXED_LEN: usize = 32 + 32 + 32 + 32 + 32 + 32 + 4 + 4 + 4 + 2;
const AAD_LABEL: &[u8] = b"MEF-26/ratchet-state-v1\0";

/// A 256-bit key used only to seal and restore one ratchet-state record.
#[derive(Debug)]
pub struct StateSealKey(AeadKey);

impl StateSealKey {
    /// Constructs a persistence key loaded from an approved platform secure store.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(AeadKey::from_bytes(bytes))
    }
}

impl RatchetState {
    /// Encrypts a complete ratchet snapshot bound to a caller-defined storage context.
    ///
    /// The context should uniquely identify the account, device and session storage slot. Persist
    /// the resulting blob atomically with outbound ciphertext or accepted inbound delivery.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized context, invalid internal state, unavailable randomness or
    /// AEAD failures.
    pub fn seal_state(&self, key: &StateSealKey, context: &[u8]) -> Result<Vec<u8>> {
        let aad = state_aad(context)?;
        let mut plaintext = encode_state(self)?;
        let ciphertext = seal(&key.0, AeadSuite::XChaCha20Poly1305, &aad, &plaintext);
        plaintext.zeroize();
        let ciphertext = ciphertext?;
        let body_len = u32::try_from(ciphertext.body().len()).map_err(|_| MefError::InvalidLength)?;
        let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.nonce().len() + ciphertext.body().len());
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&self.generation.to_be_bytes());
        output.push(u8::try_from(ciphertext.nonce().len()).map_err(|_| MefError::InvalidLength)?);
        output.extend_from_slice(&body_len.to_be_bytes());
        output.extend_from_slice(ciphertext.nonce());
        output.extend_from_slice(ciphertext.body());
        Ok(output)
    }

    /// Restores a ratchet snapshot and rejects records below a durable rollback floor.
    ///
    /// The caller must keep `minimum_generation` in storage that cannot be rolled back together
    /// with this blob. On every successful commit, advance that floor atomically with the blob.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::StateRollbackDetected`] for a generation below the supplied floor and
    /// returns an authentication error for the wrong key, context or tampered record.
    pub fn restore_state(
        key: &StateSealKey,
        context: &[u8],
        minimum_generation: u64,
        blob: &[u8],
    ) -> Result<Self> {
        if blob.len() < HEADER_LEN + NONCE_LEN + 16 || blob[..3] != MAGIC || blob[3] != VERSION {
            return Err(MefError::InvalidFrame);
        }
        let generation = u64::from_be_bytes(copy_array(&blob[4..12])?);
        if generation < minimum_generation {
            return Err(MefError::StateRollbackDetected);
        }
        let nonce_len = usize::from(blob[12]);
        let body_len = usize::try_from(u32::from_be_bytes(copy_array(&blob[13..17])?))
            .map_err(|_| MefError::InvalidLength)?;
        let expected = HEADER_LEN
            .checked_add(nonce_len)
            .and_then(|value| value.checked_add(body_len))
            .ok_or(MefError::InvalidLength)?;
        if nonce_len != NONCE_LEN || expected != blob.len() {
            return Err(MefError::InvalidFrame);
        }
        let ciphertext = Ciphertext::from_parts(
            AeadSuite::XChaCha20Poly1305,
            blob[HEADER_LEN..HEADER_LEN + NONCE_LEN].to_vec(),
            blob[HEADER_LEN + NONCE_LEN..].to_vec(),
        )?;
        let aad = state_aad(context)?;
        let mut plaintext = open(&key.0, &ciphertext, &aad)?;
        let state = decode_state(&plaintext, generation);
        plaintext.zeroize();
        state
    }
}

fn encode_state(state: &RatchetState) -> Result<Vec<u8>> {
    if state.skipped.len() > MAX_SKIPPED_KEYS {
        return Err(MefError::InvalidState);
    }
    let skipped_len = u16::try_from(state.skipped.len()).map_err(|_| MefError::InvalidState)?;
    let capacity = PLAINTEXT_FIXED_LEN
        .checked_add(usize::from(skipped_len).checked_mul(68).ok_or(MefError::InvalidLength)?)
        .ok_or(MefError::InvalidLength)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&state.session_id);
    output.extend_from_slice(&state.root_key.copy_bytes());
    output.extend_from_slice(&state.sending_chain.copy_bytes());
    output.extend_from_slice(&state.receiving_chain.copy_bytes());
    output.extend_from_slice(&state.dh_pair.secret_bytes());
    output.extend_from_slice(&state.remote_dh.to_bytes());
    output.extend_from_slice(&state.previous_sending_chain_len.to_be_bytes());
    output.extend_from_slice(&state.sending_count.to_be_bytes());
    output.extend_from_slice(&state.receiving_count.to_be_bytes());
    output.extend_from_slice(&skipped_len.to_be_bytes());
    for entry in &state.skipped {
        output.extend_from_slice(&entry.remote_dh.to_bytes());
        output.extend_from_slice(&entry.message_number.to_be_bytes());
        output.extend_from_slice(entry.key.as_bytes());
    }
    Ok(output)
}

fn decode_state(bytes: &[u8], generation: u64) -> Result<RatchetState> {
    if bytes.len() < PLAINTEXT_FIXED_LEN {
        return Err(MefError::InvalidFrame);
    }
    let skipped_count = usize::from(u16::from_be_bytes(copy_array(&bytes[204..206])?));
    if skipped_count > MAX_SKIPPED_KEYS {
        return Err(MefError::InvalidState);
    }
    let expected = PLAINTEXT_FIXED_LEN
        .checked_add(skipped_count.checked_mul(68).ok_or(MefError::InvalidLength)?)
        .ok_or(MefError::InvalidLength)?;
    if bytes.len() != expected {
        return Err(MefError::InvalidFrame);
    }
    let session_id = copy_array(&bytes[0..32])?;
    let root_key = Secret::from_bytes(copy_array(&bytes[32..64])?);
    let sending_chain = Secret::from_bytes(copy_array(&bytes[64..96])?);
    let receiving_chain = Secret::from_bytes(copy_array(&bytes[96..128])?);
    let dh_pair = DhKeyPair::from_secret(DhSecretKey::from_bytes(copy_array(&bytes[128..160])?));
    let remote_dh = DhPublicKey::from_bytes(copy_array(&bytes[160..192])?);
    let previous_sending_chain_len = u32::from_be_bytes(copy_array(&bytes[192..196])?);
    let sending_count = u32::from_be_bytes(copy_array(&bytes[196..200])?);
    let receiving_count = u32::from_be_bytes(copy_array(&bytes[200..204])?);
    let encoded_count = usize::from(u16::from_be_bytes(copy_array(&bytes[204..206])?));
    if encoded_count != skipped_count {
        return Err(MefError::InvalidFrame);
    }
    let mut skipped = Vec::with_capacity(skipped_count);
    for index in 0..skipped_count {
        let offset = 206 + index.checked_mul(68).ok_or(MefError::InvalidLength)?;
        let remote_dh = DhPublicKey::from_bytes(copy_array(&bytes[offset..offset + 32])?);
        let message_number = u32::from_be_bytes(copy_array(&bytes[offset + 32..offset + 36])?);
        if skipped.iter().any(|entry: &SkippedMessageKey| {
            entry.remote_dh == remote_dh && entry.message_number == message_number
        }) {
            return Err(MefError::InvalidState);
        }
        skipped.push(SkippedMessageKey {
            remote_dh,
            message_number,
            key: AeadKey::from_bytes(copy_array(&bytes[offset + 36..offset + 68])?),
        });
    }
    Ok(RatchetState {
        session_id,
        root_key,
        sending_chain,
        receiving_chain,
        dh_pair,
        remote_dh,
        previous_sending_chain_len,
        sending_count,
        receiving_count,
        generation,
        skipped,
    })
}

fn state_aad(context: &[u8]) -> Result<Vec<u8>> {
    let capacity = AAD_LABEL.len().checked_add(context.len()).ok_or(MefError::InvalidLength)?;
    if capacity > MAX_AAD_LEN {
        return Err(MefError::InvalidLength);
    }
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(AAD_LABEL);
    output.extend_from_slice(context);
    Ok(output)
}

fn copy_array<const N: usize>(source: &[u8]) -> Result<[u8; N]> {
    source.try_into().map_err(|_| MefError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::StateSealKey;
    use crate::{
        MefError, Result,
        frame::FrameKind,
        handshake::{LocalIdentity, ResponderPrekeyMaterial, accept, initiate},
        ratchet::RatchetState,
    };

    fn state_pair() -> Result<(RatchetState, RatchetState)> {
        let alice = LocalIdentity::generate()?;
        let mut bob = ResponderPrekeyMaterial::generate(1, 2_000)?;
        bob.add_one_time_prekey(2)?;
        let (message, alice_handshake) = initiate(&alice, &bob.bundle(), 1_000)?;
        let bob_handshake = accept(&mut bob, &message)?;
        Ok((
            RatchetState::from_authenticated_handshake(alice_handshake)?,
            RatchetState::from_authenticated_handshake(bob_handshake)?,
        ))
    }

    #[test]
    fn encrypted_snapshot_restores_full_out_of_order_state() -> Result<()> {
        let key = StateSealKey::from_bytes([9_u8; 32]);
        let (mut alice, mut bob) = state_pair()?;
        let first = alice.encrypt(FrameKind::Message, b"first")?;
        let second = alice.encrypt(FrameKind::Message, b"second")?;
        assert_eq!(bob.decrypt(&second)?, b"second");
        let blob = bob.seal_state(&key, b"account/device/session")?;
        let mut restored =
            RatchetState::restore_state(&key, b"account/device/session", bob.generation(), &blob)?;
        assert_eq!(restored.decrypt(&first)?, b"first");
        Ok(())
    }

    #[test]
    fn snapshot_is_context_bound_and_rollback_checked() -> Result<()> {
        let key = StateSealKey::from_bytes([3_u8; 32]);
        let (state, _) = state_pair()?;
        let blob = state.seal_state(&key, b"context-a")?;
        assert!(matches!(
            RatchetState::restore_state(&key, b"context-b", 0, &blob),
            Err(MefError::AuthenticationFailed)
        ));
        assert!(matches!(
            RatchetState::restore_state(&key, b"context-a", 1, &blob),
            Err(MefError::StateRollbackDetected)
        ));
        Ok(())
    }
}
