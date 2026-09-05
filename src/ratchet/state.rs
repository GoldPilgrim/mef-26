// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Stateful 1:1 ratchet transitions independent of transport and parsing.

use super::schedule::{chain_step, derive_for_message, derive_range, root_step};
use crate::{
    MefError, Result,
    crypto::{AeadKey, AeadSuite, Secret, derive_secret},
    frame::{FrameHeader, FrameKind, InnerFrame},
    handshake::AuthenticatedHandshake,
    keys::{DhKeyPair, DhPublicKey},
};

const INIT_A_TO_B_LABEL: &str = "ratchet-init-a-to-b-v1";
const INIT_B_TO_A_LABEL: &str = "ratchet-init-b-to-a-v1";
const DEFAULT_SUITE: AeadSuite = AeadSuite::XChaCha20Poly1305;

/// Direction used to derive the initial sending and receiving chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetRole {
    /// The endpoint that initiated the asynchronous session.
    Initiator,
    /// The endpoint that accepted the asynchronous session.
    Responder,
}

/// A bounded, stateful ratchet for a single 1:1 device session.
#[derive(Debug)]
pub struct RatchetState {
    pub(super) session_id: [u8; 32],
    pub(super) root_key: Secret,
    pub(super) sending_chain: Secret,
    pub(super) receiving_chain: Secret,
    pub(super) dh_pair: DhKeyPair,
    pub(super) remote_dh: DhPublicKey,
    pub(super) previous_sending_chain_len: u32,
    pub(super) sending_count: u32,
    pub(super) receiving_count: u32,
    pub(super) generation: u64,
    pub(super) suite: AeadSuite,
    pub(super) skipped: Vec<SkippedMessageKey>,
}

#[derive(Debug)]
pub(super) struct SkippedMessageKey {
    pub(super) remote_dh: DhPublicKey,
    pub(super) message_number: u32,
    pub(super) key: AeadKey,
}

impl RatchetState {
    /// Initializes a ratchet from one validated, transcript-bound handshake result.
    ///
    /// The handshake value is consumed so callers cannot accidentally reuse its root secret for
    /// another session. Use [`crate::handshake::initiate`] or [`crate::handshake::accept`] to
    /// obtain authenticated handshake material.
    ///
    /// # Errors
    ///
    /// Propagates initial HKDF key-schedule failures.
    pub fn from_authenticated_handshake(handshake: AuthenticatedHandshake) -> Result<Self> {
        Self::from_authenticated_handshake_with_suite(handshake, DEFAULT_SUITE)
    }

    /// Initializes a ratchet with an explicit payload AEAD suite.
    ///
    /// The selected suite is authenticated in every frame header and persisted in
    /// version-2 state snapshots. Use only suites supported by both endpoints.
    pub fn from_authenticated_handshake_with_suite(
        handshake: AuthenticatedHandshake,
        suite: AeadSuite,
    ) -> Result<Self> {
        let (session_id, root_key, role, local_dh, remote_dh) = handshake.into_ratchet_parts();
        let a_to_b = derive_secret(&root_key.copy_bytes(), INIT_A_TO_B_LABEL, &session_id)?;
        let b_to_a = derive_secret(&root_key.copy_bytes(), INIT_B_TO_A_LABEL, &session_id)?;
        let (sending_chain, receiving_chain) = match role {
            RatchetRole::Initiator => (a_to_b, b_to_a),
            RatchetRole::Responder => (b_to_a, a_to_b),
        };
        Ok(Self {
            session_id,
            root_key,
            sending_chain,
            receiving_chain,
            dh_pair: local_dh,
            remote_dh,
            previous_sending_chain_len: 0,
            sending_count: 0,
            receiving_count: 0,
            generation: 0,
            suite,
            skipped: Vec::new(),
        })
    }

    /// Returns the session identifier bound to every emitted frame.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Returns the public ratchet key advertised by newly encrypted frames.
    #[must_use]
    pub const fn current_public_key(&self) -> DhPublicKey {
        self.dh_pair.public()
    }

    /// Returns the payload AEAD suite selected for this ratchet.
    #[must_use]
    pub const fn suite(&self) -> AeadSuite {
        self.suite
    }

    /// Returns the number of currently retained skipped message keys.
    #[must_use]
    pub fn skipped_key_count(&self) -> usize {
        self.skipped.len()
    }

    /// Returns the monotonic in-memory transaction generation for persistence rollback checks.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Encrypts a message and commits the next sending-chain state only after successful framing.
    ///
    /// # Errors
    ///
    /// Propagates key-schedule, frame, or counter-overflow errors.
    pub fn encrypt(&mut self, kind: FrameKind, plaintext: &[u8]) -> Result<InnerFrame> {
        let message_number = self.sending_count;
        let (next_chain, message_key) = chain_step(&self.sending_chain)?;
        let header = FrameHeader::new(
            kind,
            self.session_id,
            self.dh_pair.public().to_bytes(),
            self.previous_sending_chain_len,
            message_number,
        );
        let frame = InnerFrame::seal(&message_key, self.suite, header, plaintext)?;
        self.sending_chain = next_chain;
        self.sending_count = self.sending_count.checked_add(1).ok_or(MefError::CounterExhausted)?;
        self.generation = self.generation.saturating_add(1);
        Ok(frame)
    }

    /// Decrypts an authenticated frame and commits state only after AEAD verification succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error for session mismatch, failed authentication, replay, or invalid ratchet progress.
    pub fn decrypt(&mut self, frame: &InnerFrame) -> Result<Vec<u8>> {
        let header = frame.header();
        if header.session_id() != self.session_id || frame.suite() != self.suite {
            return Err(MefError::RatchetStateMismatch);
        }
        let remote_dh = DhPublicKey::from_bytes(header.ratchet_public());
        if remote_dh == self.remote_dh {
            self.decrypt_same_ratchet(remote_dh, frame)
        } else {
            self.decrypt_new_ratchet(remote_dh, frame)
        }
    }

    /// Proactively starts a new sending DH ratchet step.
    ///
    /// # Errors
    ///
    /// Propagates CSPRNG, X25519, or root-key derivation failures.
    pub fn rotate_sending_ratchet(&mut self) -> Result<()> {
        let next_pair = DhKeyPair::generate()?;
        let (next_root, next_sending_chain) =
            root_step(&self.root_key, &next_pair.diffie_hellman(self.remote_dh)?)?;
        self.root_key = next_root;
        self.sending_chain = next_sending_chain;
        self.dh_pair = next_pair;
        self.previous_sending_chain_len = self.sending_count;
        self.sending_count = 0;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    fn decrypt_same_ratchet(&mut self, remote_dh: DhPublicKey, frame: &InnerFrame) -> Result<Vec<u8>> {
        let target = frame.header().message_number();
        if target < self.receiving_count {
            return self.decrypt_skipped(remote_dh, target, frame);
        }
        let (next_chain, message_key, newly_skipped) =
            derive_for_message(&self.receiving_chain, self.receiving_count, target, self.skipped.len())?;
        let plaintext = frame.open(&message_key)?;
        self.receiving_chain = next_chain;
        self.receiving_count = target.checked_add(1).ok_or(MefError::CounterExhausted)?;
        self.add_skipped(remote_dh, newly_skipped);
        self.generation = self.generation.saturating_add(1);
        Ok(plaintext)
    }

    fn decrypt_new_ratchet(&mut self, remote_dh: DhPublicKey, frame: &InnerFrame) -> Result<Vec<u8>> {
        let (old_chain_after_skips, old_skipped) = derive_range(
            &self.receiving_chain,
            self.receiving_count,
            frame.header().previous_chain_len(),
            self.skipped.len(),
        )?;
        let _old_chain_after_skips = old_chain_after_skips;
        let (root_after_receive, next_receiving_chain) =
            root_step(&self.root_key, &self.dh_pair.diffie_hellman(remote_dh)?)?;
        let next_pair = DhKeyPair::generate()?;
        let (root_after_send, next_sending_chain) =
            root_step(&root_after_receive, &next_pair.diffie_hellman(remote_dh)?)?;
        let extra_capacity =
            self.skipped.len().checked_add(old_skipped.len()).ok_or(MefError::SkippedKeyLimitExceeded)?;
        let (receiving_chain, message_key, new_skipped) =
            derive_for_message(&next_receiving_chain, 0, frame.header().message_number(), extra_capacity)?;
        let plaintext = frame.open(&message_key)?;
        let old_remote = self.remote_dh;
        self.add_skipped(old_remote, old_skipped);
        self.add_skipped(remote_dh, new_skipped);
        self.root_key = root_after_send;
        self.receiving_chain = receiving_chain;
        self.sending_chain = next_sending_chain;
        self.dh_pair = next_pair;
        self.remote_dh = remote_dh;
        self.previous_sending_chain_len = self.sending_count;
        self.sending_count = 0;
        self.receiving_count =
            frame.header().message_number().checked_add(1).ok_or(MefError::CounterExhausted)?;
        self.generation = self.generation.saturating_add(1);
        Ok(plaintext)
    }

    fn add_skipped(&mut self, remote_dh: DhPublicKey, keys: Vec<(u32, AeadKey)>) {
        self.skipped.extend(keys.into_iter().map(|(message_number, key)| SkippedMessageKey {
            remote_dh,
            message_number,
            key,
        }));
    }

    fn decrypt_skipped(
        &mut self,
        remote_dh: DhPublicKey,
        message_number: u32,
        frame: &InnerFrame,
    ) -> Result<Vec<u8>> {
        let index = self
            .skipped
            .iter()
            .position(|entry| entry.remote_dh == remote_dh && entry.message_number == message_number)
            .ok_or(MefError::MessageKeyConsumed)?;
        let plaintext = frame.open(&self.skipped[index].key)?;
        let _removed = self.skipped.remove(index);
        self.generation = self.generation.saturating_add(1);
        Ok(plaintext)
    }
}
