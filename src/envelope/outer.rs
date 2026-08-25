// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Canonical opaque delivery envelope with encrypted padding.

use super::{
    MailboxCapability, ReplayCache, TransportMessageId,
    capability::{CAPABILITY_LEN, TRANSPORT_ID_LEN},
};
use crate::{
    MAX_CIPHERTEXT_LEN, MefError, Result,
    crypto::{AeadSuite, Ciphertext, derive_aead_key, open, seal},
    frame::InnerFrame,
    keys::{DhKeyPair, DhPublicKey, DhSecretKey},
};

const OUTER_MAGIC: [u8; 3] = *b"MEO";
const OUTER_VERSION: u8 = 1;
const OUTER_FIXED_LEN: usize = 3 + 1 + 1 + CAPABILITY_LEN + TRANSPORT_ID_LEN + 8 + 32 + 1 + 4;
const OUTER_SUITE: AeadSuite = AeadSuite::XChaCha20Poly1305;
const AEAD_TAG_LEN: usize = 16;

/// A sealed opaque payload addressed to one mailbox capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterEnvelope {
    mailbox: MailboxCapability,
    message_id: TransportMessageId,
    expires_at_unix: u64,
    sender_ephemeral: DhPublicKey,
    ciphertext: Ciphertext,
}

impl OuterEnvelope {
    /// Seals a complete MEF-26 inner frame for one delivery recipient.
    ///
    /// `padding_len` is encrypted and product-policy controlled. It can reduce length leakage,
    /// but cannot hide traffic timing, IP addresses, or recipient routing.
    ///
    /// # Errors
    ///
    /// Propagates CSPRNG, X25519, KDF, framing, AEAD, and length validation failures.
    pub fn seal(
        recipient_delivery_key: DhPublicKey,
        mailbox: MailboxCapability,
        expires_at_unix: u64,
        inner_frame: &InnerFrame,
        padding_len: usize,
    ) -> Result<Self> {
        let sender_ephemeral = DhKeyPair::generate()?;
        let shared = sender_ephemeral.diffie_hellman(recipient_delivery_key)?;
        let key = derive_aead_key(&mailbox.to_bytes(), "outer-envelope-v1", &shared)?;
        let message_id = TransportMessageId::generate()?;
        let inner_bytes = inner_frame.encode()?;
        let plaintext_len = inner_bytes.len().checked_add(padding_len).ok_or(MefError::InvalidLength)?;
        if plaintext_len > MAX_CIPHERTEXT_LEN.saturating_sub(AEAD_TAG_LEN) {
            return Err(MefError::InvalidLength);
        }
        let body_len = plaintext_len.checked_add(AEAD_TAG_LEN).ok_or(MefError::InvalidLength)?;
        let mut plaintext = inner_bytes;
        plaintext.resize(plaintext_len, 0);
        let ciphertext = seal(
            &key,
            OUTER_SUITE,
            &encode_aad(mailbox, message_id, expires_at_unix, sender_ephemeral.public(), body_len)?,
            &plaintext,
        )?;
        Self::from_ciphertext(mailbox, message_id, expires_at_unix, sender_ephemeral.public(), ciphertext)
    }

    /// Opens an envelope and returns encoded inner frame bytes followed by encrypted padding.
    ///
    /// Prefer [`Self::open_inner`] for messenger integrations because it validates and removes
    /// canonical zero padding.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::EnvelopeExpired`] for expired data or propagates X25519/KDF/AEAD errors.
    pub fn open(&self, recipient_delivery_secret: &DhSecretKey, now_unix: u64) -> Result<Vec<u8>> {
        if now_unix > self.expires_at_unix {
            return Err(MefError::EnvelopeExpired);
        }
        let shared = recipient_delivery_secret.diffie_hellman(self.sender_ephemeral)?;
        let key = derive_aead_key(&self.mailbox.to_bytes(), "outer-envelope-v1", &shared)?;
        open(&key, &self.ciphertext, &self.aad()?)
    }

    /// Opens one canonical inner frame and rejects nonzero or malformed authenticated padding.
    ///
    /// # Errors
    ///
    /// Propagates expiry, key-agreement, KDF and AEAD failures. Returns
    /// [`MefError::InvalidFrame`] if the plaintext does not contain exactly one canonical frame
    /// followed only by zero bytes.
    pub fn open_inner(&self, recipient_delivery_secret: &DhSecretKey, now_unix: u64) -> Result<InnerFrame> {
        let plaintext = self.open(recipient_delivery_secret, now_unix)?;
        let (frame, consumed) = InnerFrame::decode_prefix(&plaintext)?;
        if plaintext[consumed..].iter().any(|byte| *byte != 0) {
            return Err(MefError::InvalidFrame);
        }
        Ok(frame)
    }

    /// Opens one inner frame and records its authenticated transport identifier against replay.
    ///
    /// The cache is updated only after successful envelope authentication and canonical padding
    /// validation. Persist the cache according to the deployment replay-retention policy.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::open_inner`] failures and returns [`MefError::ReplayDetected`] for a
    /// previously accepted transport message identifier.
    pub fn open_inner_once(
        &self,
        recipient_delivery_secret: &DhSecretKey,
        now_unix: u64,
        replay_cache: &mut ReplayCache,
    ) -> Result<InnerFrame> {
        let frame = self.open_inner(recipient_delivery_secret, now_unix)?;
        replay_cache.check_and_insert(self.message_id, self.expires_at_unix, now_unix)?;
        Ok(frame)
    }

    /// Constructs an envelope from parsed and validated wire components.
    ///
    /// # Errors
    ///
    /// Returns an error when suite or canonical header validation fails.
    pub fn from_ciphertext(
        mailbox: MailboxCapability,
        message_id: TransportMessageId,
        expires_at_unix: u64,
        sender_ephemeral: DhPublicKey,
        ciphertext: Ciphertext,
    ) -> Result<Self> {
        if ciphertext.suite() != OUTER_SUITE
            || encode_aad(mailbox, message_id, expires_at_unix, sender_ephemeral, ciphertext.body().len())?
                .len()
                != OUTER_FIXED_LEN
        {
            return Err(MefError::InvalidFrame);
        }
        Ok(Self { mailbox, message_id, expires_at_unix, sender_ephemeral, ciphertext })
    }

    /// Returns recipient routing capability required for queued delivery.
    #[must_use]
    pub const fn mailbox(&self) -> MailboxCapability {
        self.mailbox
    }

    /// Returns opaque replay identifier.
    #[must_use]
    pub const fn message_id(&self) -> TransportMessageId {
        self.message_id
    }

    /// Returns exclusive envelope expiration timestamp in Unix seconds.
    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Returns complete canonical outer-envelope wire encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical size calculation overflows.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let aad = self.aad()?;
        let total_len = aad
            .len()
            .checked_add(self.ciphertext.nonce().len())
            .and_then(|value| value.checked_add(self.ciphertext.body().len()))
            .ok_or(MefError::InvalidLength)?;
        let mut output = Vec::with_capacity(total_len);
        output.extend_from_slice(&aad);
        output.extend_from_slice(self.ciphertext.nonce());
        output.extend_from_slice(self.ciphertext.body());
        Ok(output)
    }

    /// Parses a complete canonical envelope and rejects malformed or trailing data.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] for malformed, noncanonical, or unknown-version input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < OUTER_FIXED_LEN
            || bytes.len() > MAX_CIPHERTEXT_LEN.saturating_add(OUTER_FIXED_LEN + 24)
        {
            return Err(MefError::InvalidFrame);
        }
        if bytes[0..3] != OUTER_MAGIC
            || bytes[3] != OUTER_VERSION
            || AeadSuite::from_id(bytes[4])? != OUTER_SUITE
        {
            return Err(MefError::InvalidFrame);
        }
        let mailbox = MailboxCapability::from_bytes(copy_array(&bytes[5..37])?);
        let message_id = TransportMessageId::from_bytes(copy_array(&bytes[37..53])?);
        let expires_at_unix = u64::from_be_bytes(copy_array(&bytes[53..61])?);
        let sender_ephemeral = DhPublicKey::from_bytes(copy_array(&bytes[61..93])?);
        let nonce_len = usize::from(bytes[93]);
        let body_len = usize::try_from(u32::from_be_bytes(copy_array(&bytes[94..98])?))
            .map_err(|_| MefError::InvalidLength)?;
        if nonce_len != OUTER_SUITE.nonce_len() || !(AEAD_TAG_LEN..=MAX_CIPHERTEXT_LEN).contains(&body_len) {
            return Err(MefError::InvalidFrame);
        }
        let expected = OUTER_FIXED_LEN
            .checked_add(nonce_len)
            .and_then(|value| value.checked_add(body_len))
            .ok_or(MefError::InvalidLength)?;
        if bytes.len() != expected {
            return Err(MefError::InvalidFrame);
        }
        let nonce_end = OUTER_FIXED_LEN + nonce_len;
        let ciphertext = Ciphertext::from_parts(
            OUTER_SUITE,
            bytes[OUTER_FIXED_LEN..nonce_end].to_vec(),
            bytes[nonce_end..].to_vec(),
        )?;
        Self::from_ciphertext(mailbox, message_id, expires_at_unix, sender_ephemeral, ciphertext)
    }

    fn aad(&self) -> Result<Vec<u8>> {
        encode_aad(
            self.mailbox,
            self.message_id,
            self.expires_at_unix,
            self.sender_ephemeral,
            self.ciphertext.body().len(),
        )
    }
}

fn encode_aad(
    mailbox: MailboxCapability,
    message_id: TransportMessageId,
    expires_at_unix: u64,
    sender_ephemeral: DhPublicKey,
    body_len: usize,
) -> Result<Vec<u8>> {
    let body_len = u32::try_from(body_len).map_err(|_| MefError::InvalidLength)?;
    let mut aad = Vec::with_capacity(OUTER_FIXED_LEN);
    aad.extend_from_slice(&OUTER_MAGIC);
    aad.push(OUTER_VERSION);
    aad.push(OUTER_SUITE.id());
    aad.extend_from_slice(&mailbox.to_bytes());
    aad.extend_from_slice(&message_id.to_bytes());
    aad.extend_from_slice(&expires_at_unix.to_be_bytes());
    aad.extend_from_slice(&sender_ephemeral.to_bytes());
    aad.push(u8::try_from(OUTER_SUITE.nonce_len()).map_err(|_| MefError::InvalidLength)?);
    aad.extend_from_slice(&body_len.to_be_bytes());
    if aad.len() != OUTER_FIXED_LEN {
        return Err(MefError::InvalidFrame);
    }
    Ok(aad)
}

fn copy_array<const N: usize>(source: &[u8]) -> Result<[u8; N]> {
    source.try_into().map_err(|_| MefError::InvalidFrame)
}
