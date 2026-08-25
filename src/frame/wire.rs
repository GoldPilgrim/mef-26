// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Canonical bounded serialization and parsing of MEF-26 inner frames.

use super::{
    FrameHeader, FrameKind,
    header::{RATCHET_PUBLIC_LEN, SESSION_ID_LEN},
};
use crate::{
    MAX_CIPHERTEXT_LEN, MefError, Result,
    crypto::{AeadKey, AeadSuite, Ciphertext, open, seal},
};

const MAGIC: [u8; 3] = *b"MEF";
const VERSION: u8 = 1;
const FIXED_HEADER_LEN: usize = 3 + 1 + 1 + 1 + SESSION_ID_LEN + RATCHET_PUBLIC_LEN + 4 + 4 + 1 + 4;
const AEAD_TAG_LEN: usize = 16;

/// A canonical authenticated inner message frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerFrame {
    header: FrameHeader,
    ciphertext: Ciphertext,
}

impl InnerFrame {
    /// Encrypts a plaintext into a canonical frame using a fresh AEAD nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized plaintext, failed nonce generation, or AEAD failure.
    pub fn seal(key: &AeadKey, suite: AeadSuite, header: FrameHeader, plaintext: &[u8]) -> Result<Self> {
        let body_len = plaintext.len().checked_add(AEAD_TAG_LEN).ok_or(MefError::InvalidLength)?;
        let ciphertext = seal(key, suite, &encode_aad(suite, header, body_len)?, plaintext)?;
        Self::from_ciphertext(header, ciphertext)
    }

    /// Constructs a frame from an already authenticated ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] if internal canonical header construction fails.
    pub fn from_ciphertext(header: FrameHeader, ciphertext: Ciphertext) -> Result<Self> {
        if encode_aad(ciphertext.suite(), header, ciphertext.body().len())?.len() != FIXED_HEADER_LEN {
            return Err(MefError::InvalidFrame);
        }
        Ok(Self { header, ciphertext })
    }

    /// Authenticates and decrypts this frame with the supplied message key.
    ///
    /// # Errors
    ///
    /// Propagates canonical-AAD construction and AEAD authentication errors.
    pub fn open(&self, key: &AeadKey) -> Result<Vec<u8>> {
        open(key, &self.ciphertext, &self.aad()?)
    }

    /// Returns a complete canonical wire encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if the total canonical frame length overflows.
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

    /// Parses a complete canonical wire encoding and rejects trailing data.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] for noncanonical, unknown-version, malformed, or
    /// trailing input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (frame, consumed) = Self::decode_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(MefError::InvalidFrame);
        }
        Ok(frame)
    }

    /// Parses one canonical frame from the beginning of a larger authenticated byte sequence.
    ///
    /// The returned length is the exact frame encoding length. This is intended for envelope
    /// adapters that append authenticated padding after an inner frame; callers must validate any
    /// remaining bytes according to their own format.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] for noncanonical, unknown-version, or malformed input.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < FIXED_HEADER_LEN
            || bytes.len() > MAX_CIPHERTEXT_LEN.saturating_add(FIXED_HEADER_LEN + 24)
        {
            return Err(MefError::InvalidFrame);
        }
        if bytes[0..3] != MAGIC || bytes[3] != VERSION {
            return Err(MefError::InvalidFrame);
        }
        let suite = AeadSuite::from_id(bytes[4])?;
        let kind = FrameKind::from_id(bytes[5])?;
        let session_id = copy_array::<SESSION_ID_LEN>(&bytes[6..38])?;
        let ratchet_public = copy_array::<RATCHET_PUBLIC_LEN>(&bytes[38..70])?;
        let previous_chain_len = u32::from_be_bytes(copy_array(&bytes[70..74])?);
        let message_number = u32::from_be_bytes(copy_array(&bytes[74..78])?);
        let nonce_len = usize::from(bytes[78]);
        let body_len = usize::try_from(u32::from_be_bytes(copy_array(&bytes[79..83])?))
            .map_err(|_| MefError::InvalidLength)?;
        if nonce_len != suite.nonce_len() || !(AEAD_TAG_LEN..=MAX_CIPHERTEXT_LEN).contains(&body_len) {
            return Err(MefError::InvalidFrame);
        }
        let expected_len = FIXED_HEADER_LEN
            .checked_add(nonce_len)
            .and_then(|value| value.checked_add(body_len))
            .ok_or(MefError::InvalidLength)?;
        if bytes.len() < expected_len {
            return Err(MefError::InvalidFrame);
        }
        let nonce_end = FIXED_HEADER_LEN + nonce_len;
        let ciphertext = Ciphertext::from_parts(
            suite,
            bytes[FIXED_HEADER_LEN..nonce_end].to_vec(),
            bytes[nonce_end..expected_len].to_vec(),
        )?;
        Ok((
            Self::from_ciphertext(
                FrameHeader::new(kind, session_id, ratchet_public, previous_chain_len, message_number),
                ciphertext,
            )?,
            expected_len,
        ))
    }

    /// Returns the authenticated header.
    #[must_use]
    pub const fn header(&self) -> FrameHeader {
        self.header
    }

    /// Returns the selected AEAD suite.
    #[must_use]
    pub const fn suite(&self) -> AeadSuite {
        self.ciphertext.suite()
    }

    fn aad(&self) -> Result<Vec<u8>> {
        encode_aad(self.ciphertext.suite(), self.header, self.ciphertext.body().len())
    }
}

fn encode_aad(suite: AeadSuite, header: FrameHeader, body_len: usize) -> Result<Vec<u8>> {
    let body_len = u32::try_from(body_len).map_err(|_| MefError::InvalidLength)?;
    let mut output = Vec::with_capacity(FIXED_HEADER_LEN);
    output.extend_from_slice(&MAGIC);
    output.push(VERSION);
    output.push(suite.id());
    output.push(header.kind().id());
    output.extend_from_slice(&header.session_id());
    output.extend_from_slice(&header.ratchet_public());
    output.extend_from_slice(&header.previous_chain_len().to_be_bytes());
    output.extend_from_slice(&header.message_number().to_be_bytes());
    output.push(u8::try_from(suite.nonce_len()).map_err(|_| MefError::InvalidLength)?);
    output.extend_from_slice(&body_len.to_be_bytes());
    if output.len() != FIXED_HEADER_LEN {
        return Err(MefError::InvalidFrame);
    }
    Ok(output)
}

fn copy_array<const N: usize>(source: &[u8]) -> Result<[u8; N]> {
    source.try_into().map_err(|_| MefError::InvalidFrame)
}
