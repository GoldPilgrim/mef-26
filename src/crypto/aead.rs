// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Authenticated encryption wrappers over audited RustCrypto implementations.

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{AeadInOut, KeyInit},
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, XChaCha20Poly1305, XNonce};

use super::{AeadKey, random::fill_secure};
use crate::{MAX_AAD_LEN, MAX_CIPHERTEXT_LEN, MefError, Result};

const AES_CHACHA_NONCE_LEN: usize = 12;
const XCHACHA_NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;

/// Supported authenticated-encryption suites for application payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AeadSuite {
    /// AES-256-GCM with a 96-bit nonce and a 128-bit authentication tag.
    Aes256Gcm = 1,
    /// ChaCha20-Poly1305 with a 96-bit nonce and a 128-bit authentication tag.
    ChaCha20Poly1305 = 2,
    /// XChaCha20-Poly1305 with a 192-bit nonce and a 128-bit authentication tag.
    XChaCha20Poly1305 = 3,
}

impl AeadSuite {
    /// Parses a stable wire identifier into an AEAD suite.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::UnsupportedSuite`] for an unknown identifier.
    pub const fn from_id(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Aes256Gcm),
            2 => Ok(Self::ChaCha20Poly1305),
            3 => Ok(Self::XChaCha20Poly1305),
            _ => Err(MefError::UnsupportedSuite),
        }
    }

    /// Returns the stable wire identifier for this suite.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Returns the nonce length required by this suite.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => AES_CHACHA_NONCE_LEN,
            Self::XChaCha20Poly1305 => XCHACHA_NONCE_LEN,
        }
    }
}

/// An AEAD ciphertext with its nonce and selected suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    suite: AeadSuite,
    nonce: Vec<u8>,
    body: Vec<u8>,
}

impl Ciphertext {
    /// Validates and constructs a ciphertext parsed from a canonical frame.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidLength`] for an invalid nonce or ciphertext length.
    pub fn from_parts(suite: AeadSuite, nonce: Vec<u8>, body: Vec<u8>) -> Result<Self> {
        if nonce.len() != suite.nonce_len() || !(AEAD_TAG_LEN..=MAX_CIPHERTEXT_LEN).contains(&body.len()) {
            return Err(MefError::InvalidLength);
        }
        Ok(Self { suite, nonce, body })
    }

    /// Returns the suite used for this ciphertext.
    #[must_use]
    pub const fn suite(&self) -> AeadSuite {
        self.suite
    }

    /// Returns the public nonce authenticated by AEAD usage.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns ciphertext concatenated with its authentication tag.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Flips one ciphertext byte for an internal authentication-failure test.
    #[cfg(test)]
    pub(crate) fn tamper_first_byte_for_test(&mut self) {
        self.body[0] ^= 1;
    }
}

/// Encrypts plaintext with a fresh random nonce generated internally.
///
/// # Errors
///
/// Returns an error for invalid input sizes, unavailable CSPRNG output, or a primitive failure.
pub fn seal(key: &AeadKey, suite: AeadSuite, aad: &[u8], plaintext: &[u8]) -> Result<Ciphertext> {
    validate_inputs(aad, plaintext)?;
    let mut nonce = vec![0_u8; suite.nonce_len()];
    fill_secure(&mut nonce)?;
    seal_with_nonce(key, suite, &nonce, aad, plaintext)
}

/// Encrypts plaintext with a caller-supplied nonce for deterministic test-vector verification.
///
/// Production code must use [`seal`] because this function cannot enforce nonce uniqueness.
///
/// # Errors
///
/// Returns an error for invalid input sizes, nonce length, or primitive failure.
pub fn seal_with_nonce(
    key: &AeadKey,
    suite: AeadSuite,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Ciphertext> {
    validate_inputs(aad, plaintext)?;
    if nonce.len() != suite.nonce_len() {
        return Err(MefError::InvalidLength);
    }
    let mut body = plaintext.to_vec();
    match suite {
        AeadSuite::Aes256Gcm => {
            Aes256Gcm::new_from_slice(key.as_bytes())
                .map_err(|_| MefError::InvalidLength)?
                .encrypt_in_place(
                    &AesNonce::try_from(nonce).map_err(|_| MefError::InvalidLength)?,
                    aad,
                    &mut body,
                )
                .map_err(|_| MefError::AuthenticationFailed)?;
        }
        AeadSuite::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|_| MefError::InvalidLength)?
                .encrypt_in_place(
                    &ChaChaNonce::try_from(nonce).map_err(|_| MefError::InvalidLength)?,
                    aad,
                    &mut body,
                )
                .map_err(|_| MefError::AuthenticationFailed)?;
        }
        AeadSuite::XChaCha20Poly1305 => {
            XChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|_| MefError::InvalidLength)?
                .encrypt_in_place(
                    &XNonce::try_from(nonce).map_err(|_| MefError::InvalidLength)?,
                    aad,
                    &mut body,
                )
                .map_err(|_| MefError::AuthenticationFailed)?;
        }
    }
    Ciphertext::from_parts(suite, nonce.to_vec(), body)
}

/// Decrypts and authenticates a ciphertext using exact associated data.
///
/// # Errors
///
/// Returns [`MefError::AuthenticationFailed`] when ciphertext or AAD validation fails,
/// and [`MefError::InvalidLength`] for oversized AAD.
pub fn open(key: &AeadKey, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    if aad.len() > MAX_AAD_LEN {
        return Err(MefError::InvalidLength);
    }
    let mut plaintext = ciphertext.body.clone();
    match ciphertext.suite {
        AeadSuite::Aes256Gcm => {
            Aes256Gcm::new_from_slice(key.as_bytes())
                .map_err(|_| MefError::InvalidLength)?
                .decrypt_in_place(
                    &AesNonce::try_from(ciphertext.nonce.as_slice()).map_err(|_| MefError::InvalidLength)?,
                    aad,
                    &mut plaintext,
                )
                .map_err(|_| MefError::AuthenticationFailed)?;
        }
        AeadSuite::ChaCha20Poly1305 => {
            ChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|_| MefError::InvalidLength)?
                .decrypt_in_place(
                    &ChaChaNonce::try_from(ciphertext.nonce.as_slice())
                        .map_err(|_| MefError::InvalidLength)?,
                    aad,
                    &mut plaintext,
                )
                .map_err(|_| MefError::AuthenticationFailed)?;
        }
        AeadSuite::XChaCha20Poly1305 => {
            XChaCha20Poly1305::new_from_slice(key.as_bytes())
                .map_err(|_| MefError::InvalidLength)?
                .decrypt_in_place(
                    &XNonce::try_from(ciphertext.nonce.as_slice()).map_err(|_| MefError::InvalidLength)?,
                    aad,
                    &mut plaintext,
                )
                .map_err(|_| MefError::AuthenticationFailed)?;
        }
    }
    Ok(plaintext)
}

fn validate_inputs(aad: &[u8], plaintext: &[u8]) -> Result<()> {
    if aad.len() > MAX_AAD_LEN || plaintext.len() > MAX_CIPHERTEXT_LEN.saturating_sub(AEAD_TAG_LEN) {
        return Err(MefError::InvalidLength);
    }
    Ok(())
}
