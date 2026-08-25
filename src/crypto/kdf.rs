// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Domain-separated BLAKE3 identifiers and HKDF-SHA-256 key derivation.

use blake3::Hasher;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::{AeadKey, Secret, secret::KEY_LEN};
use crate::{MAX_CIPHERTEXT_LEN, MefError, PROTOCOL_ID, Result};

/// Derives a 32-byte secret through HKDF-SHA-256 with a mandatory MEF-26 label.
///
/// # Errors
///
/// Returns [`MefError::InvalidLength`] for an invalid label or oversized input,
/// or [`MefError::KeyDerivationFailed`] when HKDF expansion rejects the request.
pub fn derive_secret(salt: &[u8], label: &str, input: &[u8]) -> Result<Secret> {
    if label.is_empty() || label.len() > u8::MAX.into() || input.len() > MAX_CIPHERTEXT_LEN {
        return Err(MefError::InvalidLength);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input);
    let mut output = [0_u8; KEY_LEN];
    hkdf.expand(&domain_label(b"kdf", label), &mut output).map_err(|_| MefError::KeyDerivationFailed)?;
    Ok(Secret::from_bytes(output))
}

/// Derives a typed AEAD key through HKDF-SHA-256.
///
/// # Errors
///
/// Propagates key-derivation validation or expansion failures from [`derive_secret`].
pub fn derive_aead_key(salt: &[u8], label: &str, input: &[u8]) -> Result<AeadKey> {
    let secret = derive_secret(salt, label, input)?;
    Ok(AeadKey::from_bytes(secret.copy_bytes()))
}

/// Computes a 32-byte BLAKE3 identifier bound to a MEF-26 domain label.
///
/// # Errors
///
/// Returns [`MefError::InvalidLength`] for an invalid label or oversized component.
pub fn blake3_id(label: &str, parts: &[&[u8]]) -> Result<[u8; KEY_LEN]> {
    if label.is_empty()
        || label.len() > u8::MAX.into()
        || parts.iter().any(|part| part.len() > MAX_CIPHERTEXT_LEN)
    {
        return Err(MefError::InvalidLength);
    }
    let mut hasher = Hasher::new();
    hasher.update(PROTOCOL_ID.as_bytes());
    hasher.update(&[0]);
    hasher.update(b"blake3-id");
    hasher.update(&[0]);
    hasher.update(label.as_bytes());
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| MefError::InvalidLength)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Compares equal-length sensitive values in constant time.
#[must_use]
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn domain_label(kind: &[u8], label: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(PROTOCOL_ID.len() + kind.len() + label.len() + 2);
    info.extend_from_slice(PROTOCOL_ID.as_bytes());
    info.push(0);
    info.extend_from_slice(kind);
    info.push(0);
    info.extend_from_slice(label.as_bytes());
    info
}
