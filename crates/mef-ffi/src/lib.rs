// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Stable C ABI metadata surface for MEF-26.
//!
//! This crate intentionally exposes only plain scalar values and a static NUL-terminated
//! identifier. Stateful cryptographic objects remain inside Rust core APIs until a dedicated,
//! audited opaque-handle ABI is specified.

use core::ffi::c_char;

const PROTOCOL_ID_C: &[u8] = b"MEF-26\0";

/// Returns the additive MEF-26 language-binding ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn mef26_abi_version() -> u32 {
    mef_26::ABI_VERSION
}

/// Returns a borrowed, process-static NUL-terminated protocol identifier.
///
/// The returned pointer is never null and must not be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn mef26_protocol_id() -> *const c_char {
    PROTOCOL_ID_C.as_ptr().cast()
}

/// Returns the maximum supported inner ciphertext body length in bytes.
#[unsafe(no_mangle)]
pub extern "C" fn mef26_max_ciphertext_len() -> usize {
    mef_26::MAX_CIPHERTEXT_LEN
}

#[cfg(test)]
mod tests {
    use super::{mef26_abi_version, mef26_max_ciphertext_len, mef26_protocol_id};

    #[test]
    fn abi_metadata_is_nonzero_and_static() {
        assert_eq!(mef26_abi_version(), 1);
        assert!(mef26_max_ciphertext_len() > 0);
        assert!(!mef26_protocol_id().is_null());
    }
}
