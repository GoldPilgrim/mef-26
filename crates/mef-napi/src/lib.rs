// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Node.js N-API metadata binding for MEF-26.

use napi_derive::napi;

/// Returns the additive MEF-26 language-binding ABI version.
#[napi]
pub const fn abi_version() -> u32 {
    mef_26::ABI_VERSION
}

/// Returns the MEF-26 protocol identifier.
#[napi]
pub fn protocol_id() -> String {
    mef_26::PROTOCOL_ID.to_owned()
}

/// Returns the maximum accepted inner ciphertext body size in bytes.
#[napi]
pub const fn max_ciphertext_len() -> u32 {
    mef_26::MAX_CIPHERTEXT_LEN as u32
}
