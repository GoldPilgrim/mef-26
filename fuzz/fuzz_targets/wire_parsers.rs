// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mef_26::{envelope::OuterEnvelope, frame::InnerFrame};

fuzz_target!(|bytes: &[u8]| {
    let _ = InnerFrame::decode(bytes);
    let _ = InnerFrame::decode_prefix(bytes);
    let _ = OuterEnvelope::decode(bytes);
});
