// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

#![allow(missing_docs)]

use mef_26::{
    crypto::{AeadKey, AeadSuite},
    frame::{FrameHeader, FrameKind, InnerFrame},
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn inner_frame_round_trip_preserves_any_bounded_payload(payload in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let key = AeadKey::from_bytes([17_u8; 32]);
        let frame = InnerFrame::seal(
            &key,
            AeadSuite::XChaCha20Poly1305,
            FrameHeader::new(FrameKind::Message, [1_u8; 32], [2_u8; 32], 0, 7),
            &payload,
        );
        prop_assert!(frame.is_ok());
        if let Ok(frame) = frame {
            let encoded = frame.encode();
            prop_assert!(encoded.is_ok());
            if let Ok(encoded) = encoded {
                let decoded = InnerFrame::decode(&encoded);
                prop_assert!(decoded.is_ok());
                if let Ok(decoded) = decoded {
                    prop_assert_eq!(decoded.open(&key).ok(), Some(payload));
                }
            }
        }
    }

    #[test]
    fn arbitrary_wire_bytes_never_panic_for_inner_or_outer_parser(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = InnerFrame::decode(&bytes);
        let _ = InnerFrame::decode_prefix(&bytes);
        let _ = mef_26::envelope::OuterEnvelope::decode(&bytes);
        let _ = mef_26::handshake::InitiatorHandshake::decode(&bytes);
    }
}
