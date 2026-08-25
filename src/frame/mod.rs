// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Canonical, bounded wire frames for MEF-26 inner messages.

mod header;
mod wire;

pub use header::{FrameHeader, FrameKind};
pub use wire::InnerFrame;

use crate::PROTOCOL_ID;

/// Returns the versioned framing label for external transcript construction.
#[must_use]
pub const fn framing_label() -> &'static str {
    "MEF-26/inner-frame-v1"
}

/// Returns the protocol identifier used by this frame format.
#[must_use]
pub const fn protocol_id() -> &'static str {
    PROTOCOL_ID
}

#[cfg(test)]
mod tests {
    use super::{FrameHeader, FrameKind, InnerFrame};
    use crate::{MefError, Result, crypto::AeadKey, crypto::AeadSuite};

    fn make_frame() -> Result<InnerFrame> {
        let key = AeadKey::from_bytes([3_u8; 32]);
        InnerFrame::seal(
            &key,
            AeadSuite::XChaCha20Poly1305,
            FrameHeader::new(FrameKind::Message, [1_u8; 32], [2_u8; 32], 4, 9),
            b"frame payload",
        )
    }

    #[test]
    fn frame_round_trips_and_decrypts() -> Result<()> {
        let key = AeadKey::from_bytes([3_u8; 32]);
        let decoded = InnerFrame::decode(&make_frame()?.encode()?)?;
        assert_eq!(decoded.open(&key)?, b"frame payload");
        assert_eq!(decoded.header().session_id(), [1_u8; 32]);
        assert_eq!(decoded.header().message_number(), 9);
        Ok(())
    }

    #[test]
    fn header_tampering_breaks_aead_authentication() -> Result<()> {
        let key = AeadKey::from_bytes([3_u8; 32]);
        let mut bytes = make_frame()?.encode()?;
        bytes[77] ^= 1;
        assert_eq!(InnerFrame::decode(&bytes)?.open(&key), Err(MefError::AuthenticationFailed));
        Ok(())
    }

    #[test]
    fn parser_rejects_trailing_and_unknown_version_bytes() -> Result<()> {
        let mut bytes = make_frame()?.encode()?;
        bytes.push(0);
        assert_eq!(InnerFrame::decode(&bytes), Err(MefError::InvalidFrame));
        bytes.pop();
        bytes[3] = 2;
        assert_eq!(InnerFrame::decode(&bytes), Err(MefError::InvalidFrame));
        Ok(())
    }
}
