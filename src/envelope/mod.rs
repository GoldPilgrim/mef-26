// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Transport-facing opaque envelopes with minimal recipient metadata.

mod capability;
mod outer;
mod replay;

pub use capability::{MailboxCapability, TransportMessageId};
pub use outer::OuterEnvelope;
pub use replay::ReplayCache;

use crate::PROTOCOL_ID;

/// Returns the versioned envelope framing label.
#[must_use]
pub const fn envelope_label() -> &'static str {
    "MEF-26/outer-envelope-v1"
}

/// Returns the protocol identifier used by the envelope format.
#[must_use]
pub const fn protocol_id() -> &'static str {
    PROTOCOL_ID
}

#[cfg(test)]
mod tests {
    use super::{MailboxCapability, OuterEnvelope, ReplayCache};
    use crate::{
        MefError, Result,
        crypto::{AeadKey, AeadSuite},
        frame::{FrameHeader, FrameKind, InnerFrame},
        keys::DhKeyPair,
    };

    fn inner_frame() -> Result<InnerFrame> {
        InnerFrame::seal(
            &AeadKey::from_bytes([4_u8; 32]),
            AeadSuite::XChaCha20Poly1305,
            FrameHeader::new(FrameKind::Message, [8_u8; 32], [7_u8; 32], 0, 1),
            b"inner",
        )
    }

    #[test]
    fn envelope_round_trips_with_padding_and_canonical_encoding() -> Result<()> {
        let recipient = DhKeyPair::generate()?;
        let mailbox = MailboxCapability::generate()?;
        let inner = inner_frame()?;
        let public = recipient.public();
        let secret = recipient.into_secret();
        let envelope = OuterEnvelope::seal(public, mailbox, 1_800_000_000, &inner, 32)?;
        let decoded = OuterEnvelope::decode(&envelope.encode()?)?;
        let plaintext = decoded.open(&secret, 1_700_000_000)?;
        let expected = inner.encode()?;
        assert_eq!(&plaintext[..expected.len()], expected.as_slice());
        assert_eq!(&plaintext[expected.len()..], &[0_u8; 32]);
        Ok(())
    }

    #[test]
    fn envelope_rejects_expiration_and_header_tampering() -> Result<()> {
        let recipient = DhKeyPair::generate()?;
        let mailbox = MailboxCapability::generate()?;
        let inner = inner_frame()?;
        let public = recipient.public();
        let secret = recipient.into_secret();
        let envelope = OuterEnvelope::seal(public, mailbox, 1_700_000_000, &inner, 0)?;
        assert_eq!(envelope.open(&secret, 1_700_000_001), Err(MefError::EnvelopeExpired));
        let mut bytes = envelope.encode()?;
        bytes[60] ^= 1;
        assert_eq!(
            OuterEnvelope::decode(&bytes)?.open(&secret, 1_600_000_000),
            Err(MefError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn open_inner_removes_padding_and_replay_cache_rejects_duplicates() -> Result<()> {
        let recipient = DhKeyPair::generate()?;
        let public = recipient.public();
        let secret = recipient.into_secret();
        let inner = inner_frame()?;
        let envelope =
            OuterEnvelope::seal(public, MailboxCapability::generate()?, 1_800_000_000, &inner, 64)?;
        let decoded = OuterEnvelope::decode(&envelope.encode()?)?;
        assert_eq!(decoded.open_inner(&secret, 1_700_000_000)?, inner);
        let mut replay_cache = ReplayCache::new(8)?;
        assert_eq!(decoded.open_inner_once(&secret, 1_700_000_000, &mut replay_cache)?, inner);
        assert!(matches!(
            decoded.open_inner_once(&secret, 1_700_000_000, &mut replay_cache),
            Err(MefError::ReplayDetected)
        ));
        Ok(())
    }

    #[test]
    fn storage_identifier_is_stable_but_capability_is_random() -> Result<()> {
        let first = MailboxCapability::generate()?;
        let second = MailboxCapability::generate()?;
        assert_ne!(first, second);
        assert_eq!(first.storage_id()?, first.storage_id()?);
        assert_ne!(first.storage_id()?, second.storage_id()?);
        Ok(())
    }
}
