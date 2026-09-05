// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! A bounded 1:1 DH and symmetric ratchet state machine.

mod persistence;
mod schedule;
mod state;

pub use persistence::StateSealKey;
pub use state::{RatchetRole, RatchetState};

#[cfg(test)]
mod tests {
    use super::{RatchetState, StateSealKey};
    use crate::{
        MefError, Result,
        crypto::AeadSuite,
        frame::FrameKind,
        handshake::{LocalIdentity, ResponderPrekeyMaterial, accept, initiate},
    };

    fn pair() -> Result<(RatchetState, RatchetState)> {
        pair_with_suite(AeadSuite::XChaCha20Poly1305)
    }

    fn pair_with_suite(suite: AeadSuite) -> Result<(RatchetState, RatchetState)> {
        let alice_identity = LocalIdentity::generate()?;
        let mut bob_material = ResponderPrekeyMaterial::generate(7, 2_000)?;
        bob_material.add_one_time_prekey(19)?;
        let (message, alice_handshake) = initiate(&alice_identity, &bob_material.bundle(), 1_000)?;
        let bob_handshake = accept(&mut bob_material, &message)?;
        Ok((
            RatchetState::from_authenticated_handshake_with_suite(alice_handshake, suite)?,
            RatchetState::from_authenticated_handshake_with_suite(bob_handshake, suite)?,
        ))
    }

    #[test]
    fn aes_gcm_siv_ratchet_round_trip_and_snapshot_restore() -> Result<()> {
        let (mut alice, mut bob) = pair_with_suite(AeadSuite::Aes256GcmSiv)?;
        assert_eq!(alice.suite(), AeadSuite::Aes256GcmSiv);
        assert_eq!(bob.decrypt(&alice.encrypt(FrameKind::Message, b"siv payload")?)?, b"siv payload");
        let key = StateSealKey::from_bytes([17_u8; 32]);
        let blob = bob.seal_state(&key, b"v011/aes-siv")?;
        let restored = RatchetState::restore_state(&key, b"v011/aes-siv", bob.generation(), &blob)?;
        assert_eq!(restored.suite(), AeadSuite::Aes256GcmSiv);
        Ok(())
    }

    #[test]
    fn bidirectional_messages_round_trip() -> Result<()> {
        let (mut alice, mut bob) = pair()?;
        assert_eq!(bob.decrypt(&alice.encrypt(FrameKind::Message, b"from alice")?)?, b"from alice");
        assert_eq!(alice.decrypt(&bob.encrypt(FrameKind::Message, b"from bob")?)?, b"from bob");
        Ok(())
    }

    #[test]
    fn out_of_order_messages_use_and_consume_skipped_keys() -> Result<()> {
        let (mut alice, mut bob) = pair()?;
        let one = alice.encrypt(FrameKind::Message, b"one")?;
        let two = alice.encrypt(FrameKind::Message, b"two")?;
        let three = alice.encrypt(FrameKind::Message, b"three")?;
        assert_eq!(bob.decrypt(&three)?, b"three");
        assert_eq!(bob.skipped_key_count(), 2);
        assert_eq!(bob.decrypt(&one)?, b"one");
        assert_eq!(bob.decrypt(&two)?, b"two");
        assert_eq!(bob.skipped_key_count(), 0);
        assert_eq!(bob.decrypt(&one), Err(MefError::MessageKeyConsumed));
        Ok(())
    }

    #[test]
    fn failed_authentication_does_not_advance_state() -> Result<()> {
        let (mut alice, mut bob) = pair()?;
        let frame = alice.encrypt(FrameKind::Message, b"valid")?;
        let mut bytes = frame.encode()?;
        let last = bytes.len().checked_sub(1).ok_or(MefError::InvalidFrame)?;
        bytes[last] ^= 1;
        let tampered = crate::frame::InnerFrame::decode(&bytes)?;
        assert_eq!(bob.decrypt(&tampered), Err(MefError::AuthenticationFailed));
        assert_eq!(bob.decrypt(&frame)?, b"valid");
        Ok(())
    }

    #[test]
    fn proactive_dh_rotation_is_processed_by_peer() -> Result<()> {
        let (mut alice, mut bob) = pair()?;
        let old_public = alice.current_public_key();
        alice.rotate_sending_ratchet()?;
        assert_ne!(alice.current_public_key(), old_public);
        assert_eq!(bob.decrypt(&alice.encrypt(FrameKind::Control, b"new ratchet")?)?, b"new ratchet");
        Ok(())
    }
}
