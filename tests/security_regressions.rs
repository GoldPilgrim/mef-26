// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

#![allow(missing_docs)]

use mef_26::{
    MAX_CIPHERTEXT_LEN, MAX_SKIPPED_KEYS, MefError, Result,
    envelope::{MailboxCapability, OuterEnvelope},
    frame::{FrameKind, InnerFrame},
    handshake::{LocalIdentity, ResponderPrekeyMaterial, accept, initiate},
    keys::DhKeyPair,
    ratchet::RatchetState,
};

fn pair(_session_id: [u8; 32]) -> Result<(RatchetState, RatchetState)> {
    let alice_identity = LocalIdentity::generate()?;
    let mut bob_material = ResponderPrekeyMaterial::generate(7, 2_000)?;
    bob_material.add_one_time_prekey(19)?;
    let (message, alice_handshake) = initiate(&alice_identity, &bob_material.bundle(), 1_000)?;
    let bob_handshake = accept(&mut bob_material, &message)?;
    Ok((
        RatchetState::from_authenticated_handshake(alice_handshake)?,
        RatchetState::from_authenticated_handshake(bob_handshake)?,
    ))
}

#[test]
fn failed_outbound_framing_does_not_consume_a_message_key() -> Result<()> {
    let (mut alice, mut bob) = pair([31_u8; 32])?;
    let oversized = vec![0_u8; MAX_CIPHERTEXT_LEN];

    assert!(alice.encrypt(FrameKind::Message, &oversized).is_err());
    let frame = alice.encrypt(FrameKind::Message, b"first valid message")?;

    assert_eq!(frame.header().message_number(), 0);
    assert_eq!(bob.decrypt(&frame)?, b"first valid message");
    Ok(())
}

#[test]
fn skipped_key_limit_rejects_large_gap_without_advancing_receiver_state() -> Result<()> {
    let (mut alice, mut bob) = pair([32_u8; 32])?;
    let frame_count = MAX_SKIPPED_KEYS.checked_add(2).ok_or(MefError::CounterExhausted)?;
    let mut frames = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        frames.push(alice.encrypt(FrameKind::Message, b"bounded gap")?);
    }

    let final_frame = frames.last().ok_or(MefError::InvalidFrame)?;
    assert_eq!(bob.decrypt(final_frame), Err(MefError::SkippedKeyLimitExceeded));
    assert_eq!(bob.skipped_key_count(), 0);
    assert_eq!(bob.decrypt(&frames[0])?, b"bounded gap");
    Ok(())
}

#[test]
fn wrong_session_frame_is_rejected_without_consuming_the_valid_message_key() -> Result<()> {
    let (mut alice, mut bob) = pair([33_u8; 32])?;
    let (mut foreign_alice, _) = pair([34_u8; 32])?;
    let valid = alice.encrypt(FrameKind::Message, b"valid session")?;
    let foreign = foreign_alice.encrypt(FrameKind::Message, b"foreign session")?;

    assert_eq!(bob.decrypt(&foreign), Err(MefError::RatchetStateMismatch));
    assert_eq!(bob.decrypt(&valid)?, b"valid session");
    Ok(())
}

#[test]
fn envelope_expiry_is_checked_before_decryption_and_wire_round_trip_stays_canonical() -> Result<()> {
    let (mut alice, _) = pair([35_u8; 32])?;
    let inner = alice.encrypt(FrameKind::Message, b"expiry guard")?;
    let delivery = DhKeyPair::generate()?;
    let public = delivery.public();
    let secret = delivery.into_secret();
    let envelope = OuterEnvelope::seal(public, MailboxCapability::generate()?, 500, &inner, 0)?;
    let wire = envelope.encode()?;

    assert_eq!(OuterEnvelope::decode(&wire)?.open(&secret, 501), Err(MefError::EnvelopeExpired));
    assert_eq!(InnerFrame::decode(&inner.encode()?)?.encode()?, inner.encode()?);
    Ok(())
}

#[test]
fn canonical_parsers_reject_truncated_and_trailing_wire_data() -> Result<()> {
    let (mut alice, _) = pair([36_u8; 32])?;
    let inner = alice.encrypt(FrameKind::Message, b"parser strictness")?;
    let inner_wire = inner.encode()?;

    let mut truncated_inner = inner_wire.clone();
    let _removed = truncated_inner.pop();
    let mut trailing_inner = inner_wire;
    trailing_inner.push(0);
    assert_eq!(InnerFrame::decode(&truncated_inner), Err(MefError::InvalidFrame));
    assert_eq!(InnerFrame::decode(&trailing_inner), Err(MefError::InvalidFrame));

    let delivery = DhKeyPair::generate()?;
    let envelope = OuterEnvelope::seal(delivery.public(), MailboxCapability::generate()?, 1_000, &inner, 0)?;
    let outer_wire = envelope.encode()?;
    let mut truncated_outer = outer_wire.clone();
    let _removed = truncated_outer.pop();
    let mut trailing_outer = outer_wire;
    trailing_outer.push(0);
    assert_eq!(OuterEnvelope::decode(&truncated_outer), Err(MefError::InvalidFrame));
    assert_eq!(OuterEnvelope::decode(&trailing_outer), Err(MefError::InvalidFrame));
    Ok(())
}
