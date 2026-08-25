// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

#![allow(missing_docs)]

use mef_26::{
    Result,
    envelope::{MailboxCapability, OuterEnvelope},
    frame::FrameKind,
    handshake::{LocalIdentity, ResponderPrekeyMaterial, accept, initiate},
    keys::DhKeyPair,
    ratchet::RatchetState,
};

#[test]
fn two_party_flow_survives_transport_wrapping() -> Result<()> {
    let alice_identity = LocalIdentity::generate()?;
    let mut bob_material = ResponderPrekeyMaterial::generate(42, 2_000_000_000)?;
    bob_material.add_one_time_prekey(43)?;
    let (init_message, alice_handshake) = initiate(&alice_identity, &bob_material.bundle(), 1_800_000_000)?;
    let bob_handshake = accept(&mut bob_material, &init_message)?;
    let mut alice = RatchetState::from_authenticated_handshake(alice_handshake)?;
    let mut bob = RatchetState::from_authenticated_handshake(bob_handshake)?;

    let encrypted = alice.encrypt(FrameKind::Message, b"message carried through an opaque envelope")?;
    let delivery_pair = DhKeyPair::generate()?;
    let delivery_public = delivery_pair.public();
    let delivery_secret = delivery_pair.into_secret();
    let envelope =
        OuterEnvelope::seal(delivery_public, MailboxCapability::generate()?, 1_900_000_000, &encrypted, 128)?;
    let wire = envelope.encode()?;
    let received_envelope = OuterEnvelope::decode(&wire)?;
    let decoded_inner = received_envelope.open_inner(&delivery_secret, 1_800_000_000)?;

    assert_eq!(bob.decrypt(&decoded_inner)?, b"message carried through an opaque envelope");
    Ok(())
}

#[test]
fn replayed_inner_frame_is_rejected_after_successful_delivery() -> Result<()> {
    let alice_identity = LocalIdentity::generate()?;
    let mut bob_material = ResponderPrekeyMaterial::generate(11, 2_000_000_000)?;
    bob_material.add_one_time_prekey(12)?;
    let (init_message, alice_handshake) = initiate(&alice_identity, &bob_material.bundle(), 1_800_000_000)?;
    let bob_handshake = accept(&mut bob_material, &init_message)?;
    let mut alice = RatchetState::from_authenticated_handshake(alice_handshake)?;
    let mut bob = RatchetState::from_authenticated_handshake(bob_handshake)?;

    let frame = alice.encrypt(FrameKind::Message, b"one-time delivery")?;
    assert_eq!(bob.decrypt(&frame)?, b"one-time delivery");
    assert_eq!(bob.decrypt(&frame), Err(mef_26::MefError::MessageKeyConsumed));
    Ok(())
}
