// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

#![allow(missing_docs)]

use mef_26::{
    Result,
    frame::FrameKind,
    handshake::{LocalIdentity, ResponderPrekeyMaterial, accept, initiate},
    ratchet::RatchetState,
};

fn main() -> Result<()> {
    let alice_identity = LocalIdentity::generate()?;
    let mut bob_prekeys = ResponderPrekeyMaterial::generate(7, 2_000_000_000)?;
    bob_prekeys.add_one_time_prekey(19)?;

    let (initial_message, alice_handshake) = initiate(&alice_identity, &bob_prekeys.bundle(), 1_800_000_000)?;
    let bob_handshake = accept(&mut bob_prekeys, &initial_message)?;
    let mut alice = RatchetState::from_authenticated_handshake(alice_handshake)?;
    let mut bob = RatchetState::from_authenticated_handshake(bob_handshake)?;

    let outbound = alice.encrypt(FrameKind::Message, b"hello from Alice")?;
    let received = bob.decrypt(&outbound)?;
    assert_eq!(received, b"hello from Alice");

    let reply = bob.encrypt(FrameKind::Message, b"hello from Bob")?;
    let received_reply = alice.decrypt(&reply)?;
    assert_eq!(received_reply, b"hello from Bob");
    Ok(())
}
