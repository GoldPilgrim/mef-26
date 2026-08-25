// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Authenticated asynchronous X25519 prekey handshake profile.
//!
//! This module provides a conventional prekey profile for initializing the
//! MEF-26 ratchet. It is intentionally classical-only: the optional ML-KEM
//! adapter is not composed here and must not be treated as PQXDH support.

use crate::{
    MefError, Result,
    crypto::{Secret, blake3_id, derive_secret},
    keys::{DhKeyPair, DhPublicKey, IdentityKeyPair, IdentityPublicKey, SignedPrekey},
    ratchet::RatchetRole,
};

const MAGIC: [u8; 3] = *b"MEH";
const BUNDLE_MAGIC: [u8; 3] = *b"MEB";
const VERSION: u8 = 1;
const IDENTITY_BINDING_LABEL: &str = "handshake-identity-dh-v1";
const SESSION_LABEL: &str = "handshake-session-v1";
const ROOT_LABEL: &str = "handshake-x3dh-root-v1";
const MESSAGE_LEN: usize = 3 + 1 + 32 + 32 + 64 + 32 + 32 + 4 + 1 + 4;
const BUNDLE_LEN: usize = 3 + 1 + 32 + 32 + 64 + 4 + 32 + 8 + 64 + 1 + 4 + 32;

/// A local long-term identity with separate signing and X25519 authentication keys.
#[derive(Debug)]
pub struct LocalIdentity {
    signing: IdentityKeyPair,
    dh: DhKeyPair,
}

impl LocalIdentity {
    /// Generates a fresh local identity using the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Propagates CSPRNG failures.
    pub fn generate() -> Result<Self> {
        Ok(Self { signing: IdentityKeyPair::generate()?, dh: DhKeyPair::generate()? })
    }

    /// Returns the public identity record authenticated by the local signing key.
    #[must_use]
    pub fn public(&self) -> IdentityDhPublic {
        let dh = self.dh.public();
        IdentityDhPublic {
            signing: self.signing.public(),
            dh,
            signature: self.signing.sign(&identity_binding_transcript(dh)),
        }
    }

    fn dh(&self) -> &DhKeyPair {
        &self.dh
    }

    fn signing(&self) -> &IdentityKeyPair {
        &self.signing
    }
}

/// A signing identity, X25519 identity key and signature binding the two together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityDhPublic {
    signing: IdentityPublicKey,
    dh: DhPublicKey,
    signature: [u8; 64],
}

impl IdentityDhPublic {
    /// Returns the Ed25519 identity key used to sign this record.
    #[must_use]
    pub const fn signing_identity(self) -> IdentityPublicKey {
        self.signing
    }

    /// Returns the X25519 identity key used by the handshake.
    #[must_use]
    pub const fn dh_identity(self) -> DhPublicKey {
        self.dh
    }

    /// Verifies the signature binding the Ed25519 and X25519 identities.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::AuthenticationFailed`] for an invalid binding.
    pub fn verify(&self) -> Result<()> {
        self.signing.verify(&identity_binding_transcript(self.dh), &self.signature)
    }
}

/// Public one-time X25519 prekey included in a responder prekey bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneTimePrekeyPublic {
    id: u32,
    public: DhPublicKey,
}

impl OneTimePrekeyPublic {
    /// Returns the stable server-side prekey identifier.
    #[must_use]
    pub const fn id(self) -> u32 {
        self.id
    }

    /// Returns the X25519 public key.
    #[must_use]
    pub const fn public(self) -> DhPublicKey {
        self.public
    }
}

#[derive(Debug)]
struct OneTimePrekey {
    public: OneTimePrekeyPublic,
    key: DhKeyPair,
}

/// A verified responder prekey bundle suitable for an asynchronous initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderPrekeyBundle {
    identity: IdentityDhPublic,
    signed_prekey: SignedPrekey,
    one_time_prekey: Option<OneTimePrekeyPublic>,
}

impl ResponderPrekeyBundle {
    /// Returns the responder's bound identity record.
    #[must_use]
    pub const fn identity(&self) -> IdentityDhPublic {
        self.identity
    }

    /// Returns the responder signed prekey record.
    #[must_use]
    pub const fn signed_prekey(&self) -> &SignedPrekey {
        &self.signed_prekey
    }

    /// Returns the optional one-time prekey offered by the delivery service.
    #[must_use]
    pub const fn one_time_prekey(&self) -> Option<OneTimePrekeyPublic> {
        self.one_time_prekey
    }

    /// Encodes a canonical public prekey bundle for directory delivery.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(BUNDLE_LEN);
        output.extend_from_slice(&BUNDLE_MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&self.identity.signing.to_bytes());
        output.extend_from_slice(&self.identity.dh.to_bytes());
        output.extend_from_slice(&self.identity.signature);
        output.extend_from_slice(&self.signed_prekey.key_id().to_be_bytes());
        output.extend_from_slice(&self.signed_prekey.public().to_bytes());
        output.extend_from_slice(&self.signed_prekey.expires_at_unix().to_be_bytes());
        output.extend_from_slice(&self.signed_prekey.signature());
        match self.one_time_prekey {
            Some(prekey) => {
                output.push(1);
                output.extend_from_slice(&prekey.id.to_be_bytes());
                output.extend_from_slice(&prekey.public.to_bytes());
            }
            None => {
                output.push(0);
                output.extend_from_slice(&0_u32.to_be_bytes());
                output.extend_from_slice(&[0_u8; 32]);
            }
        }
        output
    }

    /// Decodes one complete canonical public prekey bundle from a directory service.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] for malformed or noncanonical encoding and an
    /// authentication error for an invalid identity-key binding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BUNDLE_LEN || bytes[..3] != BUNDLE_MAGIC || bytes[3] != VERSION {
            return Err(MefError::InvalidFrame);
        }
        let identity = IdentityDhPublic {
            signing: IdentityPublicKey::from_bytes(copy_array(&bytes[4..36])?)?,
            dh: DhPublicKey::from_bytes(copy_array(&bytes[36..68])?),
            signature: copy_array(&bytes[68..132])?,
        };
        identity.verify()?;
        let signed_prekey = SignedPrekey::from_parts(
            u32::from_be_bytes(copy_array(&bytes[132..136])?),
            DhPublicKey::from_bytes(copy_array(&bytes[136..168])?),
            u64::from_be_bytes(copy_array(&bytes[168..176])?),
            copy_array(&bytes[176..240])?,
        );
        let one_time_prekey = match bytes[240] {
            0 => {
                if bytes[241..277] != [0_u8; 36] {
                    return Err(MefError::InvalidFrame);
                }
                None
            }
            1 => Some(OneTimePrekeyPublic {
                id: u32::from_be_bytes(copy_array(&bytes[241..245])?),
                public: DhPublicKey::from_bytes(copy_array(&bytes[245..277])?),
            }),
            _ => return Err(MefError::InvalidFrame),
        };
        Ok(Self { identity, signed_prekey, one_time_prekey })
    }

    /// Verifies identity binding, signed-prekey signature and expiry before use.
    ///
    /// # Errors
    ///
    /// Returns an authentication error for a malformed, expired or untrusted bundle.
    pub fn verify(&self, now_unix: u64) -> Result<()> {
        self.identity.verify()?;
        self.signed_prekey.verify(self.identity.signing_identity(), now_unix)
    }
}

/// Responder-held private material for publishing and consuming prekeys.
#[derive(Debug)]
pub struct ResponderPrekeyMaterial {
    identity: LocalIdentity,
    signed_prekey: DhKeyPair,
    signed_record: SignedPrekey,
    retired_signed_prekeys: Vec<(SignedPrekey, DhKeyPair)>,
    one_time_prekeys: Vec<OneTimePrekey>,
}

impl ResponderPrekeyMaterial {
    /// Creates private responder material and an initial signed prekey.
    ///
    /// # Errors
    ///
    /// Propagates CSPRNG failures.
    pub fn generate(signed_prekey_id: u32, expires_at_unix: u64) -> Result<Self> {
        let identity = LocalIdentity::generate()?;
        let signed_prekey = DhKeyPair::generate()?;
        let signed_record = SignedPrekey::issue(
            identity.signing(),
            signed_prekey_id,
            signed_prekey.public(),
            expires_at_unix,
        );
        Ok(Self {
            identity,
            signed_prekey,
            signed_record,
            retired_signed_prekeys: Vec::new(),
            one_time_prekeys: Vec::new(),
        })
    }

    /// Returns the current public bundle, optionally including one available one-time prekey.
    #[must_use]
    pub fn bundle(&self) -> ResponderPrekeyBundle {
        ResponderPrekeyBundle {
            identity: self.identity.public(),
            signed_prekey: self.signed_record.clone(),
            one_time_prekey: self.one_time_prekeys.first().map(|entry| entry.public),
        }
    }

    /// Adds a one-time prekey that is consumed only by a matching accepted handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if secure randomness is unavailable.
    pub fn add_one_time_prekey(&mut self, id: u32) -> Result<()> {
        if self.one_time_prekeys.iter().any(|entry| entry.public.id == id) {
            return Err(MefError::InvalidState);
        }
        let key = DhKeyPair::generate()?;
        self.one_time_prekeys
            .push(OneTimePrekey { public: OneTimePrekeyPublic { id, public: key.public() }, key });
        Ok(())
    }

    /// Returns the number of unconsumed one-time prekeys.
    #[must_use]
    pub fn available_one_time_prekeys(&self) -> usize {
        self.one_time_prekeys.len()
    }

    /// Rotates the signed prekey and retains the old private key for delayed initial messages.
    ///
    /// Call [`Self::retire_signed_prekey`] only after the deployment delay window has elapsed.
    ///
    /// # Errors
    ///
    /// Propagates CSPRNG failures and rejects duplicate current or retained identifiers.
    pub fn rotate_signed_prekey(&mut self, id: u32, expires_at_unix: u64) -> Result<()> {
        if self.signed_record.key_id() == id
            || self.retired_signed_prekeys.iter().any(|(record, _)| record.key_id() == id)
        {
            return Err(MefError::InvalidState);
        }
        let key = DhKeyPair::generate()?;
        let retired =
            DhKeyPair::from_secret(crate::keys::DhSecretKey::from_bytes(self.signed_prekey.secret_bytes()));
        self.retired_signed_prekeys.push((self.signed_record.clone(), retired));
        self.signed_record = SignedPrekey::issue(self.identity.signing(), id, key.public(), expires_at_unix);
        self.signed_prekey = key;
        Ok(())
    }

    /// Deletes one retained signed prekey after the deployment's delayed-delivery window.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidState`] for the current or unknown key identifier.
    pub fn retire_signed_prekey(&mut self, id: u32) -> Result<()> {
        let index = self
            .retired_signed_prekeys
            .iter()
            .position(|(record, _)| record.key_id() == id)
            .ok_or(MefError::InvalidState)?;
        let _removed = self.retired_signed_prekeys.remove(index);
        Ok(())
    }
}

/// Canonical public initial-handshake message delivered to the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiatorHandshake {
    initiator_identity: IdentityDhPublic,
    initiator_ephemeral: DhPublicKey,
    initiator_ratchet: DhPublicKey,
    signed_prekey_id: u32,
    one_time_prekey_id: Option<u32>,
}

impl InitiatorHandshake {
    /// Returns the initiating party's bound identity record.
    #[must_use]
    pub const fn initiator_identity(&self) -> IdentityDhPublic {
        self.initiator_identity
    }

    /// Returns the fresh X25519 ephemeral public key.
    #[must_use]
    pub const fn initiator_ephemeral(&self) -> DhPublicKey {
        self.initiator_ephemeral
    }

    /// Encodes one canonical handshake message for transport.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(MESSAGE_LEN);
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&self.initiator_identity.signing.to_bytes());
        output.extend_from_slice(&self.initiator_identity.dh.to_bytes());
        output.extend_from_slice(&self.initiator_identity.signature);
        output.extend_from_slice(&self.initiator_ephemeral.to_bytes());
        output.extend_from_slice(&self.initiator_ratchet.to_bytes());
        output.extend_from_slice(&self.signed_prekey_id.to_be_bytes());
        match self.one_time_prekey_id {
            Some(id) => {
                output.push(1);
                output.extend_from_slice(&id.to_be_bytes());
            }
            None => {
                output.push(0);
                output.extend_from_slice(&0_u32.to_be_bytes());
            }
        }
        output
    }

    /// Parses a complete canonical handshake message.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidFrame`] for malformed, unknown-version or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MESSAGE_LEN || bytes[..3] != MAGIC || bytes[3] != VERSION {
            return Err(MefError::InvalidFrame);
        }
        let signing = IdentityPublicKey::from_bytes(copy_array(&bytes[4..36])?)?;
        let dh = DhPublicKey::from_bytes(copy_array(&bytes[36..68])?);
        let signature = copy_array(&bytes[68..132])?;
        let initiator_ephemeral = DhPublicKey::from_bytes(copy_array(&bytes[132..164])?);
        let initiator_ratchet = DhPublicKey::from_bytes(copy_array(&bytes[164..196])?);
        let signed_prekey_id = u32::from_be_bytes(copy_array(&bytes[196..200])?);
        let one_time_prekey_id = match bytes[200] {
            0 => {
                if bytes[201..205] != [0_u8; 4] {
                    return Err(MefError::InvalidFrame);
                }
                None
            }
            1 => Some(u32::from_be_bytes(copy_array(&bytes[201..205])?)),
            _ => return Err(MefError::InvalidFrame),
        };
        let initiator_identity = IdentityDhPublic { signing, dh, signature };
        initiator_identity.verify()?;
        Ok(Self {
            initiator_identity,
            initiator_ephemeral,
            initiator_ratchet,
            signed_prekey_id,
            one_time_prekey_id,
        })
    }
}

/// Validated secret state consumed exactly once to initialize a ratchet.
#[derive(Debug)]
pub struct AuthenticatedHandshake {
    session_id: [u8; 32],
    root_secret: Secret,
    role: RatchetRole,
    local_ratchet: DhKeyPair,
    remote_ratchet: DhPublicKey,
}

impl AuthenticatedHandshake {
    /// Returns the transcript-bound session identifier.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    pub(crate) fn into_ratchet_parts(self) -> ([u8; 32], Secret, RatchetRole, DhKeyPair, DhPublicKey) {
        (self.session_id, self.root_secret, self.role, self.local_ratchet, self.remote_ratchet)
    }
}

/// Starts a verified asynchronous prekey handshake as the initiating party.
///
/// The returned message must be delivered to the responder. The returned authenticated
/// material is consumed by [`crate::ratchet::RatchetState::from_authenticated_handshake`].
///
/// # Errors
///
/// Returns an authentication error for an invalid or expired bundle and propagates X25519 or
/// CSPRNG failures.
pub fn initiate(
    identity: &LocalIdentity,
    bundle: &ResponderPrekeyBundle,
    now_unix: u64,
) -> Result<(InitiatorHandshake, AuthenticatedHandshake)> {
    bundle.verify(now_unix)?;
    let ephemeral = DhKeyPair::generate()?;
    let ratchet = DhKeyPair::generate()?;
    let dh1 = identity.dh().diffie_hellman(bundle.signed_prekey.public())?;
    let dh2 = ephemeral.diffie_hellman(bundle.identity.dh_identity())?;
    let dh3 = ephemeral.diffie_hellman(bundle.signed_prekey.public())?;
    let dh4 = match bundle.one_time_prekey {
        Some(prekey) => Some(ephemeral.diffie_hellman(prekey.public())?),
        None => None,
    };
    let message = InitiatorHandshake {
        initiator_identity: identity.public(),
        initiator_ephemeral: ephemeral.public(),
        initiator_ratchet: ratchet.public(),
        signed_prekey_id: bundle.signed_prekey.key_id(),
        one_time_prekey_id: bundle.one_time_prekey.map(OneTimePrekeyPublic::id),
    };
    let (session_id, root_secret) =
        derive_handshake_values(&message, bundle.identity, &dh1, &dh2, &dh3, dh4.as_ref())?;
    Ok((
        message,
        AuthenticatedHandshake {
            session_id,
            root_secret,
            role: RatchetRole::Initiator,
            local_ratchet: ratchet,
            remote_ratchet: bundle.signed_prekey.public(),
        },
    ))
}

/// Validates and accepts an initiator message as the responder.
///
/// A matching one-time prekey is removed only after the complete message has been verified and
/// all handshake computations succeed.
///
/// # Errors
///
/// Returns an error for invalid identity binding, wrong prekey identifiers, low-order X25519
/// keys, or unavailable randomness.
pub fn accept(
    material: &mut ResponderPrekeyMaterial,
    message: &InitiatorHandshake,
) -> Result<AuthenticatedHandshake> {
    message.initiator_identity.verify()?;
    let signed_prekey = if message.signed_prekey_id == material.signed_record.key_id() {
        DhKeyPair::from_secret(crate::keys::DhSecretKey::from_bytes(material.signed_prekey.secret_bytes()))
    } else {
        let (_, key) = material
            .retired_signed_prekeys
            .iter()
            .find(|(record, _)| record.key_id() == message.signed_prekey_id)
            .ok_or(MefError::RatchetStateMismatch)?;
        DhKeyPair::from_secret(crate::keys::DhSecretKey::from_bytes(key.secret_bytes()))
    };
    let one_time_index = match message.one_time_prekey_id {
        Some(id) => Some(
            material
                .one_time_prekeys
                .iter()
                .position(|entry| entry.public.id == id)
                .ok_or(MefError::RatchetStateMismatch)?,
        ),
        None => None,
    };
    let dh1 = signed_prekey.diffie_hellman(message.initiator_identity.dh_identity())?;
    let dh2 = material.identity.dh().diffie_hellman(message.initiator_ephemeral)?;
    let dh3 = signed_prekey.diffie_hellman(message.initiator_ephemeral)?;
    let dh4 = match one_time_index {
        Some(index) => {
            Some(material.one_time_prekeys[index].key.diffie_hellman(message.initiator_ephemeral)?)
        }
        None => None,
    };
    let (session_id, root_secret) =
        derive_handshake_values(message, material.identity.public(), &dh1, &dh2, &dh3, dh4.as_ref())?;
    let local_ratchet = signed_prekey;
    if let Some(index) = one_time_index {
        let _consumed = material.one_time_prekeys.remove(index);
    }
    Ok(AuthenticatedHandshake {
        session_id,
        root_secret,
        role: RatchetRole::Responder,
        local_ratchet,
        remote_ratchet: message.initiator_ratchet,
    })
}

fn derive_handshake_values(
    message: &InitiatorHandshake,
    responder_identity: IdentityDhPublic,
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
) -> Result<([u8; 32], Secret)> {
    let message_wire = message.encode();
    let responder_wire = identity_public_wire(responder_identity);
    let session_id = blake3_id(SESSION_LABEL, &[&message_wire, &responder_wire])?;
    let mut material = Vec::with_capacity(128);
    material.extend_from_slice(dh1);
    material.extend_from_slice(dh2);
    material.extend_from_slice(dh3);
    if let Some(value) = dh4 {
        material.extend_from_slice(value);
    }
    let root_secret = derive_secret(&session_id, ROOT_LABEL, &material)?;
    Ok((session_id, root_secret))
}

fn identity_binding_transcript(dh: DhPublicKey) -> Vec<u8> {
    let mut output = Vec::with_capacity(IDENTITY_BINDING_LABEL.len() + 33);
    output.extend_from_slice(IDENTITY_BINDING_LABEL.as_bytes());
    output.push(0);
    output.extend_from_slice(&dh.to_bytes());
    output
}

fn identity_public_wire(identity: IdentityDhPublic) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(&identity.signing.to_bytes());
    output.extend_from_slice(&identity.dh.to_bytes());
    output.extend_from_slice(&identity.signature);
    output
}

fn copy_array<const N: usize>(source: &[u8]) -> Result<[u8; N]> {
    source.try_into().map_err(|_| MefError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::{InitiatorHandshake, ResponderPrekeyBundle, ResponderPrekeyMaterial, accept, initiate};
    use crate::{MefError, Result, ratchet::RatchetState};

    #[test]
    fn one_time_prekey_handshake_derives_matching_ratchet_material() -> Result<()> {
        let mut responder = ResponderPrekeyMaterial::generate(7, 2_000)?;
        responder.add_one_time_prekey(19)?;
        let bundle = ResponderPrekeyBundle::decode(&responder.bundle().encode())?;
        assert_eq!(bundle.one_time_prekey().map(|entry| entry.id()), Some(19));
        let initiator = super::LocalIdentity::generate()?;
        let (message, initiator_handshake) = initiate(&initiator, &bundle, 1_000)?;
        let responder_handshake = accept(&mut responder, &InitiatorHandshake::decode(&message.encode())?)?;
        assert_eq!(initiator_handshake.session_id(), responder_handshake.session_id());
        assert_eq!(responder.available_one_time_prekeys(), 0);
        let _initiator_state = RatchetState::from_authenticated_handshake(initiator_handshake)?;
        let _responder_state = RatchetState::from_authenticated_handshake(responder_handshake)?;
        Ok(())
    }

    #[test]
    fn tampered_identity_binding_is_rejected_before_one_time_prekey_consumption() -> Result<()> {
        let mut responder = ResponderPrekeyMaterial::generate(7, 2_000)?;
        responder.add_one_time_prekey(19)?;
        let initiator = super::LocalIdentity::generate()?;
        let (message, _) = initiate(&initiator, &responder.bundle(), 1_000)?;
        let mut wire = message.encode();
        wire[68] ^= 1;
        assert_eq!(super::InitiatorHandshake::decode(&wire), Err(MefError::AuthenticationFailed));
        assert_eq!(responder.available_one_time_prekeys(), 1);
        Ok(())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{LocalIdentity, ResponderPrekeyMaterial, accept, initiate};
    use crate::Result;

    #[test]
    fn retained_signed_prekey_accepts_delayed_initial_message() -> Result<()> {
        let initiator = LocalIdentity::generate()?;
        let mut responder = ResponderPrekeyMaterial::generate(7, 2_000)?;
        let (delayed, _) = initiate(&initiator, &responder.bundle(), 1_000)?;
        responder.rotate_signed_prekey(8, 3_000)?;
        let _accepted = accept(&mut responder, &delayed)?;
        responder.retire_signed_prekey(7)?;
        Ok(())
    }
}
