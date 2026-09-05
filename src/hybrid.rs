// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Explicit hybrid X25519 plus ML-KEM-768 asynchronous handshake profile.
//!
//! This profile contributes both the classical authenticated prekey material and
//! an ML-KEM-768 shared secret to the session root. It is not claimed to be a
//! formally proven PQXDH composition.

use crate::{
    MefError, Result,
    crypto::blake3_id,
    handshake::{AuthenticatedHandshake, InitiatorHandshake, ResponderPrekeyBundle, ResponderPrekeyMaterial},
    pq::{MlKem768Ciphertext, MlKem768KeyPair, MlKem768PublicKey},
};

const MAGIC: [u8; 3] = *b"MEQ";
const VERSION: u8 = 1;
const TRANSCRIPT_LABEL: &str = "handshake-mlkem768-bundle-v1";

/// A responder bundle containing classical prekeys and an authenticated ML-KEM-768 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridResponderPrekeyBundle {
    classical: ResponderPrekeyBundle,
    pq_public: MlKem768PublicKey,
    pq_signature: [u8; 64],
}

impl HybridResponderPrekeyBundle {
    /// Returns the classical prekey bundle carried by this hybrid bundle.
    #[must_use]
    pub const fn classical(&self) -> &ResponderPrekeyBundle {
        &self.classical
    }

    /// Returns the responder ML-KEM-768 public key.
    #[must_use]
    pub const fn pq_public(&self) -> &MlKem768PublicKey {
        &self.pq_public
    }

    /// Encodes a canonical hybrid bundle for directory delivery.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let classical = self.classical.encode();
        let pq_public = self.pq_public.to_bytes();
        let mut output = Vec::with_capacity(3 + 1 + 2 + classical.len() + 2 + pq_public.len() + 64);
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&(classical.len() as u16).to_be_bytes());
        output.extend_from_slice(&classical);
        output.extend_from_slice(&(pq_public.len() as u16).to_be_bytes());
        output.extend_from_slice(&pq_public);
        output.extend_from_slice(&self.pq_signature);
        output
    }

    /// Decodes and verifies one complete canonical hybrid bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed encoding, invalid ML-KEM public material, or
    /// an invalid signature binding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || bytes[..3] != MAGIC || bytes[3] != VERSION {
            return Err(MefError::InvalidFrame);
        }
        let classical_len = usize::from(u16::from_be_bytes(copy_array(&bytes[4..6])?));
        let classical_start: usize = 6;
        let classical_end = classical_start.checked_add(classical_len).ok_or(MefError::InvalidLength)?;
        if bytes.len() < classical_end + 2 {
            return Err(MefError::InvalidFrame);
        }
        let classical = ResponderPrekeyBundle::decode(&bytes[classical_start..classical_end])?;
        let pq_len = usize::from(u16::from_be_bytes(copy_array(&bytes[classical_end..classical_end + 2])?));
        let pq_start = classical_end + 2;
        let pq_end = pq_start.checked_add(pq_len).ok_or(MefError::InvalidLength)?;
        let signature_end = pq_end.checked_add(64).ok_or(MefError::InvalidLength)?;
        if signature_end != bytes.len() {
            return Err(MefError::InvalidFrame);
        }
        let pq_public = MlKem768PublicKey::from_bytes(&bytes[pq_start..pq_end])?;
        let pq_signature = copy_array(&bytes[pq_end..signature_end])?;
        let transcript = binding_transcript(&classical, &pq_public)?;
        classical.identity().verify_signature(&transcript, &pq_signature)?;
        Ok(Self { classical, pq_public, pq_signature })
    }

    /// Verifies the classical bundle and ML-KEM public-key binding at a given time.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, expired, or unauthenticated bundle.
    pub fn verify(&self, now_unix: u64) -> Result<()> {
        self.classical.verify(now_unix)?;
        let transcript = binding_transcript(&self.classical, &self.pq_public)?;
        self.classical.identity().verify_signature(&transcript, &self.pq_signature)
    }
}

/// Responder-held private material for the hybrid handshake profile.
#[derive(Debug)]
pub struct HybridResponderPrekeyMaterial {
    classical: ResponderPrekeyMaterial,
    pq: MlKem768KeyPair,
}

impl HybridResponderPrekeyMaterial {
    /// Generates classical responder material and a native ML-KEM-768 key pair.
    pub fn generate(signed_prekey_id: u32, expires_at_unix: u64) -> Result<Self> {
        Ok(Self {
            classical: ResponderPrekeyMaterial::generate(signed_prekey_id, expires_at_unix)?,
            pq: MlKem768KeyPair::generate()?,
        })
    }

    /// Returns a signed hybrid prekey bundle for directory delivery.
    pub fn bundle(&self) -> Result<HybridResponderPrekeyBundle> {
        let classical = self.classical.bundle();
        let pq_public = self.pq.public_key();
        let transcript = binding_transcript(&classical, &pq_public)?;
        let pq_signature = self.classical.sign_message(&transcript);
        Ok(HybridResponderPrekeyBundle { classical, pq_public, pq_signature })
    }

    /// Adds a classical one-time prekey to the hybrid bundle.
    pub fn add_one_time_prekey(&mut self, id: u32) -> Result<()> {
        self.classical.add_one_time_prekey(id)
    }

    /// Returns the number of available classical one-time prekeys.
    #[must_use]
    pub fn available_one_time_prekeys(&self) -> usize {
        self.classical.available_one_time_prekeys()
    }

    /// Accepts a hybrid initiator message and derives the bound session material.
    pub fn accept(&mut self, message: &HybridInitiatorHandshake) -> Result<AuthenticatedHandshake> {
        let classical = crate::handshake::accept(&mut self.classical, &message.classical)?;
        let pq_shared = self.pq.decapsulate(&message.pq_ciphertext);
        classical.mix_ml_kem768(pq_shared.as_bytes())
    }
}

/// Canonical initiator message carrying classical prekey data and an ML-KEM ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridInitiatorHandshake {
    classical: InitiatorHandshake,
    pq_ciphertext: MlKem768Ciphertext,
}

impl HybridInitiatorHandshake {
    /// Returns the classical handshake message embedded in this hybrid message.
    #[must_use]
    pub const fn classical(&self) -> &InitiatorHandshake {
        &self.classical
    }

    /// Encodes one canonical hybrid initiator message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let classical = self.classical.encode();
        let ciphertext = self.pq_ciphertext.to_bytes();
        let mut output = Vec::with_capacity(3 + 1 + 2 + classical.len() + 2 + ciphertext.len());
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.extend_from_slice(&(classical.len() as u16).to_be_bytes());
        output.extend_from_slice(&classical);
        output.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        output.extend_from_slice(&ciphertext);
        output
    }

    /// Decodes one complete canonical hybrid initiator message.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed encoding or an invalid ML-KEM ciphertext length.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || bytes[..3] != MAGIC || bytes[3] != VERSION {
            return Err(MefError::InvalidFrame);
        }
        let classical_len = usize::from(u16::from_be_bytes(copy_array(&bytes[4..6])?));
        let classical_start: usize = 6;
        let classical_end = classical_start.checked_add(classical_len).ok_or(MefError::InvalidLength)?;
        if bytes.len() < classical_end + 2 {
            return Err(MefError::InvalidFrame);
        }
        let classical = InitiatorHandshake::decode(&bytes[classical_start..classical_end])?;
        let ciphertext_len =
            usize::from(u16::from_be_bytes(copy_array(&bytes[classical_end..classical_end + 2])?));
        let ciphertext_start = classical_end + 2;
        let ciphertext_end = ciphertext_start.checked_add(ciphertext_len).ok_or(MefError::InvalidLength)?;
        if ciphertext_end != bytes.len() {
            return Err(MefError::InvalidFrame);
        }
        let pq_ciphertext = MlKem768Ciphertext::from_bytes(&bytes[ciphertext_start..ciphertext_end])?;
        Ok(Self { classical, pq_ciphertext })
    }
}

/// Initiates a hybrid X25519 plus ML-KEM-768 prekey handshake.
pub fn initiate(
    identity: &crate::handshake::LocalIdentity,
    bundle: &HybridResponderPrekeyBundle,
    now_unix: u64,
) -> Result<(HybridInitiatorHandshake, AuthenticatedHandshake)> {
    bundle.verify(now_unix)?;
    let (classical, handshake) = crate::handshake::initiate(identity, bundle.classical(), now_unix)?;
    let (pq_ciphertext, pq_shared) = bundle.pq_public().encapsulate()?;
    let handshake = handshake.mix_ml_kem768(pq_shared.as_bytes())?;
    Ok((HybridInitiatorHandshake { classical, pq_ciphertext }, handshake))
}

fn binding_transcript(classical: &ResponderPrekeyBundle, pq_public: &MlKem768PublicKey) -> Result<Vec<u8>> {
    let classical_wire = classical.encode();
    let pq_wire = pq_public.to_bytes();
    let digest = blake3_id(TRANSCRIPT_LABEL, &[&classical_wire, &pq_wire])?;
    Ok(digest.to_vec())
}

fn copy_array<const N: usize>(source: &[u8]) -> Result<[u8; N]> {
    source.try_into().map_err(|_| MefError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::{
        HybridInitiatorHandshake, HybridResponderPrekeyBundle, HybridResponderPrekeyMaterial, initiate,
    };
    use crate::{Result, handshake::LocalIdentity, ratchet::RatchetState};

    #[test]
    fn hybrid_handshake_round_trips_and_binds_session() -> Result<()> {
        let mut responder = HybridResponderPrekeyMaterial::generate(7, 2_000)?;
        responder.add_one_time_prekey(19)?;
        let bundle = HybridResponderPrekeyBundle::decode(&responder.bundle()?.encode())?;
        let initiator = LocalIdentity::generate()?;
        let (message, initiator_handshake) = initiate(&initiator, &bundle, 1_000)?;
        let responder_handshake = responder.accept(&HybridInitiatorHandshake::decode(&message.encode())?)?;
        assert_eq!(initiator_handshake.session_id(), responder_handshake.session_id());
        assert_eq!(responder.available_one_time_prekeys(), 0);
        let _initiator_state = RatchetState::from_authenticated_handshake(initiator_handshake)?;
        let _responder_state = RatchetState::from_authenticated_handshake(responder_handshake)?;
        Ok(())
    }
}
