// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Optional ML-KEM-768 primitive adapter.
//!
//! This module wraps the FIPS 203 ML-KEM-768 primitive. It deliberately does
//! not claim that any higher-level handshake composition is PQXDH-compatible;
//! that composition requires its own protocol review and test vectors.

use getrandom::{SysRng, rand_core::TryRng};
use kem::{Decapsulate, Generate};
use ml_kem::{
    B32,
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{MefError, Result};

const SHARED_KEY_LEN: usize = 32;

/// An ML-KEM-768 encapsulation public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKem768PublicKey(EncapsulationKey);

/// An ML-KEM-768 ciphertext carrying an encapsulated shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKem768Ciphertext(Ciphertext);

/// A 32-byte ML-KEM-768 shared secret that zeroizes when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret([u8; SHARED_KEY_LEN]);

impl MlKem768SharedSecret {
    /// Returns a copy for test-only equality verification without exposing production key material.
    #[cfg(test)]
    pub(crate) const fn copy_bytes(&self) -> [u8; SHARED_KEY_LEN] {
        self.0
    }
}

impl core::fmt::Debug for MlKem768SharedSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MlKem768SharedSecret([REDACTED])")
    }
}

/// A locally held ML-KEM-768 decapsulation key plus its public encapsulation key.
pub struct MlKem768KeyPair {
    secret: DecapsulationKey,
    public: MlKem768PublicKey,
}

impl MlKem768KeyPair {
    /// Generates a key pair using fallible operating-system randomness.
    pub fn generate() -> Result<Self> {
        let mut rng = SysRng;
        let secret =
            DecapsulationKey::try_generate_from_rng(&mut rng).map_err(|_| MefError::RandomnessUnavailable)?;
        let public = MlKem768PublicKey(secret.encapsulation_key().clone());
        Ok(Self { secret, public })
    }

    /// Returns the public encapsulation key.
    pub fn public(&self) -> MlKem768PublicKey {
        self.public.clone()
    }

    /// Decapsulates a shared secret from an ML-KEM-768 ciphertext.
    pub fn decapsulate(&self, ciphertext: &MlKem768Ciphertext) -> MlKem768SharedSecret {
        shared_secret_from_slice(self.secret.decapsulate(&ciphertext.0).as_slice())
    }
}

impl core::fmt::Debug for MlKem768KeyPair {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MlKem768KeyPair([REDACTED])")
    }
}

impl MlKem768PublicKey {
    /// Encapsulates a fresh 32-byte secret using fallible operating-system randomness.
    pub fn encapsulate(&self) -> Result<(MlKem768Ciphertext, MlKem768SharedSecret)> {
        let mut randomness = B32::default();
        let mut rng = SysRng;
        rng.try_fill_bytes(randomness.as_mut_slice()).map_err(|_| MefError::RandomnessUnavailable)?;
        let (ciphertext, shared) = self.0.encapsulate_deterministic(&randomness);
        randomness.as_mut_slice().zeroize();
        Ok((MlKem768Ciphertext(ciphertext), shared_secret_from_slice(shared.as_slice())))
    }
}

fn shared_secret_from_slice(bytes: &[u8]) -> MlKem768SharedSecret {
    let mut output = [0_u8; SHARED_KEY_LEN];
    output.copy_from_slice(bytes);
    MlKem768SharedSecret(output)
}

#[cfg(test)]
mod tests {
    use super::MlKem768KeyPair;
    use crate::crypto::ct_eq;

    #[test]
    fn ml_kem_768_round_trips_and_randomizes_ciphertexts() {
        let keypair = MlKem768KeyPair::generate();
        assert!(keypair.is_ok());
        if let Ok(keypair) = keypair {
            let public = keypair.public();
            let first = public.encapsulate();
            let second = public.encapsulate();
            assert!(first.is_ok());
            assert!(second.is_ok());
            if let (Some((first_ciphertext, first_secret)), Some((second_ciphertext, second_secret))) =
                (first.ok(), second.ok())
            {
                let first_received = keypair.decapsulate(&first_ciphertext);
                let second_received = keypair.decapsulate(&second_ciphertext);
                assert!(ct_eq(&first_secret.copy_bytes(), &first_received.copy_bytes()));
                assert!(ct_eq(&second_secret.copy_bytes(), &second_received.copy_bytes()));
                assert!(!ct_eq(&first_secret.copy_bytes(), &second_secret.copy_bytes()));
            }
        }
    }
}
