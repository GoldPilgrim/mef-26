// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! X25519 and Ed25519 key wrappers used by MEF-26.

mod dh;
mod identity;
mod prekey;

pub use dh::{DhKeyPair, DhPublicKey, DhSecretKey};
pub use identity::{IdentityKeyPair, IdentityPublicKey};
pub use prekey::{SignedPrekey, identity_fingerprint};

pub(crate) const SIGNATURE_LEN: usize = 64;

#[cfg(test)]
mod tests {
    use super::{DhKeyPair, DhPublicKey, IdentityKeyPair, SignedPrekey, identity_fingerprint};
    use crate::{MefError, Result};

    #[test]
    fn x25519_agreement_is_symmetric() -> Result<()> {
        let alice = DhKeyPair::generate()?;
        let bob = DhKeyPair::generate()?;
        assert_eq!(alice.diffie_hellman(bob.public())?, bob.diffie_hellman(alice.public())?);
        Ok(())
    }

    #[test]
    fn non_contributory_x25519_input_is_rejected() -> Result<()> {
        let pair = DhKeyPair::generate()?;
        assert_eq!(
            pair.diffie_hellman(DhPublicKey::from_bytes([0_u8; 32])),
            Err(MefError::NonContributoryKeyAgreement)
        );
        Ok(())
    }

    #[test]
    fn signed_prekey_requires_correct_identity_and_freshness() -> Result<()> {
        let identity = IdentityKeyPair::generate()?;
        let other_identity = IdentityKeyPair::generate()?;
        let prekey = DhKeyPair::generate()?;
        let record = SignedPrekey::issue(&identity, 17, prekey.public(), 1_800_000_000);
        assert_eq!(record.verify(identity.public(), 1_700_000_000), Ok(()));
        assert_eq!(
            record.verify(other_identity.public(), 1_700_000_000),
            Err(MefError::AuthenticationFailed)
        );
        assert_eq!(record.verify(identity.public(), 1_900_000_000), Err(MefError::AuthenticationFailed));
        Ok(())
    }

    #[test]
    fn identity_fingerprint_changes_with_key() -> Result<()> {
        let first = IdentityKeyPair::generate()?;
        let second = IdentityKeyPair::generate()?;
        assert_ne!(identity_fingerprint(first.public())?, identity_fingerprint(second.public())?);
        Ok(())
    }
}
