// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Fallible operating-system CSPRNG access.

use getrandom::{SysRng, rand_core::TryRng};

use crate::{MefError, Result};

/// Fills a caller-owned buffer from the operating-system CSPRNG.
///
/// # Errors
///
/// Returns [`MefError::RandomnessUnavailable`] if the system CSPRNG fails.
pub(crate) fn fill_secure(destination: &mut [u8]) -> Result<()> {
    let mut rng = SysRng;
    rng.try_fill_bytes(destination).map_err(|_| MefError::RandomnessUnavailable)
}

/// Generates a fixed-size byte array using the operating-system CSPRNG.
///
/// # Errors
///
/// Returns [`MefError::RandomnessUnavailable`] if the system CSPRNG fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    fill_secure(&mut bytes)?;
    Ok(bytes)
}
