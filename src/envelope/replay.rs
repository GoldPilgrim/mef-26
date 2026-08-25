// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 GoldPilgrim <https://github.com/GoldPilgrim>
// This file is part of MEF-26.

//! Bounded recipient-side replay tracking for authenticated transport envelopes.

use super::TransportMessageId;
use crate::{MefError, Result};

/// Bounded in-memory replay cache keyed by authenticated transport message identifiers.
///
/// Persist this cache, or at least its durable high-water policy, alongside recipient delivery
/// state when replay rejection must survive process restart.
#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    entries: Vec<(TransportMessageId, u64)>,
}

impl ReplayCache {
    /// Creates an empty replay cache with a nonzero maximum entry count.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::InvalidLength`] for zero capacity.
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(MefError::InvalidLength);
        }
        Ok(Self { capacity, entries: Vec::new() })
    }

    /// Removes expired entries and records an authenticated transport identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MefError::ReplayDetected`] for a duplicate live identifier and
    /// [`MefError::InvalidState`] when callers must grow or persist the configured cache.
    pub fn check_and_insert(
        &mut self,
        message_id: TransportMessageId,
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<()> {
        self.entries.retain(|(_, expires_at)| *expires_at >= now_unix);
        if self.entries.iter().any(|(existing, _)| *existing == message_id) {
            return Err(MefError::ReplayDetected);
        }
        if self.entries.len() >= self.capacity {
            return Err(MefError::InvalidState);
        }
        self.entries.push((message_id, expires_at_unix));
        Ok(())
    }

    /// Returns the number of retained unexpired replay identifiers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no replay identifiers are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
