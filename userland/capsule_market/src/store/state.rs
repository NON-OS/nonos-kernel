// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! In-memory state of the most-recently accepted marketplace
//! index. Single-instance, single-writer, single-reader: the
//! capsule's IPC server runs one request at a time, so a plain
//! struct without locking is sufficient and the smaller surface
//! is easier to reason about.

extern crate alloc;

use alloc::vec::Vec;

use nonos_marketplace_abi::MarketplaceIndex;

pub struct Store {
    accepted: Option<Accepted>,
}

pub struct Accepted {
    pub index: MarketplaceIndex,
    /// `true` when the operator signature on this index verified
    /// against the configured verifier. Carried alongside the
    /// index so the install-readiness evaluator can answer
    /// without re-running crypto on every query.
    pub signature_verified: bool,
    pub publisher_signature_verified: Vec<bool>,
}

impl Store {
    pub const fn empty() -> Self {
        Self { accepted: None }
    }

    pub fn current(&self) -> Option<&Accepted> {
        self.accepted.as_ref()
    }

    pub fn last_serial(&self) -> u64 {
        self.accepted.as_ref().map(|a| a.index.serial).unwrap_or(0)
    }

    pub fn install(
        &mut self,
        index: MarketplaceIndex,
        signature_verified: bool,
        publisher_signature_verified: Vec<bool>,
    ) {
        self.accepted = Some(Accepted {
            index,
            signature_verified,
            publisher_signature_verified,
        });
    }
}

impl Accepted {
    pub fn publisher_signature_verified(&self, entry_index: usize, release_index: usize) -> bool {
        let mut flat_index = release_index;
        for entry in self.index.entries.iter().take(entry_index) {
            flat_index = flat_index.saturating_add(entry.releases.len());
        }
        self.publisher_signature_verified
            .get(flat_index)
            .copied()
            .unwrap_or(false)
    }
}
