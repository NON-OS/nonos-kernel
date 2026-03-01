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

extern crate alloc;

use alloc::vec::Vec;

use crate::capabilities::types::Capability;

#[derive(Debug, Clone)]
pub struct MultiSigToken {
    pub owner_module: u64,
    pub permissions: Vec<Capability>,
    pub expires_at_ms: Option<u64>,
    pub nonce: u64,
    pub threshold: usize,
    pub authorized_signers: Vec<u64>,
    pub(super) signatures: Vec<(u64, [u8; 32])>,
}

impl MultiSigToken {
    #[inline]
    pub fn is_expired(&self) -> bool {
        match self.expires_at_ms {
            Some(exp) => crate::time::timestamp_millis() >= exp,
            None => false,
        }
    }

    #[inline]
    pub fn grants(&self, cap: Capability) -> bool {
        self.permissions.iter().any(|c| *c == cap)
    }

    #[inline]
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    #[inline]
    pub fn threshold_met(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    #[inline]
    pub fn signatures_needed(&self) -> usize {
        self.threshold.saturating_sub(self.signatures.len())
    }

    pub fn has_signed(&self, signer_id: u64) -> bool {
        self.signatures.iter().any(|(id, _)| *id == signer_id)
    }

    pub fn is_authorized(&self, signer_id: u64) -> bool {
        self.authorized_signers.contains(&signer_id)
    }

    pub fn signed_by(&self) -> Vec<u64> {
        self.signatures.iter().map(|(id, _)| *id).collect()
    }

    pub fn pending_signers(&self) -> Vec<u64> {
        self.authorized_signers
            .iter()
            .filter(|id| !self.has_signed(**id))
            .copied()
            .collect()
    }

    pub fn remaining_ms(&self) -> Option<u64> {
        self.expires_at_ms
            .map(|exp| exp.saturating_sub(crate::time::timestamp_millis()))
    }

    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }

    pub fn signer_count(&self) -> usize {
        self.authorized_signers.len()
    }
}

impl core::fmt::Display for MultiSigToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MultiSig[owner:{} caps:{} sigs:{}/{} auth:{}]",
            self.owner_module,
            self.permissions.len(),
            self.signatures.len(),
            self.threshold,
            self.authorized_signers.len()
        )
    }
}
