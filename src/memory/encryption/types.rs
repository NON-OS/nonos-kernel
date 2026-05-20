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

use core::sync::atomic::{AtomicBool, AtomicU64};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemEncryption {
    None,
    AmdSme,
    AmdSev,
    IntelTme,
    IntelMktme,
    Pending(u8),
}

#[derive(Debug, Clone, Copy)]
pub struct EncryptionCapability {
    pub sme_supported: bool,
    pub sev_supported: bool,
    pub tme_supported: bool,
    pub mktme_supported: bool,
    pub c_bit_position: u8,
    pub phys_addr_reduction: u8,
    pub keyid_bits: u8,
}

impl EncryptionCapability {
    pub const fn none() -> Self {
        Self {
            sme_supported: false,
            sev_supported: false,
            tme_supported: false,
            mktme_supported: false,
            c_bit_position: 0,
            phys_addr_reduction: 0,
            keyid_bits: 0,
        }
    }

    pub fn best_available(&self) -> MemEncryption {
        if self.sev_supported {
            MemEncryption::AmdSev
        } else if self.sme_supported {
            MemEncryption::AmdSme
        } else if self.mktme_supported {
            MemEncryption::IntelMktme
        } else if self.tme_supported {
            MemEncryption::IntelTme
        } else {
            MemEncryption::None
        }
    }
}

pub struct EncryptionStatus {
    pub enabled: AtomicBool,
    pub encryption_type: MemEncryption,
    pub c_bit_mask: AtomicU64,
    pub pages_encrypted: AtomicU64,
}

impl EncryptionStatus {
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            encryption_type: MemEncryption::None,
            c_bit_mask: AtomicU64::new(0),
            pages_encrypted: AtomicU64::new(0),
        }
    }
}
