// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryProtection {
    pub dep_enabled: bool,
    pub aslr_supported: bool,
    pub sme_available: bool,
    pub sev_available: bool,
    pub tme_available: bool,
    pub physical_bits: u8,
    pub linear_bits: u8,
}

impl MemoryProtection {
    pub fn supports_encryption(&self) -> bool {
        self.sme_available || self.sev_available || self.tme_available
    }

    pub fn is_hardened(&self) -> bool {
        self.dep_enabled && self.aslr_supported
    }
}
