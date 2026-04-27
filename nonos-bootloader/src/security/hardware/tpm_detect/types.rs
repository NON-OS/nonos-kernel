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
pub struct TpmCapabilities {
    pub present: bool,
    pub version_2_0: bool,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision_id: u8,
    pub sha256_supported: bool,
    pub sha384_supported: bool,
    pub rsa_supported: bool,
    pub ecc_supported: bool,
    pub locality_count: u8,
}

impl TpmCapabilities {
    pub fn is_production_ready(&self) -> bool {
        self.present && self.version_2_0 && self.sha256_supported
    }

    pub fn supports_attestation(&self) -> bool {
        self.present && self.version_2_0 && (self.rsa_supported || self.ecc_supported)
    }
}
