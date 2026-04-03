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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    Development,
    Standard,
    Hardened,
    SafeMode,
    NetworkIsolated,
    Recovery,
}

impl SecurityMode {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Development => "Development",
            Self::Standard => "Standard",
            Self::Hardened => "Hardened",
            Self::SafeMode => "Safe Mode",
            Self::NetworkIsolated => "Air-Gapped",
            Self::Recovery => "Recovery",
        }
    }

    pub const fn description(&self) -> &'static str {
        match self {
            Self::Development => "Unsigned kernel allowed, all security checks disabled",
            Self::Standard => "Signed kernel required, standard security enforced",
            Self::Hardened => "Full verification chain required, maximum security",
            Self::SafeMode => "Minimal drivers, reduced features, diagnostic mode",
            Self::NetworkIsolated => "Network stack disabled, air-gapped operation",
            Self::Recovery => "Recovery environment for system repair",
        }
    }

    pub const fn requires_signature(&self) -> bool {
        match self {
            Self::Development => false,
            Self::Standard | Self::Hardened | Self::SafeMode | Self::NetworkIsolated | Self::Recovery => true,
        }
    }

    pub const fn requires_secure_boot(&self) -> bool {
        match self {
            Self::Development | Self::Standard | Self::SafeMode | Self::Recovery => false,
            Self::Hardened | Self::NetworkIsolated => true,
        }
    }

    pub const fn requires_tpm(&self) -> bool {
        match self {
            Self::Development | Self::Standard | Self::SafeMode | Self::Recovery => false,
            Self::Hardened | Self::NetworkIsolated => true,
        }
    }

    pub const fn network_enabled(&self) -> bool {
        match self {
            Self::NetworkIsolated => false,
            _ => true,
        }
    }

    pub const fn minimal_drivers(&self) -> bool {
        match self {
            Self::SafeMode | Self::Recovery => true,
            _ => false,
        }
    }

    pub const fn boot_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.network_enabled() { flags |= 0x01; }
        if !self.minimal_drivers() { flags |= 0x02; }
        if self.requires_signature() { flags |= 0x04; }
        if self.requires_secure_boot() { flags |= 0x08; }
        if self.requires_tpm() { flags |= 0x10; }
        flags
    }
}

impl Default for SecurityMode {
    fn default() -> Self {
        Self::Standard
    }
}
