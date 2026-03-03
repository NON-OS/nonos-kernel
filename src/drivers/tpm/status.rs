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


use core::fmt;

#[derive(Debug, Clone)]
pub struct TpmStatus {
    pub present: bool,
    pub initialized: bool,
    pub manufacturer: u32,
    pub version: u32,
    pub locality: u8,
    pub measurement_count: usize,
}

impl TpmStatus {
    pub fn not_present() -> Self {
        Self {
            present: false,
            initialized: false,
            manufacturer: 0,
            version: 0,
            locality: 0,
            measurement_count: 0,
        }
    }

    pub fn vendor_id(&self) -> u16 {
        (self.manufacturer & 0xFFFF) as u16
    }

    pub fn device_id(&self) -> u16 {
        ((self.manufacturer >> 16) & 0xFFFF) as u16
    }

    pub fn manufacturer_name(&self) -> &'static str {
        match self.vendor_id() {
            0x1014 => "IBM",
            0x104A => "STMicroelectronics",
            0x1050 => "Winbond",
            0x1095 => "Silicon Image",
            0x1180 => "Ricoh",
            0x15D1 => "Infineon",
            0x1022 => "AMD",
            0x8086 => "Intel",
            0x1AE0 => "Nuvoton",
            0x19FA => "Nationz",
            0x1B4E => "Atmel",
            _ => "Unknown",
        }
    }

    pub fn is_usable(&self) -> bool {
        self.present && self.initialized
    }
}

impl Default for TpmStatus {
    fn default() -> Self {
        Self::not_present()
    }
}

impl fmt::Display for TpmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.present {
            write!(f, "TPM: not present")
        } else if !self.initialized {
            write!(f, "TPM: present but not initialized")
        } else {
            write!(
                f,
                "TPM: {} (0x{:04X}:{:04X}) v{}.{} locality {} measurements={}",
                self.manufacturer_name(),
                self.vendor_id(),
                self.device_id(),
                (self.version >> 8) & 0xFF,
                self.version & 0xFF,
                self.locality,
                self.measurement_count
            )
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PcrBankConfig {
    pub sha1_enabled: bool,
    pub sha256_enabled: bool,
    pub sha384_enabled: bool,
    pub sha512_enabled: bool,
}

impl Default for PcrBankConfig {
    fn default() -> Self {
        Self {
            sha1_enabled: true,
            sha256_enabled: true,
            sha384_enabled: false,
            sha512_enabled: false,
        }
    }
}

impl PcrBankConfig {
    pub fn sha256_only() -> Self {
        Self {
            sha1_enabled: false,
            sha256_enabled: true,
            sha384_enabled: false,
            sha512_enabled: false,
        }
    }

    pub fn none() -> Self {
        Self {
            sha1_enabled: false,
            sha256_enabled: false,
            sha384_enabled: false,
            sha512_enabled: false,
        }
    }

    pub fn enabled_count(&self) -> usize {
        let mut count = 0;
        if self.sha1_enabled { count += 1; }
        if self.sha256_enabled { count += 1; }
        if self.sha384_enabled { count += 1; }
        if self.sha512_enabled { count += 1; }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_status_not_present() {
        let status = TpmStatus::not_present();
        assert!(!status.present);
        assert!(!status.initialized);
        assert!(!status.is_usable());
    }

    #[test]
    fn test_tpm_status_manufacturer() {
        let status = TpmStatus {
            present: true,
            initialized: true,
            manufacturer: 0x1234_8086,  // Intel
            version: 0,
            locality: 0,
            measurement_count: 0,
        };
        assert_eq!(status.vendor_id(), 0x8086);
        assert_eq!(status.device_id(), 0x1234);
        assert_eq!(status.manufacturer_name(), "Intel");
    }

    #[test]
    fn test_pcr_bank_config_default() {
        let config = PcrBankConfig::default();
        assert!(config.sha1_enabled);
        assert!(config.sha256_enabled);
        assert!(!config.sha384_enabled);
        assert_eq!(config.enabled_count(), 2);
    }

    #[test]
    fn test_pcr_bank_config_sha256_only() {
        let config = PcrBankConfig::sha256_only();
        assert!(!config.sha1_enabled);
        assert!(config.sha256_enabled);
        assert_eq!(config.enabled_count(), 1);
    }
}
