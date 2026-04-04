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

use crate::drivers::tpm::status::{PcrBankConfig, TpmStatus};

#[test]
fn test_tpm_status_not_present() {
    let status = TpmStatus::not_present();
    assert!(!status.present);
    assert!(!status.initialized);
    assert_eq!(status.manufacturer, 0);
    assert_eq!(status.version, 0);
    assert_eq!(status.locality, 0);
    assert_eq!(status.measurement_count, 0);
}

#[test]
fn test_tpm_status_default() {
    let status = TpmStatus::default();
    assert!(!status.present);
    assert!(!status.initialized);
}

#[test]
fn test_tpm_status_vendor_id() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x1234_5678,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.vendor_id(), 0x5678);
}

#[test]
fn test_tpm_status_device_id() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x1234_5678,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.device_id(), 0x1234);
}

#[test]
fn test_tpm_status_manufacturer_intel() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_8086,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.manufacturer_name(), "Intel");
}

#[test]
fn test_tpm_status_manufacturer_amd() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_1022,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.manufacturer_name(), "AMD");
}

#[test]
fn test_tpm_status_manufacturer_ibm() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_1014,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.manufacturer_name(), "IBM");
}

#[test]
fn test_tpm_status_manufacturer_infineon() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_15D1,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.manufacturer_name(), "Infineon");
}

#[test]
fn test_tpm_status_manufacturer_nuvoton() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_1AE0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.manufacturer_name(), "Nuvoton");
}

#[test]
fn test_tpm_status_manufacturer_unknown() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_FFFF,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert_eq!(status.manufacturer_name(), "Unknown");
}

#[test]
fn test_tpm_status_is_usable_when_present_and_init() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert!(status.is_usable());
}

#[test]
fn test_tpm_status_not_usable_when_not_present() {
    let status = TpmStatus::not_present();
    assert!(!status.is_usable());
}

#[test]
fn test_tpm_status_not_usable_when_not_initialized() {
    let status = TpmStatus {
        present: true,
        initialized: false,
        manufacturer: 0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    assert!(!status.is_usable());
}

#[test]
fn test_tpm_status_clone() {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x8086,
        version: 0x0200,
        locality: 0,
        measurement_count: 5,
    };
    let cloned = status.clone();
    assert_eq!(status.present, cloned.present);
    assert_eq!(status.manufacturer, cloned.manufacturer);
    assert_eq!(status.measurement_count, cloned.measurement_count);
}

#[test]
fn test_tpm_status_display_not_present() {
    let status = TpmStatus::not_present();
    let display = format!("{}", status);
    assert_eq!(display, "TPM: not present");
}

#[test]
fn test_tpm_status_display_not_initialized() {
    let status = TpmStatus {
        present: true,
        initialized: false,
        manufacturer: 0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    let display = format!("{}", status);
    assert_eq!(display, "TPM: present but not initialized");
}

#[test]
fn test_pcr_bank_config_default() {
    let config = PcrBankConfig::default();
    assert!(config.sha1_enabled);
    assert!(config.sha256_enabled);
    assert!(!config.sha384_enabled);
    assert!(!config.sha512_enabled);
}

#[test]
fn test_pcr_bank_config_sha256_only() {
    let config = PcrBankConfig::sha256_only();
    assert!(!config.sha1_enabled);
    assert!(config.sha256_enabled);
    assert!(!config.sha384_enabled);
    assert!(!config.sha512_enabled);
}

#[test]
fn test_pcr_bank_config_none() {
    let config = PcrBankConfig::none();
    assert!(!config.sha1_enabled);
    assert!(!config.sha256_enabled);
    assert!(!config.sha384_enabled);
    assert!(!config.sha512_enabled);
}

#[test]
fn test_pcr_bank_config_enabled_count_default() {
    let config = PcrBankConfig::default();
    assert_eq!(config.enabled_count(), 2);
}

#[test]
fn test_pcr_bank_config_enabled_count_sha256_only() {
    let config = PcrBankConfig::sha256_only();
    assert_eq!(config.enabled_count(), 1);
}

#[test]
fn test_pcr_bank_config_enabled_count_none() {
    let config = PcrBankConfig::none();
    assert_eq!(config.enabled_count(), 0);
}

#[test]
fn test_pcr_bank_config_enabled_count_all() {
    let config = PcrBankConfig {
        sha1_enabled: true,
        sha256_enabled: true,
        sha384_enabled: true,
        sha512_enabled: true,
    };
    assert_eq!(config.enabled_count(), 4);
}

#[test]
fn test_pcr_bank_config_copy() {
    let c1 = PcrBankConfig::default();
    let c2 = c1;
    assert_eq!(c1.sha1_enabled, c2.sha1_enabled);
    assert_eq!(c1.sha256_enabled, c2.sha256_enabled);
}

#[test]
fn test_pcr_bank_config_clone() {
    let c1 = PcrBankConfig::sha256_only();
    let c2 = c1.clone();
    assert_eq!(c1.sha1_enabled, c2.sha1_enabled);
    assert_eq!(c1.sha256_enabled, c2.sha256_enabled);
}
