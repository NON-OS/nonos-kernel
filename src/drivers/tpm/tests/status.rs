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
use crate::test::framework::TestResult;

pub(crate) fn test_tpm_status_not_present() -> TestResult {
    let status = TpmStatus::not_present();
    if status.present {
        return TestResult::Fail;
    }
    if status.initialized {
        return TestResult::Fail;
    }
    if status.manufacturer != 0 {
        return TestResult::Fail;
    }
    if status.version != 0 {
        return TestResult::Fail;
    }
    if status.locality != 0 {
        return TestResult::Fail;
    }
    if status.measurement_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_default() -> TestResult {
    let status = TpmStatus::default();
    if status.present {
        return TestResult::Fail;
    }
    if status.initialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_vendor_id() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x1234_5678,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.vendor_id() != 0x5678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_device_id() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x1234_5678,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.device_id() != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_manufacturer_intel() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_8086,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.manufacturer_name() != "Intel" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_manufacturer_amd() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_1022,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.manufacturer_name() != "AMD" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_manufacturer_ibm() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_1014,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.manufacturer_name() != "IBM" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_manufacturer_infineon() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_15D1,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.manufacturer_name() != "Infineon" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_manufacturer_nuvoton() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_1AE0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.manufacturer_name() != "Nuvoton" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_manufacturer_unknown() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x0000_FFFF,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.manufacturer_name() != "Unknown" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_is_usable_when_present_and_init() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if !status.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_not_usable_when_not_present() -> TestResult {
    let status = TpmStatus::not_present();
    if status.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_not_usable_when_not_initialized() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: false,
        manufacturer: 0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    if status.is_usable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_clone() -> TestResult {
    let status = TpmStatus {
        present: true,
        initialized: true,
        manufacturer: 0x8086,
        version: 0x0200,
        locality: 0,
        measurement_count: 5,
    };
    let cloned = status.clone();
    if status.present != cloned.present {
        return TestResult::Fail;
    }
    if status.manufacturer != cloned.manufacturer {
        return TestResult::Fail;
    }
    if status.measurement_count != cloned.measurement_count {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_display_not_present() -> TestResult {
    use core::fmt::Write;
    let status = TpmStatus::not_present();
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", status);
    if writer.as_str() != "TPM: not present" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tpm_status_display_not_initialized() -> TestResult {
    use core::fmt::Write;
    let status = TpmStatus {
        present: true,
        initialized: false,
        manufacturer: 0,
        version: 0,
        locality: 0,
        measurement_count: 0,
    };
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", status);
    if writer.as_str() != "TPM: present but not initialized" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_default() -> TestResult {
    let config = PcrBankConfig::default();
    if !config.sha1_enabled {
        return TestResult::Fail;
    }
    if !config.sha256_enabled {
        return TestResult::Fail;
    }
    if config.sha384_enabled {
        return TestResult::Fail;
    }
    if config.sha512_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_sha256_only() -> TestResult {
    let config = PcrBankConfig::sha256_only();
    if config.sha1_enabled {
        return TestResult::Fail;
    }
    if !config.sha256_enabled {
        return TestResult::Fail;
    }
    if config.sha384_enabled {
        return TestResult::Fail;
    }
    if config.sha512_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_none() -> TestResult {
    let config = PcrBankConfig::none();
    if config.sha1_enabled {
        return TestResult::Fail;
    }
    if config.sha256_enabled {
        return TestResult::Fail;
    }
    if config.sha384_enabled {
        return TestResult::Fail;
    }
    if config.sha512_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_enabled_count_default() -> TestResult {
    let config = PcrBankConfig::default();
    if config.enabled_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_enabled_count_sha256_only() -> TestResult {
    let config = PcrBankConfig::sha256_only();
    if config.enabled_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_enabled_count_none() -> TestResult {
    let config = PcrBankConfig::none();
    if config.enabled_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_enabled_count_all() -> TestResult {
    let config = PcrBankConfig {
        sha1_enabled: true,
        sha256_enabled: true,
        sha384_enabled: true,
        sha512_enabled: true,
    };
    if config.enabled_count() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_copy() -> TestResult {
    let c1 = PcrBankConfig::default();
    let c2 = c1;
    if c1.sha1_enabled != c2.sha1_enabled {
        return TestResult::Fail;
    }
    if c1.sha256_enabled != c2.sha256_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_bank_config_clone() -> TestResult {
    let c1 = PcrBankConfig::sha256_only();
    let c2 = c1.clone();
    if c1.sha1_enabled != c2.sha1_enabled {
        return TestResult::Fail;
    }
    if c1.sha256_enabled != c2.sha256_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}
