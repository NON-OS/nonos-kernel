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


#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn test_error_as_str() {
        assert_eq!(TpmError::NotPresent.as_str(), "TPM not present");
        assert_eq!(TpmError::Timeout.as_str(), "TPM operation timed out");
        assert_eq!(TpmError::NotInitialized.as_str(), "TPM not initialized");
    }

    #[test]
    fn test_error_response_code() {
        let err = TpmError::CommandFailed(0x123);
        assert_eq!(err.response_code(), Some(0x123));
        assert_eq!(TpmError::Timeout.response_code(), None);
    }

    #[test]
    fn test_error_is_recoverable() {
        assert!(TpmError::Timeout.is_recoverable());
        assert!(TpmError::BufferTooSmall.is_recoverable());
        assert!(!TpmError::NotPresent.is_recoverable());
        assert!(!TpmError::HardwareError.is_recoverable());
    }

    #[test]
    fn test_error_is_fatal() {
        assert!(TpmError::NotPresent.is_fatal());
        assert!(TpmError::HardwareError.is_fatal());
        assert!(!TpmError::Timeout.is_fatal());
    }

    #[test]
    fn test_tpm_status_not_present() {
        let status = TpmStatus::not_present();
        assert!(!status.present);
        assert!(!status.initialized);
        assert!(!status.is_usable());
    }

    #[test]
    fn test_tpm_status_manufacturer_parsing() {
        let status = TpmStatus {
            present: true,
            initialized: true,
            manufacturer: 0x1234_8086, // Intel
            version: 0x0102,
            locality: 0,
            measurement_count: 5,
        };
        assert_eq!(status.vendor_id(), 0x8086);
        assert_eq!(status.device_id(), 0x1234);
        assert_eq!(status.manufacturer_name(), "Intel");
        assert!(status.is_usable());
    }

    #[test]
    fn test_tpm_status_unknown_manufacturer() {
        let status = TpmStatus {
            present: true,
            initialized: true,
            manufacturer: 0x0000_DEAD,
            version: 0,
            locality: 0,
            measurement_count: 0,
        };
        assert_eq!(status.manufacturer_name(), "Unknown");
    }

    #[test]
    fn test_pcr_bank_config_default() {
        let config = PcrBankConfig::default();
        assert!(config.sha1_enabled);
        assert!(config.sha256_enabled);
        assert!(!config.sha384_enabled);
        assert!(!config.sha512_enabled);
        assert_eq!(config.enabled_count(), 2);
    }

    #[test]
    fn test_pcr_bank_config_sha256_only() {
        let config = PcrBankConfig::sha256_only();
        assert!(!config.sha1_enabled);
        assert!(config.sha256_enabled);
        assert!(!config.sha384_enabled);
        assert!(!config.sha512_enabled);
        assert_eq!(config.enabled_count(), 1);
    }

    #[test]
    fn test_component_type_pcr_indices() {
        assert_eq!(ComponentType::Bootloader.pcr_index(), 4);
        assert_eq!(ComponentType::BootloaderConfig.pcr_index(), 5);
        assert_eq!(ComponentType::KernelCode.pcr_index(), 8);
        assert_eq!(ComponentType::KernelConfig.pcr_index(), 9);
        assert_eq!(ComponentType::ImaPolicy.pcr_index(), 10);
        assert_eq!(ComponentType::Module.pcr_index(), 11);
    }

    #[test]
    fn test_component_type_as_str() {
        assert_eq!(ComponentType::Bootloader.as_str(), "bootloader");
        assert_eq!(ComponentType::KernelCode.as_str(), "kernel");
        assert_eq!(ComponentType::Module.as_str(), "module");
    }

    #[test]
    fn test_pcr_measurement_creation() {
        let digest = [0xABu8; 32];
        let measurement = PcrMeasurement::new(
            8,
            alg::TPM2_ALG_SHA256,
            &digest,
            EV_NONOS_KERNEL,
            b"test".to_vec(),
        );

        assert_eq!(measurement.pcr_index, 8);
        assert_eq!(measurement.hash_alg, alg::TPM2_ALG_SHA256);
        assert_eq!(measurement.digest_len, 32);
        assert_eq!(measurement.digest_slice(), &digest);
        assert_eq!(measurement.event_type, EV_NONOS_KERNEL);
    }

    #[test]
    fn test_digest_len_for_alg() {
        assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA1), 20);
        assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA256), 32);
        assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA384), 48);
        assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA512), 64);
        assert_eq!(PcrMeasurement::digest_len_for_alg(0xFFFF), 0);
    }

    #[test]
    fn test_boot_chain_measurements() {
        let bootloader = vec![0x11u8; 32];
        let kernel = vec![0x22u8; 32];
        let measurements = BootChainMeasurements::new(bootloader.clone(), kernel.clone());

        assert_eq!(measurements.bootloader_hash, bootloader);
        assert_eq!(measurements.kernel_hash, kernel);
    }

    #[test]
    fn test_locality_addresses() {
        assert_eq!(TPM_LOCALITY_0, 0xFED4_0000);
        assert_eq!(TPM_LOCALITY_1, 0xFED4_1000);
        assert_eq!(TPM_LOCALITY_2, 0xFED4_2000);
        assert_eq!(TPM_LOCALITY_3, 0xFED4_3000);
        assert_eq!(TPM_LOCALITY_4, 0xFED4_4000);
    }

    #[test]
    fn test_pcr_ranges() {
        assert_eq!(PCR_BIOS_START, 0);
        assert_eq!(PCR_BIOS_END, 7);
        assert_eq!(PCR_OS_START, 8);
        assert_eq!(PCR_OS_END, 15);
    }

    #[test]
    fn test_command_codes() {
        assert_eq!(commands::TPM2_CC_STARTUP, 0x0000_0144);
        assert_eq!(commands::TPM2_CC_PCR_EXTEND, 0x0000_0182);
        assert_eq!(commands::TPM2_CC_GET_RANDOM, 0x0000_017B);
    }

    #[test]
    fn test_algorithm_ids() {
        assert_eq!(alg::TPM2_ALG_SHA1, 0x0004);
        assert_eq!(alg::TPM2_ALG_SHA256, 0x000B);
        assert_eq!(alg::TPM2_ALG_SHA384, 0x000C);
        assert_eq!(alg::TPM2_ALG_SHA512, 0x000D);
    }

    #[test]
    fn test_parse_response_code_success() {
        let info = error::parse_response_code(0);
        assert!(!info.is_error);
        assert_eq!(info.raw, 0);
    }

    #[test]
    fn test_parse_response_code_error() {
        let info = error::parse_response_code(0x100);
        assert!(info.is_error);
        assert!(!info.is_tpm2_format);
    }

    #[test]
    fn test_parse_response_code_tpm2_format() {
        let info = error::parse_response_code(0x80);
        assert!(info.is_error);
        assert!(info.is_tpm2_format);
    }
}
