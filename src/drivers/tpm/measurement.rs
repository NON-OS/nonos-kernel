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
use spin::Mutex;
use super::constants::*;

#[derive(Debug, Clone)]
pub struct PcrMeasurement {
    pub pcr_index: u32,
    pub hash_alg: u16,
    pub digest: [u8; TPM_MAX_DIGEST_SIZE],
    pub digest_len: usize,
    pub event_type: u32,
    pub event_data: Vec<u8>,
}

impl PcrMeasurement {
    pub fn new(
        pcr_index: u32,
        hash_alg: u16,
        digest: &[u8],
        event_type: u32,
        event_data: Vec<u8>,
    ) -> Self {
        let mut digest_arr = [0u8; TPM_MAX_DIGEST_SIZE];
        let len = core::cmp::min(digest.len(), TPM_MAX_DIGEST_SIZE);
        digest_arr[..len].copy_from_slice(&digest[..len]);

        Self {
            pcr_index,
            hash_alg,
            digest: digest_arr,
            digest_len: len,
            event_type,
            event_data,
        }
    }

    pub fn digest_slice(&self) -> &[u8] {
        &self.digest[..self.digest_len]
    }

    pub fn digest_len_for_alg(hash_alg: u16) -> usize {
        match hash_alg {
            alg::TPM2_ALG_SHA1 => 20,
            alg::TPM2_ALG_SHA256 => 32,
            alg::TPM2_ALG_SHA384 => 48,
            alg::TPM2_ALG_SHA512 => 64,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentType {
    Bootloader,
    BootloaderConfig,
    KernelCode,
    KernelConfig,
    Module,
    ImaPolicy,
}

impl ComponentType {
    pub fn pcr_index(&self) -> u32 {
        match self {
            ComponentType::Bootloader => PCR_NONOS_BOOTLOADER,
            ComponentType::BootloaderConfig => PCR_NONOS_BOOTLOADER_CONFIG,
            ComponentType::KernelCode => PCR_NONOS_KERNEL,
            ComponentType::KernelConfig => PCR_NONOS_KERNEL_CONFIG,
            ComponentType::Module => PCR_NONOS_MODULES,
            ComponentType::ImaPolicy => PCR_NONOS_IMA,
        }
    }

    pub fn event_type(&self) -> u32 {
        match self {
            ComponentType::Bootloader | ComponentType::BootloaderConfig => EV_NONOS_KERNEL,
            ComponentType::KernelCode | ComponentType::KernelConfig => EV_NONOS_KERNEL,
            ComponentType::Module => EV_NONOS_MODULE,
            ComponentType::ImaPolicy => EV_NONOS_CONFIG,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ComponentType::Bootloader => "bootloader",
            ComponentType::BootloaderConfig => "bootloader-config",
            ComponentType::KernelCode => "kernel",
            ComponentType::KernelConfig => "kernel-config",
            ComponentType::Module => "module",
            ComponentType::ImaPolicy => "ima-policy",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BootChainMeasurements {
    pub bootloader_hash: Vec<u8>,
    pub kernel_hash: Vec<u8>,
}

impl BootChainMeasurements {
    pub fn new(bootloader_hash: Vec<u8>, kernel_hash: Vec<u8>) -> Self {
        Self {
            bootloader_hash,
            kernel_hash,
        }
    }

    pub fn from_slices(bootloader: &[u8], kernel: &[u8]) -> Self {
        Self {
            bootloader_hash: bootloader.to_vec(),
            kernel_hash: kernel.to_vec(),
        }
    }
}

pub(super) static MEASUREMENT_LOG: Mutex<Vec<PcrMeasurement>> = Mutex::new(Vec::new());

pub(super) fn log_measurement(measurement: PcrMeasurement) {
    MEASUREMENT_LOG.lock().push(measurement);
}

pub fn get_measurement_log() -> Vec<PcrMeasurement> {
    MEASUREMENT_LOG.lock().clone()
}

pub fn clear_measurement_log() {
    MEASUREMENT_LOG.lock().clear();
}

pub(super) fn measurement_count() -> usize {
    MEASUREMENT_LOG.lock().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_type_pcr_indices() {
        assert_eq!(ComponentType::Bootloader.pcr_index(), 4);
        assert_eq!(ComponentType::KernelCode.pcr_index(), 8);
        assert_eq!(ComponentType::Module.pcr_index(), 11);
    }

    #[test]
    fn test_digest_len_for_alg() {
        assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA1), 20);
        assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA256), 32);
        assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA512), 64);
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
        assert_eq!(measurement.digest_len, 32);
        assert_eq!(measurement.digest_slice(), &digest);
    }
}
