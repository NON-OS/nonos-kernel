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

use crate::drivers::tpm::constants::*;
use crate::drivers::tpm::measurement::{BootChainMeasurements, ComponentType, PcrMeasurement};
use crate::test::framework::TestResult;
use alloc::vec;

pub(crate) fn test_component_type_bootloader_pcr() -> TestResult {
    if ComponentType::Bootloader.pcr_index() != PCR_NONOS_BOOTLOADER {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_bootloader_config_pcr() -> TestResult {
    if ComponentType::BootloaderConfig.pcr_index() != PCR_NONOS_BOOTLOADER_CONFIG {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_kernel_code_pcr() -> TestResult {
    if ComponentType::KernelCode.pcr_index() != PCR_NONOS_KERNEL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_kernel_config_pcr() -> TestResult {
    if ComponentType::KernelConfig.pcr_index() != PCR_NONOS_KERNEL_CONFIG {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_module_pcr() -> TestResult {
    if ComponentType::Module.pcr_index() != PCR_NONOS_MODULES {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_ima_policy_pcr() -> TestResult {
    if ComponentType::ImaPolicy.pcr_index() != PCR_NONOS_IMA {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_bootloader_event() -> TestResult {
    if ComponentType::Bootloader.event_type() != EV_NONOS_KERNEL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_kernel_event() -> TestResult {
    if ComponentType::KernelCode.event_type() != EV_NONOS_KERNEL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_module_event() -> TestResult {
    if ComponentType::Module.event_type() != EV_NONOS_MODULE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_ima_policy_event() -> TestResult {
    if ComponentType::ImaPolicy.event_type() != EV_NONOS_CONFIG {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_bootloader_str() -> TestResult {
    if ComponentType::Bootloader.as_str() != "bootloader" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_bootloader_config_str() -> TestResult {
    if ComponentType::BootloaderConfig.as_str() != "bootloader-config" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_kernel_code_str() -> TestResult {
    if ComponentType::KernelCode.as_str() != "kernel" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_kernel_config_str() -> TestResult {
    if ComponentType::KernelConfig.as_str() != "kernel-config" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_module_str() -> TestResult {
    if ComponentType::Module.as_str() != "module" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_ima_policy_str() -> TestResult {
    if ComponentType::ImaPolicy.as_str() != "ima-policy" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_equality() -> TestResult {
    if ComponentType::Bootloader != ComponentType::Bootloader {
        return TestResult::Fail;
    }
    if ComponentType::Bootloader == ComponentType::KernelCode {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_copy() -> TestResult {
    let c1 = ComponentType::Module;
    let c2 = c1;
    if c1 != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_component_type_clone() -> TestResult {
    let c1 = ComponentType::ImaPolicy;
    let c2 = c1.clone();
    if c1 != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_digest_len_sha1() -> TestResult {
    if PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA1) != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_digest_len_sha256() -> TestResult {
    if PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA256) != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_digest_len_sha384() -> TestResult {
    if PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA384) != 48 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_digest_len_sha512() -> TestResult {
    if PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA512) != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_digest_len_unknown() -> TestResult {
    if PcrMeasurement::digest_len_for_alg(0xFFFF) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_new() -> TestResult {
    let digest = [0xAB; 32];
    let measurement = PcrMeasurement::new(
        8,
        alg::TPM2_ALG_SHA256,
        &digest,
        EV_NONOS_KERNEL,
        vec![0x01, 0x02, 0x03],
    );
    if measurement.pcr_index != 8 {
        return TestResult::Fail;
    }
    if measurement.hash_alg != alg::TPM2_ALG_SHA256 {
        return TestResult::Fail;
    }
    if measurement.digest_len != 32 {
        return TestResult::Fail;
    }
    if measurement.event_type != EV_NONOS_KERNEL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_digest_slice() -> TestResult {
    let digest = [0xCD; 32];
    let measurement =
        PcrMeasurement::new(8, alg::TPM2_ALG_SHA256, &digest, EV_NONOS_KERNEL, vec![]);
    if measurement.digest_slice() != &digest {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_truncates_large_digest() -> TestResult {
    let large_digest = [0xEF; 128];
    let measurement =
        PcrMeasurement::new(8, alg::TPM2_ALG_SHA256, &large_digest, EV_NONOS_KERNEL, vec![]);
    if measurement.digest_len != TPM_MAX_DIGEST_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcr_measurement_clone() -> TestResult {
    let digest = [0x12; 32];
    let m1 = PcrMeasurement::new(4, alg::TPM2_ALG_SHA256, &digest, EV_NONOS_MODULE, vec![0x55]);
    let m2 = m1.clone();
    if m1.pcr_index != m2.pcr_index {
        return TestResult::Fail;
    }
    if m1.hash_alg != m2.hash_alg {
        return TestResult::Fail;
    }
    if m1.digest_slice() != m2.digest_slice() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_chain_measurements_new() -> TestResult {
    let bootloader = vec![0x11; 32];
    let kernel = vec![0x22; 32];
    let bcm = BootChainMeasurements::new(bootloader.clone(), kernel.clone());
    if bcm.bootloader_hash != bootloader {
        return TestResult::Fail;
    }
    if bcm.kernel_hash != kernel {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_chain_measurements_from_slices() -> TestResult {
    let bootloader = [0x33; 32];
    let kernel = [0x44; 32];
    let bcm = BootChainMeasurements::from_slices(&bootloader, &kernel);
    if bcm.bootloader_hash.len() != 32 {
        return TestResult::Fail;
    }
    if bcm.kernel_hash.len() != 32 {
        return TestResult::Fail;
    }
    if bcm.bootloader_hash[0] != 0x33 {
        return TestResult::Fail;
    }
    if bcm.kernel_hash[0] != 0x44 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_chain_measurements_clone() -> TestResult {
    let bcm1 = BootChainMeasurements::new(vec![0xAA], vec![0xBB]);
    let bcm2 = bcm1.clone();
    if bcm1.bootloader_hash != bcm2.bootloader_hash {
        return TestResult::Fail;
    }
    if bcm1.kernel_hash != bcm2.kernel_hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}
