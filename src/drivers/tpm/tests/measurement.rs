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

use alloc::vec;
use crate::drivers::tpm::constants::*;
use crate::drivers::tpm::measurement::{BootChainMeasurements, ComponentType, PcrMeasurement};

#[test]
fn test_component_type_bootloader_pcr() {
    assert_eq!(ComponentType::Bootloader.pcr_index(), PCR_NONOS_BOOTLOADER);
}

#[test]
fn test_component_type_bootloader_config_pcr() {
    assert_eq!(ComponentType::BootloaderConfig.pcr_index(), PCR_NONOS_BOOTLOADER_CONFIG);
}

#[test]
fn test_component_type_kernel_code_pcr() {
    assert_eq!(ComponentType::KernelCode.pcr_index(), PCR_NONOS_KERNEL);
}

#[test]
fn test_component_type_kernel_config_pcr() {
    assert_eq!(ComponentType::KernelConfig.pcr_index(), PCR_NONOS_KERNEL_CONFIG);
}

#[test]
fn test_component_type_module_pcr() {
    assert_eq!(ComponentType::Module.pcr_index(), PCR_NONOS_MODULES);
}

#[test]
fn test_component_type_ima_policy_pcr() {
    assert_eq!(ComponentType::ImaPolicy.pcr_index(), PCR_NONOS_IMA);
}

#[test]
fn test_component_type_bootloader_event() {
    assert_eq!(ComponentType::Bootloader.event_type(), EV_NONOS_KERNEL);
}

#[test]
fn test_component_type_kernel_event() {
    assert_eq!(ComponentType::KernelCode.event_type(), EV_NONOS_KERNEL);
}

#[test]
fn test_component_type_module_event() {
    assert_eq!(ComponentType::Module.event_type(), EV_NONOS_MODULE);
}

#[test]
fn test_component_type_ima_policy_event() {
    assert_eq!(ComponentType::ImaPolicy.event_type(), EV_NONOS_CONFIG);
}

#[test]
fn test_component_type_bootloader_str() {
    assert_eq!(ComponentType::Bootloader.as_str(), "bootloader");
}

#[test]
fn test_component_type_bootloader_config_str() {
    assert_eq!(ComponentType::BootloaderConfig.as_str(), "bootloader-config");
}

#[test]
fn test_component_type_kernel_code_str() {
    assert_eq!(ComponentType::KernelCode.as_str(), "kernel");
}

#[test]
fn test_component_type_kernel_config_str() {
    assert_eq!(ComponentType::KernelConfig.as_str(), "kernel-config");
}

#[test]
fn test_component_type_module_str() {
    assert_eq!(ComponentType::Module.as_str(), "module");
}

#[test]
fn test_component_type_ima_policy_str() {
    assert_eq!(ComponentType::ImaPolicy.as_str(), "ima-policy");
}

#[test]
fn test_component_type_equality() {
    assert_eq!(ComponentType::Bootloader, ComponentType::Bootloader);
    assert_ne!(ComponentType::Bootloader, ComponentType::KernelCode);
}

#[test]
fn test_component_type_copy() {
    let c1 = ComponentType::Module;
    let c2 = c1;
    assert_eq!(c1, c2);
}

#[test]
fn test_component_type_clone() {
    let c1 = ComponentType::ImaPolicy;
    let c2 = c1.clone();
    assert_eq!(c1, c2);
}

#[test]
fn test_pcr_measurement_digest_len_sha1() {
    assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA1), 20);
}

#[test]
fn test_pcr_measurement_digest_len_sha256() {
    assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA256), 32);
}

#[test]
fn test_pcr_measurement_digest_len_sha384() {
    assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA384), 48);
}

#[test]
fn test_pcr_measurement_digest_len_sha512() {
    assert_eq!(PcrMeasurement::digest_len_for_alg(alg::TPM2_ALG_SHA512), 64);
}

#[test]
fn test_pcr_measurement_digest_len_unknown() {
    assert_eq!(PcrMeasurement::digest_len_for_alg(0xFFFF), 0);
}

#[test]
fn test_pcr_measurement_new() {
    let digest = [0xAB; 32];
    let measurement = PcrMeasurement::new(
        8,
        alg::TPM2_ALG_SHA256,
        &digest,
        EV_NONOS_KERNEL,
        vec![0x01, 0x02, 0x03],
    );
    assert_eq!(measurement.pcr_index, 8);
    assert_eq!(measurement.hash_alg, alg::TPM2_ALG_SHA256);
    assert_eq!(measurement.digest_len, 32);
    assert_eq!(measurement.event_type, EV_NONOS_KERNEL);
}

#[test]
fn test_pcr_measurement_digest_slice() {
    let digest = [0xCD; 32];
    let measurement = PcrMeasurement::new(
        8,
        alg::TPM2_ALG_SHA256,
        &digest,
        EV_NONOS_KERNEL,
        vec![],
    );
    assert_eq!(measurement.digest_slice(), &digest);
}

#[test]
fn test_pcr_measurement_truncates_large_digest() {
    let large_digest = [0xEF; 128];
    let measurement = PcrMeasurement::new(
        8,
        alg::TPM2_ALG_SHA256,
        &large_digest,
        EV_NONOS_KERNEL,
        vec![],
    );
    assert_eq!(measurement.digest_len, TPM_MAX_DIGEST_SIZE);
}

#[test]
fn test_pcr_measurement_clone() {
    let digest = [0x12; 32];
    let m1 = PcrMeasurement::new(
        4,
        alg::TPM2_ALG_SHA256,
        &digest,
        EV_NONOS_MODULE,
        vec![0x55],
    );
    let m2 = m1.clone();
    assert_eq!(m1.pcr_index, m2.pcr_index);
    assert_eq!(m1.hash_alg, m2.hash_alg);
    assert_eq!(m1.digest_slice(), m2.digest_slice());
}

#[test]
fn test_boot_chain_measurements_new() {
    let bootloader = vec![0x11; 32];
    let kernel = vec![0x22; 32];
    let bcm = BootChainMeasurements::new(bootloader.clone(), kernel.clone());
    assert_eq!(bcm.bootloader_hash, bootloader);
    assert_eq!(bcm.kernel_hash, kernel);
}

#[test]
fn test_boot_chain_measurements_from_slices() {
    let bootloader = [0x33; 32];
    let kernel = [0x44; 32];
    let bcm = BootChainMeasurements::from_slices(&bootloader, &kernel);
    assert_eq!(bcm.bootloader_hash.len(), 32);
    assert_eq!(bcm.kernel_hash.len(), 32);
    assert_eq!(bcm.bootloader_hash[0], 0x33);
    assert_eq!(bcm.kernel_hash[0], 0x44);
}

#[test]
fn test_boot_chain_measurements_clone() {
    let bcm1 = BootChainMeasurements::new(vec![0xAA], vec![0xBB]);
    let bcm2 = bcm1.clone();
    assert_eq!(bcm1.bootloader_hash, bcm2.bootloader_hash);
    assert_eq!(bcm1.kernel_hash, bcm2.kernel_hash);
}
