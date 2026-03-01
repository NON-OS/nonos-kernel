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

//! TPM 2.0 public API.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::constants::*;
use super::driver::TpmDriver;
use super::error::{TpmError, TpmResult};
use super::measurement::{
    log_measurement, measurement_count, BootChainMeasurements, ComponentType,
    PcrMeasurement,
};
use super::status::TpmStatus;

static TPM_DRIVER: Mutex<Option<TpmDriver>> = Mutex::new(None);
static TPM_AVAILABLE: AtomicBool = AtomicBool::new(false);

pub fn init_tpm() -> TpmResult<()> {
    let mut driver = TpmDriver::new();

    match driver.init() {
        Ok(()) => {
            TPM_AVAILABLE.store(true, Ordering::SeqCst);
            *TPM_DRIVER.lock() = Some(driver);
            Ok(())
        }
        Err(TpmError::NotPresent) => {
            crate::log_info!("[TPM] TPM not detected (platform may not have TPM)");
            Err(TpmError::NotPresent)
        }
        Err(e) => {
            crate::log_error!("[TPM] TPM initialization failed: {:?}", e);
            Err(e)
        }
    }
}

pub fn is_tpm_available() -> bool {
    TPM_AVAILABLE.load(Ordering::SeqCst)
}

pub fn extend_pcr_sha256(pcr_index: u32, data: &[u8]) -> TpmResult<()> {
    let guard = TPM_DRIVER.lock();
    let driver = guard.as_ref().ok_or(TpmError::NotInitialized)?;

    let digest = crate::crypto::hash::sha256(data);

    driver.pcr_extend(pcr_index, alg::TPM2_ALG_SHA256, &digest)?;

    let measurement = PcrMeasurement::new(
        pcr_index,
        alg::TPM2_ALG_SHA256,
        &digest,
        EV_NONOS_KERNEL,
        data.to_vec(),
    );
    log_measurement(measurement);

    crate::log_dbg!("[TPM] Extended PCR[{}] with SHA-256 digest", pcr_index);

    Ok(())
}

pub fn read_pcr(pcr_index: u32) -> TpmResult<Vec<u8>> {
    let guard = TPM_DRIVER.lock();
    let driver = guard.as_ref().ok_or(TpmError::NotInitialized)?;
    driver.pcr_read(pcr_index, alg::TPM2_ALG_SHA256)
}

pub fn get_random_bytes(count: u16) -> TpmResult<Vec<u8>> {
    let guard = TPM_DRIVER.lock();
    let driver = guard.as_ref().ok_or(TpmError::NotInitialized)?;
    driver.get_random(count)
}

pub fn measure_component(component_type: ComponentType, data: &[u8]) -> TpmResult<()> {
    extend_pcr_sha256(component_type.pcr_index(), data)
}

pub fn verify_boot_chain(expected: &BootChainMeasurements) -> TpmResult<bool> {
    if !is_tpm_available() {
        return Err(TpmError::NotPresent);
    }

    let pcr4 = read_pcr(PCR_NONOS_BOOTLOADER)?;
    let pcr8 = read_pcr(PCR_NONOS_KERNEL)?;

    let bootloader_ok = pcr4 == expected.bootloader_hash;
    let kernel_ok = pcr8 == expected.kernel_hash;

    if !bootloader_ok {
        crate::log_error!("[TPM] Bootloader measurement mismatch!");
    }
    if !kernel_ok {
        crate::log_error!("[TPM] Kernel measurement mismatch!");
    }

    Ok(bootloader_ok && kernel_ok)
}

pub fn get_tpm_status() -> TpmStatus {
    let guard = TPM_DRIVER.lock();
    match guard.as_ref() {
        Some(driver) => TpmStatus {
            present: true,
            initialized: driver.is_initialized(),
            manufacturer: driver.get_manufacturer(),
            version: driver.get_version(),
            locality: driver.get_locality(),
            measurement_count: measurement_count(),
        },
        None => TpmStatus::not_present(),
    }
}

pub fn shutdown_tpm(save_state: bool) -> TpmResult<()> {
    let guard = TPM_DRIVER.lock();
    let driver = guard.as_ref().ok_or(TpmError::NotInitialized)?;
    driver.shutdown(save_state)
}

pub fn measure_module(name: &str, code: &[u8]) -> TpmResult<()> {
    if !is_tpm_available() {
        return Ok(());
    }

    let mut hasher_input = Vec::with_capacity(name.len() + 1 + code.len());
    hasher_input.extend_from_slice(name.as_bytes());
    hasher_input.push(0);
    hasher_input.extend_from_slice(code);

    extend_pcr_sha256(PCR_NONOS_MODULES, &hasher_input)?;

    crate::log_info!("[TPM] Measured module '{}' ({} bytes)", name, code.len());

    Ok(())
}

pub fn measure_config_change(key: &str, value: &[u8]) -> TpmResult<()> {
    if !is_tpm_available() {
        return Ok(());
    }

    let mut data = Vec::with_capacity(key.len() + 1 + value.len());
    data.extend_from_slice(key.as_bytes());
    data.push(0);
    data.extend_from_slice(value);

    extend_pcr_sha256(PCR_NONOS_KERNEL_CONFIG, &data)
}

pub fn create_quote(pcr_selection: &[u32], nonce: &[u8]) -> TpmResult<Vec<u8>> {
    if !is_tpm_available() {
        return Err(TpmError::NotPresent);
    }

    if pcr_selection.is_empty() || pcr_selection.len() > TPM_NUM_PCRS {
        return Err(TpmError::InvalidParameter);
    }

    if nonce.len() > TPM_MAX_DIGEST_SIZE {
        return Err(TpmError::InvalidParameter);
    }

    let guard = TPM_DRIVER.lock();
    let driver = guard.as_ref().ok_or(TpmError::NotInitialized)?;
    driver.create_quote(pcr_selection, nonce)
}
