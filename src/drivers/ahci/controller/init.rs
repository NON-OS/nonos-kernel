// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! AHCI controller and port initialization.

use alloc::{vec::Vec, format, string::String, collections::BTreeMap};
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use crate::crypto::hash::sha256;

use super::super::error::AhciError;
use super::super::types::{AhciDevice, AhciDeviceType};
use super::super::dma::PortDma;
use super::super::constants::*;
use super::commands;
use super::io::{find_free_slot, wait_complete_or_error};
use super::helpers::RegisterAccess;

/// BIOS handoff.
pub fn bios_handoff<T: RegisterAccess>(ctrl: &T) -> Result<(), AhciError> {
    if (ctrl.read_hba_reg(HBA_CAP2) & 1) == 0 {
        return Ok(());
    }
    ctrl.write_hba_reg(HBA_BOHC, ctrl.read_hba_reg(HBA_BOHC) | (1 << 1));
    if !ctrl.wait_while(|| (ctrl.read_hba_reg(HBA_BOHC) & 1) != 0, 1_000_000) {
        return Err(AhciError::BiosHandoffTimeout);
    }
    Ok(())
}

/// Initialize HBA.
pub fn init_hba<T: RegisterAccess>(ctrl: &T) -> Result<u32, AhciError> {
    let cap = ctrl.read_hba_reg(HBA_CAP);
    let ports_impl = ctrl.read_hba_reg(HBA_PI);

    crate::log::logger::log_critical(&format!(
        "AHCI: CAP=0x{:08x}, PI=0x{:08x}",
        cap, ports_impl
    ));

    bios_handoff(ctrl)?;

    // Enable AHCI mode + reset
    let mut ghc = ctrl.read_hba_reg(HBA_GHC) | (1 << 31);
    ctrl.write_hba_reg(HBA_GHC, ghc);
    ghc |= 1;
    ctrl.write_hba_reg(HBA_GHC, ghc);

    if !ctrl.wait_while(|| (ctrl.read_hba_reg(HBA_GHC) & 1) != 0, 1_000_000) {
        return Err(AhciError::HbaResetTimeout);
    }

    // Re-enable AHCI mode
    ctrl.write_hba_reg(HBA_GHC, ctrl.read_hba_reg(HBA_GHC) | (1 << 31));

    Ok(ports_impl)
}

/// Enable interrupts.
pub fn enable_interrupts<T: RegisterAccess>(ctrl: &T) {
    ctrl.write_hba_reg(HBA_GHC, ctrl.read_hba_reg(HBA_GHC) | (1 << 1));
}

/// Stop a port.
pub fn stop_port<T: RegisterAccess>(ctrl: &T, port: u32) -> Result<(), AhciError> {
    let mut cmd = ctrl.read_port_reg(port, PORT_CMD) & !CMD_ST;
    ctrl.write_port_reg(port, PORT_CMD, cmd);

    if !ctrl.wait_while(|| (ctrl.read_port_reg(port, PORT_CMD) & CMD_CR) != 0, 1_000_000) {
        return Err(AhciError::PortCmdListStopTimeout);
    }

    cmd = ctrl.read_port_reg(port, PORT_CMD) & !CMD_FRE;
    ctrl.write_port_reg(port, PORT_CMD, cmd);

    if !ctrl.wait_while(|| (ctrl.read_port_reg(port, PORT_CMD) & CMD_FR) != 0, 1_000_000) {
        return Err(AhciError::PortFisStopTimeout);
    }
    Ok(())
}

/// Initialize a port.
pub fn init_port<T: RegisterAccess>(
    ctrl: &T,
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    ports: &RwLock<BTreeMap<u32, AhciDevice>>,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    encryption_enabled: &AtomicBool,
    command_timeout: u32,
    port: u32,
) -> Result<(), AhciError> {
    stop_port(ctrl, port)?;

    let pdma = PortDma::new()?;
    ctrl.write_port_reg(port, PORT_CLB, (pdma.cl_dma_pa.as_u64() & 0xFFFF_FFFF) as u32);
    ctrl.write_port_reg(port, PORT_CLBU, (pdma.cl_dma_pa.as_u64() >> 32) as u32);
    ctrl.write_port_reg(port, PORT_FB, (pdma.fis_dma_pa.as_u64() & 0xFFFF_FFFF) as u32);
    ctrl.write_port_reg(port, PORT_FBU, (pdma.fis_dma_pa.as_u64() >> 32) as u32);

    ctrl.write_port_reg(port, PORT_IS, 0xFFFF_FFFF);
    ctrl.write_port_reg(port, PORT_SERR, 0xFFFF_FFFF);

    let mut cmd = ctrl.read_port_reg(port, PORT_CMD) | CMD_FRE;
    ctrl.write_port_reg(port, PORT_CMD, cmd);
    cmd |= CMD_ST;
    ctrl.write_port_reg(port, PORT_CMD, cmd);

    let sig = ctrl.read_port_reg(port, PORT_SIG);
    let device_type = match AhciDeviceType::from_signature(sig) {
        Some(dt) => dt,
        None => {
            port_dma.lock().insert(port, pdma);
            return Ok(());
        }
    };

    crate::log::logger::log_critical(&format!(
        "AHCI Port {}: Device type {:?}",
        port, device_type
    ));

    port_dma.lock().insert(port, pdma);

    if device_type == AhciDeviceType::Sata {
        identify_device(ctrl, port_dma, ports, errors, port_resets, encryption_enabled, command_timeout, port)?;
    }

    Ok(())
}

/// Identify a SATA device.
pub fn identify_device<T: RegisterAccess>(
    ctrl: &T,
    port_dma: &Mutex<BTreeMap<u32, PortDma>>,
    ports: &RwLock<BTreeMap<u32, AhciDevice>>,
    errors: &AtomicU64,
    port_resets: &AtomicU64,
    encryption_enabled: &AtomicBool,
    command_timeout: u32,
    port: u32,
) -> Result<(), AhciError> {
    let buf_dma_region = alloc_dma_coherent(512, DmaConstraints {
        alignment: 2,
        max_segment_size: 512,
        dma32_only: false,
        coherent: true,
    }).map_err(|_| AhciError::DmaAllocationFailed)?;

    let (buf_va, buf_pa) = (buf_dma_region.virt_addr, buf_dma_region.phys_addr);
    unsafe { core::ptr::write_bytes(buf_va.as_mut_ptr::<u8>(), 0, 512); }

    let slot = find_free_slot(ctrl, port)?;
    commands::build_identify_command(port_dma, port, slot, buf_pa)?;
    ctrl.write_port_reg(port, PORT_CI, 1 << slot);
    wait_complete_or_error(ctrl, errors, port_resets, command_timeout, port, slot)?;

    let identify_data = unsafe { core::slice::from_raw_parts(buf_va.as_ptr::<u16>(), 256) };

    let sectors = if identify_data[83] & (1 << 10) != 0 {
        ((identify_data[103] as u64) << 48) |
        ((identify_data[102] as u64) << 32) |
        ((identify_data[101] as u64) << 16) |
        (identify_data[100] as u64)
    } else {
        ((identify_data[61] as u64) << 16) | (identify_data[60] as u64)
    };

    let model = extract_string(&identify_data[27..47]);
    let serial = extract_string(&identify_data[10..20]);
    let firmware = extract_string(&identify_data[23..27]);
    let supports_ncq = identify_data[76] & (1 << 8) != 0;
    let supports_trim = (identify_data[169] & (1 << 0)) != 0;
    let supports_security_erase = identify_data[128] & (1 << 0) != 0;

    let identify_bytes = unsafe { core::slice::from_raw_parts(buf_va.as_ptr::<u8>(), 512) };
    let identify_checksum = sha256(identify_bytes);
    let integrity_verified = verify_device_integrity(sectors, &model, &serial)?;

    let device = AhciDevice {
        port,
        device_type: AhciDeviceType::Sata,
        sectors,
        sector_size: 512,
        model: model.clone(),
        serial,
        firmware,
        supports_ncq,
        supports_trim,
        encrypted: encryption_enabled.load(Ordering::Relaxed),
        supports_security_erase,
        identify_checksum,
        integrity_verified,
        last_trim_timestamp: AtomicU64::new(0),
    };

    crate::log::logger::log_critical(&format!(
        "AHCI: Port {} - {} sectors, model {}, integrity={}, sec_erase={}",
        port, sectors, model, integrity_verified, supports_security_erase
    ));

    ports.write().insert(port, device);
    Ok(())
}

/// Extract ATA string from identify data.
fn extract_string(words: &[u16]) -> String {
    let mut result = Vec::new();
    for &word in words {
        let bytes = word.to_be_bytes();
        if bytes[0] != 0 { result.push(bytes[0]); }
        if bytes[1] != 0 { result.push(bytes[1]); }
    }
    String::from_utf8_lossy(&result).trim().into()
}

/// Verify device integrity.
fn verify_device_integrity(sectors: u64, model: &str, serial: &str) -> Result<bool, AhciError> {
    if sectors > MAX_DEVICE_SECTORS { return Ok(false); }
    if sectors == 0 { return Err(AhciError::ZeroSectorCapacity); }
    if model.is_empty() || serial.is_empty() { return Ok(false); }
    if !model.chars().all(|c| c.is_ascii()) || !serial.chars().all(|c| c.is_ascii()) { return Ok(false); }
    Ok(true)
}
