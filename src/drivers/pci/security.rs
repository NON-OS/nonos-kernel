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

//! PCI security policy and validation.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use super::constants::*;
use super::error::{PciError, Result, SecurityViolation};
use super::types::PciDevice;

static SECURITY_VIOLATIONS: AtomicU64 = AtomicU64::new(0);
static BLOCKED_WRITES: AtomicU64 = AtomicU64::new(0);
static ALLOWED_BUS_MASTERS: AtomicU64 = AtomicU64::new(0);
static DEVICE_BLOCKLIST: Mutex<Vec<(u16, u16)>> = Mutex::new(Vec::new());
static DEVICE_ALLOWLIST: Mutex<Option<Vec<(u16, u16)>>> = Mutex::new(None);
static BUS_MASTER_APPROVED: Mutex<Vec<(u8, u8, u8)>> = Mutex::new(Vec::new());

pub struct SecurityPolicy {
    pub allow_rom_writes: bool,
    pub allow_arbitrary_bus_master: bool,
    pub allow_interrupt_line_writes: bool,
    pub log_all_config_writes: bool,
    pub enforce_allowlist: bool,
    pub block_unknown_vendors: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_rom_writes: false,
            allow_arbitrary_bus_master: false,
            allow_interrupt_line_writes: true,
            log_all_config_writes: true,
            enforce_allowlist: false,
            block_unknown_vendors: false,
        }
    }
}

static POLICY: Mutex<SecurityPolicy> = Mutex::new(SecurityPolicy {
    allow_rom_writes: false,
    allow_arbitrary_bus_master: false,
    allow_interrupt_line_writes: true,
    log_all_config_writes: true,
    enforce_allowlist: false,
    block_unknown_vendors: false,
});

pub fn set_security_policy(policy: SecurityPolicy) {
    *POLICY.lock() = policy;
}

pub fn get_security_policy() -> SecurityPolicy {
    let p = POLICY.lock();
    SecurityPolicy {
        allow_rom_writes: p.allow_rom_writes,
        allow_arbitrary_bus_master: p.allow_arbitrary_bus_master,
        allow_interrupt_line_writes: p.allow_interrupt_line_writes,
        log_all_config_writes: p.log_all_config_writes,
        enforce_allowlist: p.enforce_allowlist,
        block_unknown_vendors: p.block_unknown_vendors,
    }
}

pub fn validate_config_write(
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    value: u32,
) -> Result<()> {
    let policy = POLICY.lock();

    if offset == CFG_VENDOR_ID || offset == CFG_DEVICE_ID {
        record_violation(SecurityViolation::VendorIdTampering);
        return Err(PciError::ReadOnlyRegister { offset });
    }

    if offset == CFG_CLASS_CODE || offset == CFG_SUBCLASS || offset == CFG_PROG_IF {
        record_violation(SecurityViolation::ClassCodeTampering);
        return Err(PciError::ReadOnlyRegister { offset });
    }

    if offset == CFG_EXPANSION_ROM_BASE && !policy.allow_rom_writes {
        record_violation(SecurityViolation::ExpansionRomBlocked);
        return Err(PciError::ProtectedRegister { offset });
    }

    if offset == CFG_COMMAND {
        let cmd_value = (value & 0xFFFF) as u16;

        if (cmd_value & CMD_BUS_MASTER) != 0 && !policy.allow_arbitrary_bus_master {
            if !is_bus_master_approved(bus, device, function) {
                record_violation(SecurityViolation::BusMasterWithoutApproval);
                return Err(PciError::SecurityViolation(
                    SecurityViolation::BusMasterWithoutApproval,
                ));
            }
        }
    }

    if offset == CFG_INTERRUPT_LINE && !policy.allow_interrupt_line_writes {
        record_violation(SecurityViolation::InterruptLineModification);
        return Err(PciError::ProtectedRegister { offset });
    }

    if (CFG_BAR0..=CFG_BAR5).contains(&offset) {
        if !is_bus_master_approved(bus, device, function) {
            record_violation(SecurityViolation::BarProgrammingBlocked);
        }
    }

    Ok(())
}

fn is_bus_master_approved(bus: u8, device: u8, function: u8) -> bool {
    let approved = BUS_MASTER_APPROVED.lock();
    approved.iter().any(|(b, d, f)| *b == bus && *d == device && *f == function)
}

pub fn approve_bus_master(bus: u8, device: u8, function: u8) {
    let mut approved = BUS_MASTER_APPROVED.lock();
    if !approved.iter().any(|(b, d, f)| *b == bus && *d == device && *f == function) {
        approved.push((bus, device, function));
        ALLOWED_BUS_MASTERS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn revoke_bus_master(bus: u8, device: u8, function: u8) {
    let mut approved = BUS_MASTER_APPROVED.lock();
    approved.retain(|(b, d, f)| !(*b == bus && *d == device && *f == function));
}

pub fn clear_bus_master_approvals() {
    BUS_MASTER_APPROVED.lock().clear();
}

fn record_violation(_violation: SecurityViolation) {
    SECURITY_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    BLOCKED_WRITES.fetch_add(1, Ordering::Relaxed);
}

pub fn check_device_allowed(vendor_id: u16, device_id: u16) -> Result<()> {
    let blocklist = DEVICE_BLOCKLIST.lock();
    if blocklist.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
        return Err(PciError::DeviceBlocked {
            vendor: vendor_id,
            device: device_id,
        });
    }
    drop(blocklist);

    let allowlist = DEVICE_ALLOWLIST.lock();
    if let Some(ref list) = *allowlist {
        if !list.is_empty() && !list.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
            return Err(PciError::DeviceNotAllowed {
                vendor: vendor_id,
                device: device_id,
            });
        }
    }

    Ok(())
}

pub fn add_to_blocklist(vendor_id: u16, device_id: u16) {
    let mut blocklist = DEVICE_BLOCKLIST.lock();
    if !blocklist.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
        blocklist.push((vendor_id, device_id));
    }
}

pub fn remove_from_blocklist(vendor_id: u16, device_id: u16) {
    let mut blocklist = DEVICE_BLOCKLIST.lock();
    blocklist.retain(|(v, d)| !(*v == vendor_id && *d == device_id));
}

pub fn clear_blocklist() {
    DEVICE_BLOCKLIST.lock().clear();
}

pub fn set_allowlist(list: Option<Vec<(u16, u16)>>) {
    *DEVICE_ALLOWLIST.lock() = list;
}

pub fn add_to_allowlist(vendor_id: u16, device_id: u16) {
    let mut allowlist = DEVICE_ALLOWLIST.lock();
    let list = allowlist.get_or_insert_with(Vec::new);
    if !list.iter().any(|(v, d)| *v == vendor_id && *d == device_id) {
        list.push((vendor_id, device_id));
    }
}

pub fn clear_allowlist() {
    *DEVICE_ALLOWLIST.lock() = None;
}

pub fn is_dma_capable(device: &PciDevice) -> bool {
    match device.class() {
        CLASS_BRIDGE => false,
        CLASS_BASE_PERIPHERAL => device.subclass() != 0x05,
        _ => true,
    }
}

pub fn is_security_relevant(device: &PciDevice) -> bool {
    match (device.class(), device.subclass()) {
        (CLASS_SERIAL_BUS, SUBCLASS_SERIAL_USB) => true,
        (CLASS_NETWORK, _) => true,
        (CLASS_MASS_STORAGE, _) => true,
        (CLASS_DISPLAY, _) => true,
        (CLASS_WIRELESS, _) => true,
        _ => false,
    }
}

pub fn device_security_level(device: &PciDevice) -> SecurityLevel {
    if !is_dma_capable(device) {
        return SecurityLevel::Low;
    }

    match (device.class(), device.subclass()) {
        (CLASS_SERIAL_BUS, SUBCLASS_SERIAL_USB) => SecurityLevel::High,
        (CLASS_NETWORK, _) => SecurityLevel::High,
        (CLASS_MASS_STORAGE, SUBCLASS_STORAGE_NVM) => SecurityLevel::High,
        (CLASS_MASS_STORAGE, _) => SecurityLevel::Medium,
        (CLASS_DISPLAY, _) => SecurityLevel::Medium,
        (CLASS_WIRELESS, _) => SecurityLevel::Critical,
        (CLASS_ENCRYPTION, _) => SecurityLevel::Critical,
        _ => SecurityLevel::Low,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub struct SecurityStats {
    pub violations: u64,
    pub blocked_writes: u64,
    pub allowed_bus_masters: u64,
    pub blocklist_size: usize,
    pub allowlist_size: Option<usize>,
}

pub fn get_security_stats() -> SecurityStats {
    let blocklist_size = DEVICE_BLOCKLIST.lock().len();
    let allowlist_size = DEVICE_ALLOWLIST.lock().as_ref().map(|l| l.len());

    SecurityStats {
        violations: SECURITY_VIOLATIONS.load(Ordering::Relaxed),
        blocked_writes: BLOCKED_WRITES.load(Ordering::Relaxed),
        allowed_bus_masters: ALLOWED_BUS_MASTERS.load(Ordering::Relaxed),
        blocklist_size,
        allowlist_size,
    }
}

pub fn reset_security_stats() {
    SECURITY_VIOLATIONS.store(0, Ordering::Relaxed);
    BLOCKED_WRITES.store(0, Ordering::Relaxed);
}

pub struct DeviceAuditInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub dma_capable: bool,
    pub security_level: SecurityLevel,
    pub bus_master_approved: bool,
    pub msi_capable: bool,
    pub msix_capable: bool,
}

pub fn audit_device(device: &PciDevice) -> DeviceAuditInfo {
    DeviceAuditInfo {
        vendor_id: device.vendor_id(),
        device_id: device.device_id_value(),
        class: device.class(),
        subclass: device.subclass(),
        dma_capable: is_dma_capable(device),
        security_level: device_security_level(device),
        bus_master_approved: is_bus_master_approved(
            device.bus(),
            device.device(),
            device.function(),
        ),
        msi_capable: device.supports_msi(),
        msix_capable: device.supports_msix(),
    }
}

pub fn validate_device_for_driver(device: &PciDevice) -> Result<()> {
    check_device_allowed(device.vendor_id(), device.device_id_value())?;

    Ok(())
}

pub fn prepare_device_for_dma(device: &PciDevice) -> Result<()> {
    validate_device_for_driver(device)?;

    approve_bus_master(device.bus(), device.device(), device.function());

    Ok(())
}

pub fn verify_bar_not_protected(address: u64, size: u64) -> Result<()> {
    use super::error::ProtectedRegion;

    if address < MIN_MMIO_ADDRESS {
        return Err(PciError::BarOverlapsProtected {
            address,
            region: ProtectedRegion::LegacyBios,
        });
    }

    let apic_base = 0xFEE0_0000u64;
    let apic_end = 0xFEE0_1000u64;
    let end = address.saturating_add(size);
    if address < apic_end && end > apic_base {
        return Err(PciError::BarOverlapsProtected {
            address,
            region: ProtectedRegion::LocalApicMmio,
        });
    }

    let ioapic_base = 0xFEC0_0000u64;
    let ioapic_end = 0xFED0_0000u64;
    if address < ioapic_end && end > ioapic_base {
        return Err(PciError::BarOverlapsProtected {
            address,
            region: ProtectedRegion::IoapicMmio,
        });
    }

    Ok(())
}
