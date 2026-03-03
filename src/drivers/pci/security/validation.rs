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

use core::sync::atomic::{AtomicU64, Ordering};

use super::super::constants::*;
use super::super::error::{PciError, ProtectedRegion, Result, SecurityViolation};
use super::approval::{is_bus_master_approved, BUS_MASTER_APPROVED};
use super::policy::POLICY;

pub(super) static SECURITY_VIOLATIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static BLOCKED_WRITES: AtomicU64 = AtomicU64::new(0);

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

pub(super) fn record_violation(_violation: SecurityViolation) {
    SECURITY_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    BLOCKED_WRITES.fetch_add(1, Ordering::Relaxed);
}

pub fn verify_bar_not_protected(address: u64, size: u64) -> Result<()> {
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
