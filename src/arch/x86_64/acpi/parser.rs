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

//! ACPI table discovery and parsing.
//!
//! Handles RSDP discovery, root table parsing, and individual table parsing.

use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use alloc::collections::BTreeMap;
use spin::RwLock;

use super::error::{AcpiError, AcpiResult};
use super::tables::*;
use super::data::*;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static TABLES: RwLock<Option<TableRegistry>> = RwLock::new(None);
static STATS: RwLock<AcpiStats> = RwLock::new(AcpiStats::new());
/// Discovered tables: signature -> physical address
struct TableRegistry {
    tables: BTreeMap<u32, u64>,
    data: AcpiData,
}

pub fn init() -> AcpiResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(AcpiError::AlreadyInitialized);
    }

    let rsdp = find_rsdp()?;
    let mut registry = TableRegistry {
        tables: BTreeMap::new(),
        data: AcpiData::new(),
    };

    registry.data.revision = rsdp.base.revision;
    registry.data.oem_id = rsdp.base.oem_id;

    // Parse root table (prefer XSDT over RSDT)
    if rsdp.has_xsdt() {
        parse_xsdt(&mut registry, rsdp.xsdt_address)?;
    } else if rsdp.rsdt_address() != 0 {
        parse_rsdt(&mut registry, rsdp.rsdt_address() as u64)?;
    } else {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(AcpiError::NoRootTable);
    }

    // Parse individual tables
    parse_fadt(&mut registry)?;
    parse_madt(&mut registry);
    parse_hpet(&mut registry);
    parse_mcfg(&mut registry);
    parse_srat(&mut registry);

    // Update statistics
    {
        let mut stats = STATS.write();
        stats.tables_found = registry.tables.len() as u32;
        stats.processors_found = registry.data.processors.len() as u32;
        stats.ioapics_found = registry.data.ioapics.len() as u32;
        stats.overrides_found = registry.data.overrides.len() as u32;
        stats.pcie_segments = registry.data.pcie_segments.len() as u32;

        let mut nodes: alloc::collections::BTreeSet<u32> = alloc::collections::BTreeSet::new();
        for region in &registry.data.numa_regions {
            nodes.insert(region.proximity_domain);
        }
        stats.numa_nodes = nodes.len() as u32;
    }

    // Store registry
    *TABLES.write() = Some(registry);

    Ok(())
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

fn find_rsdp() -> AcpiResult<RsdpExtended> {
    // SAFETY: Search EBDA first
    unsafe {
        let ebda_segment = ptr::read_volatile(rsdp::EBDA_PTR_ADDR as *const u16);
        if ebda_segment != 0 {
            let ebda_start = (ebda_segment as usize) << 4;
            if let Some(rsdp) = search_rsdp_range(ebda_start, 1024) {
                return Ok(rsdp);
            }
        }
    }

    if let Some(rsdp) = search_rsdp_range(rsdp::BIOS_ROM_START, rsdp::BIOS_ROM_SIZE) {
        return Ok(rsdp);
    }

    Err(AcpiError::RsdpNotFound)
}

/// Search for RSDP in a memory range
fn search_rsdp_range(start: usize, length: usize) -> Option<RsdpExtended> {
    for addr in (start..start + length).step_by(rsdp::RSDP_ALIGNMENT) {
        unsafe {
            let ptr = addr as *const Rsdp;
            let sig = ptr::read_volatile(&(*ptr).signature);

            if sig == rsdp::RSDP_SIGNATURE {
                let rsdp = ptr::read_volatile(ptr);
                if !rsdp.validate_checksum() {
                    continue;
                }

                if rsdp.is_acpi2() {
                    let ext_ptr = addr as *const RsdpExtended;
                    let ext_rsdp = ptr::read_volatile(ext_ptr);
                    if ext_rsdp.validate_extended_checksum() {
                        return Some(ext_rsdp);
                    }
                } else {
                    // ACPI 1.0
                    return Some(RsdpExtended::from_rsdp(rsdp));
                }
            }
        }
    }
    None
}

fn parse_rsdt(registry: &mut TableRegistry, addr: u64) -> AcpiResult<()> {
    unsafe {
        let header = ptr::read_volatile(addr as *const SdtHeader);

        if header.signature != SIG_RSDT {
            return Err(AcpiError::InvalidRsdtSignature);
        }

        if !header.validate_checksum(addr as *const u8) {
            return Err(AcpiError::RsdtChecksumFailed);
        }

        let entry_count = (header.length as usize - mem::size_of::<SdtHeader>()) / 4;
        let entries_ptr = (addr as usize + mem::size_of::<SdtHeader>()) as *const u32;

        for i in 0..entry_count {
            let entry_addr = ptr::read_volatile(entries_ptr.add(i)) as u64;
            if entry_addr != 0 {
                let table_header = ptr::read_volatile(entry_addr as *const SdtHeader);
                registry.tables.insert(table_header.signature, entry_addr);
            }
        }
    }

    Ok(())
}

fn parse_xsdt(registry: &mut TableRegistry, addr: u64) -> AcpiResult<()> {
    unsafe {
        let header = ptr::read_volatile(addr as *const SdtHeader);

        if header.signature != SIG_XSDT {
            return Err(AcpiError::InvalidXsdtSignature);
        }

        if !header.validate_checksum(addr as *const u8) {
            return Err(AcpiError::XsdtChecksumFailed);
        }

        let entry_count = (header.length as usize - mem::size_of::<SdtHeader>()) / 8;
        let entries_ptr = (addr as usize + mem::size_of::<SdtHeader>()) as *const u64;

        for i in 0..entry_count {
            let entry_addr = ptr::read_volatile(entries_ptr.add(i));
            if entry_addr != 0 {
                let table_header = ptr::read_volatile(entry_addr as *const SdtHeader);
                registry.tables.insert(table_header.signature, entry_addr);
            }
        }
    }

    Ok(())
}

fn parse_fadt(registry: &mut TableRegistry) -> AcpiResult<()> {
    let addr = *registry.tables.get(&SIG_FADT).ok_or(AcpiError::FadtNotFound)?;

    unsafe {
        let fadt = ptr::read_volatile(addr as *const Fadt);

        registry.data.pm1a_control = fadt.pm1a_control_block;
        registry.data.pm1b_control = fadt.pm1b_control_block;
        registry.data.pm_profile = fadt.pm_profile();
        registry.data.sci_interrupt = fadt.sci_interrupt;

        if fadt.has_reset_register() {
            registry.data.reset_reg = Some(fadt.reset_reg);
            registry.data.reset_value = fadt.reset_value;
        }
      
        registry.data.slp_typ[5] = 0;
    }

    Ok(())
}

/// Parse MADT
fn parse_madt(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_MADT) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let madt = ptr::read_volatile(addr as *const Madt);

        registry.data.lapic_address = madt.local_apic_address as u64;
        registry.data.has_legacy_pics = madt.has_legacy_pics();

        let madt_end = addr + madt.header.length as u64;
        let mut entry_ptr = addr + mem::size_of::<Madt>() as u64;

        while entry_ptr + 2 <= madt_end {
            let header = ptr::read_volatile(entry_ptr as *const MadtEntryHeader);

            if header.length < 2 || entry_ptr + header.length as u64 > madt_end {
                break;
            }

            match header.entry_type {
                0 => parse_madt_local_apic(registry, entry_ptr, header.length),
                1 => parse_madt_ioapic(registry, entry_ptr, header.length),
                2 => parse_madt_interrupt_override(registry, entry_ptr, header.length),
                4 => parse_madt_local_apic_nmi(registry, entry_ptr, header.length),
                5 => parse_madt_lapic_override(registry, entry_ptr, header.length),
                9 => parse_madt_x2apic(registry, entry_ptr, header.length),
                10 => parse_madt_x2apic_nmi(registry, entry_ptr, header.length),
                _ => {}
            }

            entry_ptr += header.length as u64;
        }
    }
}

fn parse_madt_local_apic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApic>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApic);
        if entry.is_usable() {
            registry.data.processors.push(ProcessorInfo::new(
                entry.apic_id as u32,
                entry.processor_id as u32,
                false,
                entry.is_enabled(),
            ));
        }
    }
}

fn parse_madt_ioapic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtIoApic>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtIoApic);
        registry.data.ioapics.push(IoApicInfo {
            id: entry.ioapic_id,
            address: entry.address as u64,
            gsi_base: entry.gsi_base,
        });
    }
}

fn parse_madt_interrupt_override(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtInterruptOverride>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtInterruptOverride);
        registry.data.overrides.push(InterruptOverride {
            source_irq: entry.source,
            gsi: entry.gsi,
            polarity: entry.polarity(),
            trigger_mode: entry.trigger_mode(),
        });
    }
}

fn parse_madt_local_apic_nmi(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApicNmi>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApicNmi);
        registry.data.nmis.push(NmiConfig {
            processor_uid: if entry.processor_id == 0xFF {
                u32::MAX
            } else {
                entry.processor_id as u32
            },
            lint: entry.lint,
            flags: entry.flags,
        });
    }
}

fn parse_madt_lapic_override(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalApicOverride>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalApicOverride);
        registry.data.lapic_address = entry.address;
    }
}

fn parse_madt_x2apic(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalX2Apic>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalX2Apic);
        if entry.is_usable() {
            registry.data.processors.push(ProcessorInfo::new(
                entry.x2apic_id,
                entry.processor_uid,
                true,
                entry.is_enabled(),
            ));
        }
    }
}

fn parse_madt_x2apic_nmi(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<MadtLocalX2ApicNmi>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const MadtLocalX2ApicNmi);
        registry.data.nmis.push(NmiConfig {
            processor_uid: entry.processor_uid,
            lint: entry.lint,
            flags: entry.flags,
        });
    }
}

fn parse_hpet(registry: &mut TableRegistry) {
    if let Some(&addr) = registry.tables.get(&SIG_HPET) {
        unsafe {
            let hpet = ptr::read_volatile(addr as *const Hpet);
            if hpet.is_valid() {
                registry.data.hpet_address = Some(hpet.address());
            }
        }
    }
}

fn parse_mcfg(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_MCFG) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let mcfg = ptr::read_volatile(addr as *const Mcfg);
        let entry_count = mcfg.entry_count();
        let entries_ptr = (addr + mcfg.entries_offset() as u64) as *const McfgEntry;

        for i in 0..entry_count {
            let entry = ptr::read_volatile(entries_ptr.add(i));
            registry.data.pcie_segments.push(PcieSegment {
                base_address: entry.base_address,
                segment: entry.segment_group,
                start_bus: entry.start_bus,
                end_bus: entry.end_bus,
            });
        }
    }
}

fn parse_srat(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_SRAT) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let srat = ptr::read_volatile(addr as *const Srat);
        let srat_end = addr + srat.header.length as u64;
        let mut entry_ptr = addr + srat.entries_offset() as u64;

        while entry_ptr + 2 <= srat_end {
            let entry_type = ptr::read_volatile(entry_ptr as *const u8);
            let length = ptr::read_volatile((entry_ptr + 1) as *const u8);

            if length < 2 || entry_ptr + length as u64 > srat_end {
                break;
            }

            match entry_type {
                0 => parse_srat_processor_affinity(registry, entry_ptr, length),
                1 => parse_srat_memory_affinity(registry, entry_ptr, length),
                2 => parse_srat_x2apic_affinity(registry, entry_ptr, length),
                _ => {}
            }

            entry_ptr += length as u64;
        }
    }
}

fn parse_srat_processor_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratProcessorAffinity>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const SratProcessorAffinity);
        if entry.is_enabled() {
            for proc in &mut registry.data.processors {
                if proc.apic_id == entry.apic_id as u32 {
                    proc.proximity_domain = entry.proximity_domain();
                    break;
                }
            }
        }
    }
}

fn parse_srat_memory_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratMemoryAffinity>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const SratMemoryAffinity);
        if entry.is_enabled() {
            registry.data.numa_regions.push(NumaMemoryRegion {
                base: entry.base_address,
                length: entry.length_bytes,
                proximity_domain: entry.proximity_domain,
                hot_pluggable: entry.is_hot_pluggable(),
                non_volatile: entry.is_non_volatile(),
            });
        }
    }
}

fn parse_srat_x2apic_affinity(registry: &mut TableRegistry, ptr: u64, len: u8) {
    if len < mem::size_of::<SratX2ApicAffinity>() as u8 {
        return;
    }
    unsafe {
        let entry = ptr::read_volatile(ptr as *const SratX2ApicAffinity);
        if entry.is_enabled() {
            for proc in &mut registry.data.processors {
                if proc.apic_id == entry.x2apic_id {
                    proc.proximity_domain = entry.proximity_domain;
                    break;
                }
            }
        }
    }
}

pub fn revision() -> Option<u8> {
    TABLES.read().as_ref().map(|t| t.data.revision)
}

pub fn oem_id() -> Option<[u8; 6]> {
    TABLES.read().as_ref().map(|t| t.data.oem_id)
}

pub fn lapic_address() -> Option<u64> {
    TABLES.read().as_ref().map(|t| t.data.lapic_address)
}

pub fn has_legacy_pics() -> Option<bool> {
    TABLES.read().as_ref().map(|t| t.data.has_legacy_pics)
}

pub fn processors() -> alloc::vec::Vec<ProcessorInfo> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.processors.clone())
        .unwrap_or_default()
}

pub fn ioapics() -> alloc::vec::Vec<IoApicInfo> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.ioapics.clone())
        .unwrap_or_default()
}

pub fn interrupt_overrides() -> alloc::vec::Vec<InterruptOverride> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.overrides.clone())
        .unwrap_or_default()
}

pub fn nmi_configs() -> alloc::vec::Vec<NmiConfig> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.nmis.clone())
        .unwrap_or_default()
}

pub fn numa_regions() -> alloc::vec::Vec<NumaMemoryRegion> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.numa_regions.clone())
        .unwrap_or_default()
}

pub fn pcie_segments() -> alloc::vec::Vec<PcieSegment> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.pcie_segments.clone())
        .unwrap_or_default()
}

pub fn hpet_address() -> Option<u64> {
    TABLES.read().as_ref().and_then(|t| t.data.hpet_address)
}

pub fn pm_profile() -> Option<PmProfile> {
    TABLES.read().as_ref().map(|t| t.data.pm_profile)
}

pub fn sci_interrupt() -> Option<u16> {
    TABLES.read().as_ref().map(|t| t.data.sci_interrupt)
}

pub fn stats() -> AcpiStats {
    *STATS.read()
}

pub fn has_table(signature: &[u8; 4]) -> bool {
    let sig = u32::from_le_bytes(*signature);
    TABLES
        .read()
        .as_ref()
        .map(|t| t.tables.contains_key(&sig))
        .unwrap_or(false)
}

pub fn table_address(signature: &[u8; 4]) -> Option<u64> {
    let sig = u32::from_le_bytes(*signature);
    TABLES.read().as_ref().and_then(|t| t.tables.get(&sig).copied())
}

pub(crate) fn with_data<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&AcpiData) -> R,
{
    TABLES.read().as_ref().map(|t| f(&t.data))
}
