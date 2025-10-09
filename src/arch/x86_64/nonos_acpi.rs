//! ACPI | Advanced Configuration and Power Interface

use core::mem;
use core::ptr;
use core::slice;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

/// RSDP (Root System Description Pointer) signature
const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// ACPI table signatures
const RSDT_SIGNATURE: u32 = u32::from_le_bytes(*b"RSDT");
const XSDT_SIGNATURE: u32 = u32::from_le_bytes(*b"XSDT");
const FADT_SIGNATURE: u32 = u32::from_le_bytes(*b"FADT");
const HPET_SIGNATURE: u32 = u32::from_le_bytes(*b"HPET");
const MADT_SIGNATURE: u32 = u32::from_le_bytes(*b"APIC");
const MCFG_SIGNATURE: u32 = u32::from_le_bytes(*b"MCFG");

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RsdpExtended {
    pub rsdp: Rsdp,
    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AcpiTableHeader {
    pub signature: u32,
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Hpet {
    pub header: AcpiTableHeader,
    pub hardware_rev_id: u8,
    pub comparator_count: u8,
    pub counter_size: u8,
    pub reserved: u8,
    pub legacy_replacement: u8,
    pub pci_vendor_id: u16,
    pub base_address: u64,
    pub hpet_number: u8,
    pub minimum_tick: u16,
    pub page_protection: u8,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Fadt {
    pub header: AcpiTableHeader,
    pub firmware_ctrl: u32,
    pub dsdt: u32,
    pub reserved1: u8,
    pub preferred_pm_profile: u8,
    pub sci_interrupt: u16,
    pub smi_command_port: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4bios_req: u8,
    pub pstate_control: u8,
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm2_control_block: u32,
    pub pm_timer_block: u32,
    pub gpe0_block: u32,
    pub gpe1_block: u32,
    pub pm1_event_length: u8,
    pub pm1_control_length: u8,
    pub pm2_control_length: u8,
    pub pm_timer_length: u8,
    pub gpe0_length: u8,
    pub gpe1_length: u8,
    pub gpe1_base: u8,
    pub cst_control: u8,
    pub c2_latency: u16,
    pub c3_latency: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alarm: u8,
    pub month_alarm: u8,
    pub century: u8,
    pub boot_architecture_flags: u16,
    pub reserved2: u8,
    pub flags: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Madt {
    pub header: AcpiTableHeader,
    pub local_apic_address: u32,
    pub flags: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Mcfg {
    pub header: AcpiTableHeader,
    pub reserved: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct McfgEntry {
    pub base_address: u64,
    pub segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
    pub reserved: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Srat {
    pub header: AcpiTableHeader,
    pub table_revision: u32,
    pub reserved: u64,
}

impl Srat {
    /// Get an iterator over SRAT entries
    pub fn entries(&self) -> SratEntryIterator {
        SratEntryIterator::new(self)
    }
}

pub struct SratEntryIterator {
    data: *const u8,
    remaining: usize,
}

impl SratEntryIterator {
    fn new(srat: &Srat) -> Self {
        unsafe {
            let start = (srat as *const Srat as *const u8).add(core::mem::size_of::<Srat>());
            let remaining = srat.header.length as usize - core::mem::size_of::<Srat>();
            Self { data: start, remaining }
        }
    }
}

impl Iterator for SratEntryIterator {
    type Item = SratEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining < 2 {
            return None;
        }
        unsafe {
            let entry_type = *self.data;
            let entry_length = *self.data.add(1);
            if entry_length < 2 || entry_length as usize > self.remaining {
                return None;
            }
            let entry = match entry_type {
                0 => {
                    if entry_length >= core::mem::size_of::<ProcessorAffinityEntry>() as u8 {
                        Some(SratEntry::ProcessorAffinity(*(self.data as *const ProcessorAffinityEntry)))
                    } else { None }
                },
                1 => {
                    if entry_length >= core::mem::size_of::<MemoryAffinityEntry>() as u8 {
                        Some(SratEntry::MemoryAffinity(*(self.data as *const MemoryAffinityEntry)))
                    } else { None }
                },
                2 => {
                    if entry_length >= core::mem::size_of::<ProcessorX2ApicAffinityEntry>() as u8 {
                        Some(SratEntry::ProcessorX2ApicAffinity(*(self.data as *const ProcessorX2ApicAffinityEntry)))
                    } else { None }
                },
                _ => None,
            };
            self.data = self.data.add(entry_length as usize);
            self.remaining -= entry_length as usize;
            entry
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SratEntry {
    ProcessorAffinity(ProcessorAffinityEntry),
    MemoryAffinity(MemoryAffinityEntry),
    ProcessorX2ApicAffinity(ProcessorX2ApicAffinityEntry),
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessorAffinityEntry {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain_low: u8,
    pub local_apic_id: u8,
    pub flags: u32,
    pub local_sapic_eid: u8,
    pub proximity_domain_high: [u8; 3],
    pub clock_domain: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryAffinityEntry {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain: u32,
    pub reserved1: u16,
    pub base_address: u64,
    pub length_bytes: u64,
    pub reserved2: u32,
    pub flags: u32,
    pub reserved3: u64,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessorX2ApicAffinityEntry {
    pub entry_type: u8,
    pub length: u8,
    pub reserved1: u16,
    pub proximity_domain: u32,
    pub x2apic_id: u32,
    pub flags: u32,
    pub clock_domain: u32,
    pub reserved2: u32,
}

/// ACPI tables collection
pub struct AcpiTables {
    rsdp: RsdpExtended,
    rsdt_address: Option<u32>,
    xsdt_address: Option<u64>,
    tables: BTreeMap<u32, u64>, // signature -> physical address
}

impl AcpiTables {
    /// Find a table by signature and type
    pub fn find_table<T>(&self) -> Option<&'static T> {
        let signature = match core::any::type_name::<T>() {
            name if name.contains("Hpet") => HPET_SIGNATURE,
            name if name.contains("Fadt") => FADT_SIGNATURE,
            name if name.contains("Madt") => MADT_SIGNATURE,
            name if name.contains("Mcfg") => MCFG_SIGNATURE,
            _ => return None,
        };
        if let Some(&address) = self.tables.get(&signature) {
            unsafe {
                Some(&*(address as *const T))
            }
        } else {
            None
        }
    }

    /// Get all tables of a specific type
    pub fn find_tables<T>(&self) -> Vec<&'static T> {
        let mut results = Vec::new();
        for (&sig, &addr) in &self.tables {
            if sig == HPET_SIGNATURE && core::any::type_name::<T>().contains("Hpet") {
                unsafe { results.push(&*(addr as *const T)); }
            }
            // Extend for other types as needed
        }
        results
    }
}

/// Global ACPI tables instance
static mut ACPI_TABLES: Option<AcpiTables> = None;

/// Get ACPI tables instance
pub fn get_acpi_tables() -> Option<&'static AcpiTables> {
    unsafe { ACPI_TABLES.as_ref() }
}

/// Initialize ACPI subsystem and enumerate tables
pub fn init() -> Result<(), &'static str> {
    let rsdp = find_rsdp().ok_or("RSDP not found")?;
    let mut tables = AcpiTables {
        rsdp,
        rsdt_address: if rsdp.rsdp.revision == 0 { Some(rsdp.rsdp.rsdt_address) } else { None },
        xsdt_address: if rsdp.rsdp.revision >= 2 { Some(rsdp.xsdt_address) } else { None },
        tables: BTreeMap::new(),
    };

    // Parse RSDT or XSDT
    if let Some(xsdt_addr) = tables.xsdt_address {
        parse_xsdt(&mut tables, xsdt_addr)?;
    } else if let Some(rsdt_addr) = tables.rsdt_address {
        parse_rsdt(&mut tables, rsdt_addr as u64)?;
    } else {
        return Err("No RSDT or XSDT found");
    }

    unsafe { ACPI_TABLES = Some(tables); }
    Ok(())
}

/// Find RSDP in memory
fn find_rsdp() -> Option<RsdpExtended> {
    // Search in EBDA (Extended BIOS Data Area)
    unsafe {
        let ebda_segment = ptr::read_volatile(0x040E as *const u16) as u32;
        let ebda_start = (ebda_segment << 4) as usize;
        if let Some(rsdp) = search_rsdp(ebda_start, 1024) {
            return Some(rsdp);
        }
    }
    // Search in BIOS memory area
    if let Some(rsdp) = search_rsdp(0xE0000, 0x20000) {
        return Some(rsdp);
    }
    None
}

/// Search for RSDP in memory range
fn search_rsdp(start: usize, length: usize) -> Option<RsdpExtended> {
    for addr in (start..start + length).step_by(16) {
        unsafe {
            let potential_rsdp = addr as *const Rsdp;
            if ptr::read_volatile(potential_rsdp).signature == *RSDP_SIGNATURE {
                let rsdp = ptr::read_volatile(potential_rsdp);
                if validate_checksum(&rsdp as *const _ as *const u8, mem::size_of::<Rsdp>()) {
                    if rsdp.revision >= 2 {
                        // ACPI 2.0+ extended RSDP
                        let extended_rsdp = ptr::read_volatile(addr as *const RsdpExtended);
                        if validate_checksum(&extended_rsdp as *const _ as *const u8, extended_rsdp.length as usize) {
                            return Some(extended_rsdp);
                        }
                    } else {
                        // ACPI 1.0 RSDP, create extended version
                        return Some(RsdpExtended {
                            rsdp,
                            length: mem::size_of::<Rsdp>() as u32,
                            xsdt_address: 0,
                            extended_checksum: 0,
                            reserved: [0; 3],
                        });
                    }
                }
            }
        }
    }
    None
}

/// Parse RSDT (Root System Description Table)
fn parse_rsdt(tables: &mut AcpiTables, rsdt_addr: u64) -> Result<(), &'static str> {
    unsafe {
        let header = ptr::read_volatile(rsdt_addr as *const AcpiTableHeader);
        if header.signature != RSDT_SIGNATURE { return Err("Invalid RSDT signature"); }
        if !validate_checksum(rsdt_addr as *const u8, header.length as usize) { return Err("RSDT checksum failed"); }
        let entry_count = (header.length - mem::size_of::<AcpiTableHeader>() as u32) / 4;
        let entries_ptr = (rsdt_addr + mem::size_of::<AcpiTableHeader>() as u64) as *const u32;
        let entries = slice::from_raw_parts(entries_ptr, entry_count as usize);
        for &entry_addr in entries {
            let table_header = ptr::read_volatile(entry_addr as *const AcpiTableHeader);
            tables.tables.insert(table_header.signature, entry_addr as u64);
        }
    }
    Ok(())
}

/// Parse XSDT (Extended System Description Table)
fn parse_xsdt(tables: &mut AcpiTables, xsdt_addr: u64) -> Result<(), &'static str> {
    unsafe {
        let header = ptr::read_volatile(xsdt_addr as *const AcpiTableHeader);
        if header.signature != XSDT_SIGNATURE { return Err("Invalid XSDT signature"); }
        if !validate_checksum(xsdt_addr as *const u8, header.length as usize) { return Err("XSDT checksum failed"); }
        let entry_count = (header.length - mem::size_of::<AcpiTableHeader>() as u32) / 8;
        let entries_ptr = (xsdt_addr + mem::size_of::<AcpiTableHeader>() as u64) as *const u64;
        let entries = slice::from_raw_parts(entries_ptr, entry_count as usize);
        for &entry_addr in entries {
            let table_header = ptr::read_volatile(entry_addr as *const AcpiTableHeader);
            tables.tables.insert(table_header.signature, entry_addr);
        }
    }
    Ok(())
}

/// Validate ACPI table checksum
fn validate_checksum(data: *const u8, length: usize) -> bool {
    unsafe {
        let bytes = slice::from_raw_parts(data, length);
        let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        sum == 0
    }
}

/// Power management operations
pub mod power {
    use super::*;

    /// ACPI power states
    #[derive(Debug, Clone, Copy)]
    pub enum PowerState {
        S0, // Working
        S1, // Sleep
        S2, // Sleep
        S3, // Suspend to RAM
        S4, // Suspend to Disk
        S5, // Soft Power Off
    }

    /// Enter ACPI power state (S5 implemented, others require hardware-specific support)
    pub fn enter_power_state(state: PowerState) -> Result<(), &'static str> {
        if let Some(tables) = get_acpi_tables() {
            if let Some(fadt) = tables.find_table::<Fadt>() {
                match state {
                    PowerState::S0 => Ok(()), // Already in working state
                    PowerState::S5 => {
                        unsafe {
                            crate::arch::x86_64::port::outw(fadt.pm1a_control_block as u16, 0x2000);
                            if fadt.pm1b_control_block != 0 {
                                crate::arch::x86_64::port::outw(fadt.pm1b_control_block as u16, 0x2000);
                            }
                        }
                        Ok(())
                    },
                    _ => Err("Power state requires hardware-specific implementation"),
                }
            } else {
                Err("FADT not found")
            }
        } else {
            Err("ACPI not initialized")
        }
    }

    /// System shutdown via ACPI (uses S5 state)
    pub fn shutdown() -> Result<(), &'static str> {
        enter_power_state(PowerState::S5)
    }

    /// System reboot via ACPI (uses keyboard controller fallback if reset reg not available)
    pub fn reboot() -> Result<(), &'static str> {
        if let Some(tables) = get_acpi_tables() {
            if let Some(fadt) = tables.find_table::<Fadt>() {
                unsafe {
                    if fadt.flags & (1 << 10) != 0 {
                        // ACPI reset register support detected, needs full protocol
                        return Err("ACPI reset register protocol not implemented");
                    }
                    crate::arch::x86_64::port::outb(0x64, 0xFE);
                }
                Ok(())
            } else {
                Err("FADT not found")
            }
        } else {
            Err("ACPI not initialized")
        }
    }
}

/// Device enumeration and hardware queries
pub mod devices {
    use super::*;

    /// Enumerate PCI devices using MCFG table (full hardware scan)
    pub fn enumerate_pci_devices() -> Vec<(u8, u8, u8)> {
        let mut devices = Vec::new();
        if let Some(tables) = get_acpi_tables() {
            if let Some(mcfg) = tables.find_table::<Mcfg>() {
                unsafe {
                    let entry_count = (mcfg.header.length - mem::size_of::<Mcfg>() as u32) / mem::size_of::<McfgEntry>() as u32;
                    let entries_ptr = (mcfg as *const Mcfg as u64 + mem::size_of::<Mcfg>() as u64) as *const McfgEntry;
                    let entries = slice::from_raw_parts(entries_ptr, entry_count as usize);
                    for entry in entries {
                        for bus in entry.start_bus..=entry.end_bus {
                            for device in 0..32 {
                                for function in 0..8 {
                                    let config_addr = entry.base_address +
                                        ((bus as u64) << 20) +
                                        ((device as u64) << 15) +
                                        ((function as u64) << 12);
                                    let vendor_id = ptr::read_volatile(config_addr as *const u16);
                                    if vendor_id != 0xFFFF {
                                        devices.push((bus, device, function));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        devices
    }

    /// Get HPET base address from ACPI tables
    pub fn get_hpet_base() -> Option<u64> {
        get_acpi_tables().and_then(|tables| tables.find_table::<Hpet>().map(|hpet| hpet.base_address))
    }

    /// Get LAPIC base address from MADT
    pub fn get_lapic_base() -> Option<u32> {
        get_acpi_tables().and_then(|tables| tables.find_table::<Madt>().map(|madt| madt.local_apic_address))
    }
}
