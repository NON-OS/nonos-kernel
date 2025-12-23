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
//! ACPI (Advanced-Configuration-Power-Interface)
//!
//! ## ACPI Table Hierarchy
//! RSDP (Root System Description Pointer)
//!   └─► XSDT/RSDT (Extended/Root System Description Table)
//!         ├─► FADT (Fixed ACPI Description Table)
//!         │     └─► DSDT (Differentiated System Description Table)
//!         ├─► MADT (Multiple APIC Description Table)
//!         ├─► HPET (High Precision Event Timer)
//!         ├─► MCFG (Memory-mapped ConFiGuration space)
//!         ├─► SRAT (System Resource Affinity Table)
//!         ├─► SLIT (System Locality Information Table)
//!         └─► ... other tables
//! ```

use core::mem;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::RwLock;

// ============================================================================
// Error Handling
// ============================================================================

/// ACPI subsystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// ACPI not initialized
    NotInitialized,
    /// Already initialized
    AlreadyInitialized,
    /// RSDP not found in memory
    RsdpNotFound,
    /// Invalid RSDP signature
    InvalidRsdpSignature,
    /// RSDP checksum validation failed
    RsdpChecksumFailed,
    /// Extended RSDP checksum failed
    ExtendedRsdpChecksumFailed,
    /// Neither RSDT nor XSDT found
    NoRootTable,
    /// Invalid RSDT signature
    InvalidRsdtSignature,
    /// RSDT checksum failed
    RsdtChecksumFailed,
    /// Invalid XSDT signature
    InvalidXsdtSignature,
    /// XSDT checksum failed
    XsdtChecksumFailed,
    /// Table not found
    TableNotFound,
    /// Invalid table signature
    InvalidTableSignature,
    /// Table checksum failed
    TableChecksumFailed,
    /// Invalid table structure
    InvalidTableStructure,
    /// FADT not found (required for power management)
    FadtNotFound,
    /// MADT not found (required for APIC enumeration)
    MadtNotFound,
    /// Power state not supported
    PowerStateNotSupported,
    /// ACPI hardware access failed
    HardwareAccessFailed,
    /// Reset register not available
    ResetNotAvailable,
    /// Invalid memory address
    InvalidAddress,
    /// Table revision not supported
    UnsupportedRevision,
}

impl AcpiError {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "ACPI not initialized",
            Self::AlreadyInitialized => "ACPI already initialized",
            Self::RsdpNotFound => "RSDP not found in memory",
            Self::InvalidRsdpSignature => "invalid RSDP signature",
            Self::RsdpChecksumFailed => "RSDP checksum validation failed",
            Self::ExtendedRsdpChecksumFailed => "extended RSDP checksum failed",
            Self::NoRootTable => "neither RSDT nor XSDT found",
            Self::InvalidRsdtSignature => "invalid RSDT signature",
            Self::RsdtChecksumFailed => "RSDT checksum failed",
            Self::InvalidXsdtSignature => "invalid XSDT signature",
            Self::XsdtChecksumFailed => "XSDT checksum failed",
            Self::TableNotFound => "ACPI table not found",
            Self::InvalidTableSignature => "invalid table signature",
            Self::TableChecksumFailed => "table checksum failed",
            Self::InvalidTableStructure => "invalid table structure",
            Self::FadtNotFound => "FADT not found",
            Self::MadtNotFound => "MADT not found",
            Self::PowerStateNotSupported => "power state not supported",
            Self::HardwareAccessFailed => "hardware access failed",
            Self::ResetNotAvailable => "reset register not available",
            Self::InvalidAddress => "invalid memory address",
            Self::UnsupportedRevision => "table revision not supported",
        }
    }
}

/// Result type for ACPI operations
pub type AcpiResult<T> = Result<T, AcpiError>;

// ============================================================================
// Constants
// ============================================================================

/// RSDP signature "RSD PTR "
const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

/// Table signatures (as little-endian u32)
const SIG_RSDT: u32 = u32::from_le_bytes(*b"RSDT");
const SIG_XSDT: u32 = u32::from_le_bytes(*b"XSDT");
const SIG_FADT: u32 = u32::from_le_bytes(*b"FACP"); // FADT uses "FACP" signature
const SIG_MADT: u32 = u32::from_le_bytes(*b"APIC");
const SIG_HPET: u32 = u32::from_le_bytes(*b"HPET");
const SIG_MCFG: u32 = u32::from_le_bytes(*b"MCFG");
const SIG_SRAT: u32 = u32::from_le_bytes(*b"SRAT");
const SIG_SLIT: u32 = u32::from_le_bytes(*b"SLIT");
const SIG_DSDT: u32 = u32::from_le_bytes(*b"DSDT");
const SIG_SSDT: u32 = u32::from_le_bytes(*b"SSDT");
const SIG_BGRT: u32 = u32::from_le_bytes(*b"BGRT");
const SIG_WAET: u32 = u32::from_le_bytes(*b"WAET");

/// EBDA segment pointer location
const EBDA_PTR_ADDR: usize = 0x040E;

/// BIOS ROM search area
const BIOS_ROM_START: usize = 0xE0000;
const BIOS_ROM_SIZE: usize = 0x20000;

/// RSDP alignment requirement
const RSDP_ALIGNMENT: usize = 16;

// ============================================================================
// RSDP Structures
// ============================================================================

/// RSDP (Root System Description Pointer) - ACPI 1.0
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Rsdp {
    /// Signature "RSD PTR "
    pub signature: [u8; 8],
    /// Checksum of first 20 bytes
    pub checksum: u8,
    /// OEM identifier
    pub oem_id: [u8; 6],
    /// ACPI revision (0 = 1.0, 2 = 2.0+)
    pub revision: u8,
    /// Physical address of RSDT (32-bit)
    pub rsdt_address: u32,
}

impl Rsdp {
    /// Validates RSDP checksum
    pub fn validate_checksum(&self) -> bool {
        let bytes = unsafe {
            slice::from_raw_parts(self as *const Self as *const u8, mem::size_of::<Self>())
        };
        bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
    }
}

/// Extended RSDP - ACPI 2.0+
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RsdpExtended {
    /// ACPI 1.0 RSDP fields
    pub base: Rsdp,
    /// Length of entire RSDP structure
    pub length: u32,
    /// Physical address of XSDT (64-bit)
    pub xsdt_address: u64,
    /// Checksum of entire structure
    pub extended_checksum: u8,
    /// Reserved
    pub reserved: [u8; 3],
}

impl RsdpExtended {
    /// Validates extended checksum
    pub fn validate_extended_checksum(&self) -> bool {
        let bytes = unsafe {
            slice::from_raw_parts(
                self as *const Self as *const u8,
                self.length as usize,
            )
        };
        bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
    }

    /// Creates from ACPI 1.0 RSDP
    pub fn from_rsdp(rsdp: Rsdp) -> Self {
        Self {
            base: rsdp,
            length: mem::size_of::<Rsdp>() as u32,
            xsdt_address: 0,
            extended_checksum: 0,
            reserved: [0; 3],
        }
    }
}

// ============================================================================
// Common Table Header
// ============================================================================

/// SDT Header (System Description Table) - common to all ACPI tables
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SdtHeader {
    /// 4-byte ASCII signature
    pub signature: u32,
    /// Total table length including header
    pub length: u32,
    /// Table revision
    pub revision: u8,
    /// Checksum (entire table must sum to 0)
    pub checksum: u8,
    /// OEM identifier
    pub oem_id: [u8; 6],
    /// OEM table identifier
    pub oem_table_id: [u8; 8],
    /// OEM revision
    pub oem_revision: u32,
    /// Creator ID (ASL compiler vendor)
    pub creator_id: u32,
    /// Creator revision
    pub creator_revision: u32,
}

impl SdtHeader {
    /// Returns signature as string
    pub fn signature_str(&self) -> [u8; 4] {
        self.signature.to_le_bytes()
    }

    /// Validates table checksum
    pub fn validate_checksum(&self, table_ptr: *const u8) -> bool {
        if self.length < mem::size_of::<Self>() as u32 {
            return false;
        }
        unsafe {
            let bytes = slice::from_raw_parts(table_ptr, self.length as usize);
            bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
        }
    }
}

// ============================================================================
// Generic Address Structure (GAS)
// ============================================================================

/// Address space identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressSpace {
    SystemMemory = 0x00,
    SystemIo = 0x01,
    PciConfig = 0x02,
    EmbeddedController = 0x03,
    SmBus = 0x04,
    Cmos = 0x05,
    PciBarTarget = 0x06,
    Ipmi = 0x07,
    Gpio = 0x08,
    GenericSerialBus = 0x09,
    Pcc = 0x0A,
    FunctionalFixedHw = 0x7F,
}

/// Generic Address Structure - used for register addresses in FADT
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct GenericAddress {
    /// Address space ID
    pub address_space: u8,
    /// Register bit width
    pub bit_width: u8,
    /// Register bit offset
    pub bit_offset: u8,
    /// Access size (1=byte, 2=word, 3=dword, 4=qword)
    pub access_size: u8,
    /// 64-bit address
    pub address: u64,
}

impl GenericAddress {
    /// Returns true if this is a valid address
    pub fn is_valid(&self) -> bool {
        self.address != 0
    }

    /// Returns the address space type
    pub fn space(&self) -> Option<AddressSpace> {
        match self.address_space {
            0x00 => Some(AddressSpace::SystemMemory),
            0x01 => Some(AddressSpace::SystemIo),
            0x02 => Some(AddressSpace::PciConfig),
            0x7F => Some(AddressSpace::FunctionalFixedHw),
            _ => None,
        }
    }
}

// ============================================================================
// FADT (Fixed ACPI Description Table)
// ============================================================================

/// PM Profile types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PmProfile {
    Unspecified = 0,
    Desktop = 1,
    Mobile = 2,
    Workstation = 3,
    EnterpriseServer = 4,
    SohoServer = 5,
    AppliancePc = 6,
    PerformanceServer = 7,
    Tablet = 8,
}

/// FADT flags
pub mod fadt_flags {
    pub const WBINVD: u32 = 1 << 0;
    pub const WBINVD_FLUSH: u32 = 1 << 1;
    pub const PROC_C1: u32 = 1 << 2;
    pub const P_LVL2_UP: u32 = 1 << 3;
    pub const PWR_BUTTON: u32 = 1 << 4;
    pub const SLP_BUTTON: u32 = 1 << 5;
    pub const FIX_RTC: u32 = 1 << 6;
    pub const RTC_S4: u32 = 1 << 7;
    pub const TMR_VAL_EXT: u32 = 1 << 8;
    pub const DCK_CAP: u32 = 1 << 9;
    pub const RESET_REG_SUP: u32 = 1 << 10;
    pub const SEALED_CASE: u32 = 1 << 11;
    pub const HEADLESS: u32 = 1 << 12;
    pub const CPU_SW_SLP: u32 = 1 << 13;
    pub const PCI_EXP_WAK: u32 = 1 << 14;
    pub const USE_PLATFORM_CLOCK: u32 = 1 << 15;
    pub const S4_RTC_STS_VALID: u32 = 1 << 16;
    pub const REMOTE_POWER_ON: u32 = 1 << 17;
    pub const APIC_CLUSTER: u32 = 1 << 18;
    pub const APIC_PHYSICAL: u32 = 1 << 19;
    pub const HW_REDUCED_ACPI: u32 = 1 << 20;
    pub const LOW_POWER_S0: u32 = 1 << 21;
}

/// FADT (Fixed ACPI Description Table)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Fadt {
    pub header: SdtHeader,
    /// Physical address of FACS
    pub firmware_ctrl: u32,
    /// Physical address of DSDT
    pub dsdt: u32,
    /// Reserved (ACPI 1.0 interrupt model)
    pub reserved1: u8,
    /// Preferred power management profile
    pub preferred_pm_profile: u8,
    /// SCI interrupt vector
    pub sci_interrupt: u16,
    /// SMI command port
    pub smi_command_port: u32,
    /// Value to write to enable ACPI
    pub acpi_enable: u8,
    /// Value to write to disable ACPI
    pub acpi_disable: u8,
    /// Value for S4BIOS support
    pub s4bios_req: u8,
    /// P-state control
    pub pstate_control: u8,
    /// PM1a event block address
    pub pm1a_event_block: u32,
    /// PM1b event block address
    pub pm1b_event_block: u32,
    /// PM1a control block address
    pub pm1a_control_block: u32,
    /// PM1b control block address
    pub pm1b_control_block: u32,
    /// PM2 control block address
    pub pm2_control_block: u32,
    /// PM timer block address
    pub pm_timer_block: u32,
    /// GPE0 block address
    pub gpe0_block: u32,
    /// GPE1 block address
    pub gpe1_block: u32,
    /// PM1 event block length
    pub pm1_event_length: u8,
    /// PM1 control block length
    pub pm1_control_length: u8,
    /// PM2 control block length
    pub pm2_control_length: u8,
    /// PM timer block length
    pub pm_timer_length: u8,
    /// GPE0 block length
    pub gpe0_length: u8,
    /// GPE1 block length
    pub gpe1_length: u8,
    /// GPE1 base offset
    pub gpe1_base: u8,
    /// C-state control
    pub cst_control: u8,
    /// C2 latency (microseconds)
    pub c2_latency: u16,
    /// C3 latency (microseconds)
    pub c3_latency: u16,
    /// Cache flush size
    pub flush_size: u16,
    /// Cache flush stride
    pub flush_stride: u16,
    /// Duty cycle offset
    pub duty_offset: u8,
    /// Duty cycle width
    pub duty_width: u8,
    /// RTC day alarm index
    pub day_alarm: u8,
    /// RTC month alarm index
    pub month_alarm: u8,
    /// RTC century index
    pub century: u8,
    /// Boot architecture flags (ACPI 2.0+)
    pub boot_architecture_flags: u16,
    /// Reserved
    pub reserved2: u8,
    /// Feature flags
    pub flags: u32,
    // ACPI 2.0+ extended fields follow
    /// Reset register
    pub reset_reg: GenericAddress,
    /// Reset value
    pub reset_value: u8,
    /// ARM boot architecture flags
    pub arm_boot_arch: u16,
    /// FADT minor version
    pub fadt_minor_version: u8,
    /// Extended FACS address (64-bit)
    pub x_firmware_ctrl: u64,
    /// Extended DSDT address (64-bit)
    pub x_dsdt: u64,
    /// Extended PM1a event block
    pub x_pm1a_event_block: GenericAddress,
    /// Extended PM1b event block
    pub x_pm1b_event_block: GenericAddress,
    /// Extended PM1a control block
    pub x_pm1a_control_block: GenericAddress,
    /// Extended PM1b control block
    pub x_pm1b_control_block: GenericAddress,
    /// Extended PM2 control block
    pub x_pm2_control_block: GenericAddress,
    /// Extended PM timer block
    pub x_pm_timer_block: GenericAddress,
    /// Extended GPE0 block
    pub x_gpe0_block: GenericAddress,
    /// Extended GPE1 block
    pub x_gpe1_block: GenericAddress,
    /// Sleep control register
    pub sleep_control_reg: GenericAddress,
    /// Sleep status register
    pub sleep_status_reg: GenericAddress,
    /// Hypervisor vendor ID
    pub hypervisor_vendor_id: u64,
}

impl Fadt {
    /// Returns true if reset register is supported
    pub fn has_reset_register(&self) -> bool {
        self.flags & fadt_flags::RESET_REG_SUP != 0 && self.reset_reg.is_valid()
    }

    /// Returns true if hardware-reduced ACPI mode
    pub fn is_hw_reduced(&self) -> bool {
        self.flags & fadt_flags::HW_REDUCED_ACPI != 0
    }

    /// Returns DSDT address (prefers 64-bit if available)
    pub fn dsdt_address(&self) -> u64 {
        if self.header.length >= 148 && self.x_dsdt != 0 {
            self.x_dsdt
        } else {
            self.dsdt as u64
        }
    }

    /// Returns PM profile
    pub fn pm_profile(&self) -> PmProfile {
        match self.preferred_pm_profile {
            1 => PmProfile::Desktop,
            2 => PmProfile::Mobile,
            3 => PmProfile::Workstation,
            4 => PmProfile::EnterpriseServer,
            5 => PmProfile::SohoServer,
            6 => PmProfile::AppliancePc,
            7 => PmProfile::PerformanceServer,
            8 => PmProfile::Tablet,
            _ => PmProfile::Unspecified,
        }
    }
}

// ============================================================================
// MADT (Multiple APIC Description Table)
// ============================================================================

/// MADT flags
pub mod madt_flags {
    /// PC-AT compatible dual 8259 PICs installed
    pub const PCAT_COMPAT: u32 = 1 << 0;
}

/// MADT structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Madt {
    pub header: SdtHeader,
    /// Local APIC physical address
    pub local_apic_address: u32,
    /// Flags
    pub flags: u32,
}

impl Madt {
    /// Returns true if legacy PICs are present
    pub fn has_legacy_pics(&self) -> bool {
        self.flags & madt_flags::PCAT_COMPAT != 0
    }
}

/// MADT entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MadtEntryType {
    LocalApic = 0,
    IoApic = 1,
    InterruptSourceOverride = 2,
    NmiSource = 3,
    LocalApicNmi = 4,
    LocalApicAddressOverride = 5,
    IoSapic = 6,
    LocalSapic = 7,
    PlatformInterrupt = 8,
    LocalX2Apic = 9,
    LocalX2ApicNmi = 10,
    GicCpu = 11,
    GicDistributor = 12,
    GicMsiFrame = 13,
    GicRedistributor = 14,
    GicIts = 15,
    MultiprocessorWakeup = 16,
}

/// MADT entry header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtEntryHeader {
    pub entry_type: u8,
    pub length: u8,
}

/// Local APIC entry (type 0)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApic {
    pub header: MadtEntryHeader,
    /// ACPI processor UID
    pub processor_id: u8,
    /// Local APIC ID
    pub apic_id: u8,
    /// Flags (bit 0 = enabled, bit 1 = online capable)
    pub flags: u32,
}

impl MadtLocalApic {
    pub fn is_enabled(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn is_online_capable(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// I/O APIC entry (type 1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtIoApic {
    pub header: MadtEntryHeader,
    /// I/O APIC ID
    pub ioapic_id: u8,
    /// Reserved
    pub reserved: u8,
    /// I/O APIC physical address
    pub address: u32,
    /// Global System Interrupt base
    pub gsi_base: u32,
}

/// Interrupt Source Override entry (type 2)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtInterruptOverride {
    pub header: MadtEntryHeader,
    /// Bus (always 0 = ISA)
    pub bus: u8,
    /// Bus-relative IRQ source
    pub source: u8,
    /// Global System Interrupt
    pub gsi: u32,
    /// MPS INTI flags
    pub flags: u16,
}

impl MadtInterruptOverride {
    /// Returns polarity (0=bus, 1=active high, 3=active low)
    pub fn polarity(&self) -> u8 {
        (self.flags & 0x03) as u8
    }

    /// Returns trigger mode (0=bus, 1=edge, 3=level)
    pub fn trigger_mode(&self) -> u8 {
        ((self.flags >> 2) & 0x03) as u8
    }
}

/// NMI Source entry (type 3)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtNmiSource {
    pub header: MadtEntryHeader,
    /// Flags
    pub flags: u16,
    /// Global System Interrupt for NMI
    pub gsi: u32,
}

/// Local APIC NMI entry (type 4)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApicNmi {
    pub header: MadtEntryHeader,
    /// Processor UID (0xFF = all)
    pub processor_id: u8,
    /// Flags
    pub flags: u16,
    /// Local APIC LINT# (0 or 1)
    pub lint: u8,
}

/// Local APIC Address Override entry (type 5)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApicOverride {
    pub header: MadtEntryHeader,
    /// Reserved
    pub reserved: u16,
    /// 64-bit Local APIC address
    pub address: u64,
}

/// x2APIC entry (type 9)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalX2Apic {
    pub header: MadtEntryHeader,
    /// Reserved
    pub reserved: u16,
    /// x2APIC ID
    pub x2apic_id: u32,
    /// Flags
    pub flags: u32,
    /// ACPI processor UID
    pub processor_uid: u32,
}

impl MadtLocalX2Apic {
    pub fn is_enabled(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// x2APIC NMI entry (type 10)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalX2ApicNmi {
    pub header: MadtEntryHeader,
    /// Flags
    pub flags: u16,
    /// Processor UID
    pub processor_uid: u32,
    /// Local x2APIC LINT#
    pub lint: u8,
    /// Reserved
    pub reserved: [u8; 3],
}

// ============================================================================
// HPET (High Precision Event Timer)
// ============================================================================

/// HPET table
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Hpet {
    pub header: SdtHeader,
    /// Event timer block ID
    pub event_timer_block_id: u32,
    /// Base address
    pub base_address: GenericAddress,
    /// HPET sequence number
    pub hpet_number: u8,
    /// Minimum tick in periodic mode
    pub minimum_tick: u16,
    /// Page protection and OEM attribute
    pub page_protection: u8,
}

impl Hpet {
    /// Returns number of comparators
    pub fn comparator_count(&self) -> u8 {
        ((self.event_timer_block_id >> 8) & 0x1F) as u8 + 1
    }

    /// Returns true if 64-bit counter
    pub fn is_64bit(&self) -> bool {
        self.event_timer_block_id & (1 << 13) != 0
    }

    /// Returns true if legacy replacement supported
    pub fn supports_legacy_replacement(&self) -> bool {
        self.event_timer_block_id & (1 << 15) != 0
    }

    /// Returns PCI vendor ID
    pub fn vendor_id(&self) -> u16 {
        (self.event_timer_block_id >> 16) as u16
    }
}

// ============================================================================
// MCFG (PCI Express Memory-mapped Configuration)
// ============================================================================

/// MCFG table
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Mcfg {
    pub header: SdtHeader,
    /// Reserved
    pub reserved: u64,
}

/// MCFG configuration space entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct McfgEntry {
    /// Base address of enhanced configuration mechanism
    pub base_address: u64,
    /// PCI segment group number
    pub segment_group: u16,
    /// Start PCI bus number
    pub start_bus: u8,
    /// End PCI bus number
    pub end_bus: u8,
    /// Reserved
    pub reserved: u32,
}

// ============================================================================
// SRAT (System Resource Affinity Table) - NUMA
// ============================================================================

/// SRAT table
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Srat {
    pub header: SdtHeader,
    /// Table revision
    pub table_revision: u32,
    /// Reserved
    pub reserved: u64,
}

/// SRAT entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SratEntryType {
    ProcessorAffinity = 0,
    MemoryAffinity = 1,
    ProcessorX2ApicAffinity = 2,
    GiccAffinity = 3,
    GicItsAffinity = 4,
    GenericInitiatorAffinity = 5,
}

/// Processor Local APIC/SAPIC Affinity (type 0)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratProcessorAffinity {
    pub entry_type: u8,
    pub length: u8,
    /// Bits [7:0] of proximity domain
    pub proximity_domain_low: u8,
    /// Local APIC ID
    pub apic_id: u8,
    /// Flags (bit 0 = enabled)
    pub flags: u32,
    /// Local SAPIC EID
    pub sapic_eid: u8,
    /// Bits [31:8] of proximity domain
    pub proximity_domain_high: [u8; 3],
    /// Clock domain
    pub clock_domain: u32,
}

impl SratProcessorAffinity {
    pub fn proximity_domain(&self) -> u32 {
        self.proximity_domain_low as u32
            | ((self.proximity_domain_high[0] as u32) << 8)
            | ((self.proximity_domain_high[1] as u32) << 16)
            | ((self.proximity_domain_high[2] as u32) << 24)
    }

    pub fn is_enabled(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// Memory Affinity (type 1)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratMemoryAffinity {
    pub entry_type: u8,
    pub length: u8,
    /// Proximity domain
    pub proximity_domain: u32,
    /// Reserved
    pub reserved1: u16,
    /// Base address
    pub base_address: u64,
    /// Length in bytes
    pub length_bytes: u64,
    /// Reserved
    pub reserved2: u32,
    /// Flags
    pub flags: u32,
    /// Reserved
    pub reserved3: u64,
}

impl SratMemoryAffinity {
    pub fn is_enabled(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn is_hot_pluggable(&self) -> bool {
        self.flags & 2 != 0
    }

    pub fn is_non_volatile(&self) -> bool {
        self.flags & 4 != 0
    }
}

/// Processor x2APIC Affinity (type 2)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratX2ApicAffinity {
    pub entry_type: u8,
    pub length: u8,
    /// Reserved
    pub reserved1: u16,
    /// Proximity domain
    pub proximity_domain: u32,
    /// x2APIC ID
    pub x2apic_id: u32,
    /// Flags
    pub flags: u32,
    /// Clock domain
    pub clock_domain: u32,
    /// Reserved
    pub reserved2: u32,
}

impl SratX2ApicAffinity {
    pub fn is_enabled(&self) -> bool {
        self.flags & 1 != 0
    }
}

// ============================================================================
// SLIT (System Locality Information Table) - NUMA distances
// ============================================================================

/// SLIT table
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Slit {
    pub header: SdtHeader,
    /// Number of System Localities
    pub locality_count: u64,
}

impl Slit {
    /// Gets distance between two NUMA nodes
    pub fn distance(&self, from: usize, to: usize) -> Option<u8> {
        let count = self.locality_count as usize;
        if from >= count || to >= count {
            return None;
        }
        unsafe {
            let matrix = (self as *const Self as *const u8)
                .add(mem::size_of::<Self>());
            Some(*matrix.add(from * count + to))
        }
    }
}

// ============================================================================
// Parsed ACPI Data
// ============================================================================

/// Parsed processor information
#[derive(Debug, Clone)]
pub struct ProcessorInfo {
    /// APIC ID
    pub apic_id: u32,
    /// ACPI processor UID
    pub processor_uid: u32,
    /// NUMA proximity domain
    pub proximity_domain: u32,
    /// Is x2APIC mode
    pub is_x2apic: bool,
    /// Is enabled
    pub enabled: bool,
}

/// Parsed I/O APIC information
#[derive(Debug, Clone, Copy)]
pub struct IoApicInfo {
    /// I/O APIC ID
    pub id: u8,
    /// Physical base address
    pub address: u64,
    /// Global System Interrupt base
    pub gsi_base: u32,
}

/// Parsed interrupt override information
#[derive(Debug, Clone, Copy)]
pub struct InterruptOverride {
    /// Source IRQ (ISA)
    pub source_irq: u8,
    /// Global System Interrupt
    pub gsi: u32,
    /// Polarity (0=bus, 1=active high, 3=active low)
    pub polarity: u8,
    /// Trigger mode (0=bus, 1=edge, 3=level)
    pub trigger_mode: u8,
}

/// Parsed NMI configuration
#[derive(Debug, Clone, Copy)]
pub struct NmiConfig {
    /// Processor UID (u32::MAX = all)
    pub processor_uid: u32,
    /// LINT# pin
    pub lint: u8,
    /// Flags
    pub flags: u16,
}

/// Parsed NUMA memory region
#[derive(Debug, Clone, Copy)]
pub struct NumaMemoryRegion {
    /// Base physical address
    pub base: u64,
    /// Length in bytes
    pub length: u64,
    /// Proximity domain
    pub proximity_domain: u32,
    /// Is hot-pluggable
    pub hot_pluggable: bool,
    /// Is non-volatile (NVDIMM)
    pub non_volatile: bool,
}

/// Parsed MCFG entry
#[derive(Debug, Clone, Copy)]
pub struct PcieSegment {
    /// ECAM base address
    pub base_address: u64,
    /// Segment group
    pub segment: u16,
    /// Start bus
    pub start_bus: u8,
    /// End bus
    pub end_bus: u8,
}

/// Complete parsed ACPI data
#[derive(Debug)]
pub struct AcpiData {
    /// ACPI revision (from RSDP)
    pub revision: u8,
    /// OEM ID
    pub oem_id: [u8; 6],
    /// Local APIC base address
    pub lapic_address: u64,
    /// Has legacy 8259 PICs
    pub has_legacy_pics: bool,
    /// Processors discovered
    pub processors: Vec<ProcessorInfo>,
    /// I/O APICs discovered
    pub ioapics: Vec<IoApicInfo>,
    /// Interrupt source overrides
    pub overrides: Vec<InterruptOverride>,
    /// NMI configurations
    pub nmis: Vec<NmiConfig>,
    /// NUMA memory regions
    pub numa_regions: Vec<NumaMemoryRegion>,
    /// PCIe segments (from MCFG)
    pub pcie_segments: Vec<PcieSegment>,
    /// HPET base address
    pub hpet_address: Option<u64>,
    /// PM1a control block
    pub pm1a_control: u32,
    /// PM1b control block
    pub pm1b_control: u32,
    /// SLP_TYPa values for each S-state
    pub slp_typ: [u8; 6],
    /// Reset register (if supported)
    pub reset_reg: Option<GenericAddress>,
    /// Reset value
    pub reset_value: u8,
    /// PM profile
    pub pm_profile: PmProfile,
    /// SCI interrupt
    pub sci_interrupt: u16,
}

impl AcpiData {
    fn new() -> Self {
        Self {
            revision: 0,
            oem_id: [0; 6],
            lapic_address: 0xFEE0_0000,
            has_legacy_pics: true,
            processors: Vec::new(),
            ioapics: Vec::new(),
            overrides: Vec::new(),
            nmis: Vec::new(),
            numa_regions: Vec::new(),
            pcie_segments: Vec::new(),
            hpet_address: None,
            pm1a_control: 0,
            pm1b_control: 0,
            slp_typ: [0; 6],
            reset_reg: None,
            reset_value: 0,
            pm_profile: PmProfile::Unspecified,
            sci_interrupt: 9,
        }
    }
}

// ============================================================================
// Table Registry
// ============================================================================

/// ACPI table collection
struct TableRegistry {
    /// RSDP data
    rsdp: RsdpExtended,
    /// All discovered tables: signature -> physical address
    tables: BTreeMap<u32, u64>,
    /// Parsed ACPI data
    data: AcpiData,
}

// ============================================================================
// Global State
// ============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static TABLES: RwLock<Option<TableRegistry>> = RwLock::new(None);
static STATS: RwLock<AcpiStats> = RwLock::new(AcpiStats::new());

/// ACPI statistics
#[derive(Debug, Clone, Copy)]
pub struct AcpiStats {
    /// Tables discovered
    pub tables_found: u32,
    /// Processors discovered
    pub processors_found: u32,
    /// I/O APICs discovered
    pub ioapics_found: u32,
    /// Interrupt overrides
    pub overrides_found: u32,
    /// NUMA nodes discovered
    pub numa_nodes: u32,
    /// PCIe segments
    pub pcie_segments: u32,
    /// Table parse errors
    pub parse_errors: u32,
}

impl AcpiStats {
    const fn new() -> Self {
        Self {
            tables_found: 0,
            processors_found: 0,
            ioapics_found: 0,
            overrides_found: 0,
            numa_nodes: 0,
            pcie_segments: 0,
            parse_errors: 0,
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize ACPI subsystem
pub fn init() -> AcpiResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(AcpiError::AlreadyInitialized);
    }

    // Find RSDP
    let rsdp = find_rsdp()?;

    // Create table registry
    let mut registry = TableRegistry {
        rsdp,
        tables: BTreeMap::new(),
        data: AcpiData::new(),
    };

    registry.data.revision = rsdp.base.revision;
    registry.data.oem_id = rsdp.base.oem_id;

    // Parse root table (XSDT preferred over RSDT)
    if rsdp.base.revision >= 2 && rsdp.xsdt_address != 0 {
        parse_xsdt(&mut registry, rsdp.xsdt_address)?;
    } else if rsdp.base.rsdt_address != 0 {
        parse_rsdt(&mut registry, rsdp.base.rsdt_address as u64)?;
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

    // Update stats
    {
        let mut stats = STATS.write();
        stats.tables_found = registry.tables.len() as u32;
        stats.processors_found = registry.data.processors.len() as u32;
        stats.ioapics_found = registry.data.ioapics.len() as u32;
        stats.overrides_found = registry.data.overrides.len() as u32;
        stats.pcie_segments = registry.data.pcie_segments.len() as u32;
    }

    // Store registry
    *TABLES.write() = Some(registry);

    Ok(())
}

/// Find RSDP in memory
fn find_rsdp() -> AcpiResult<RsdpExtended> {
    // Search EBDA
    unsafe {
        let ebda_segment = ptr::read_volatile(EBDA_PTR_ADDR as *const u16);
        if ebda_segment != 0 {
            let ebda_start = (ebda_segment as usize) << 4;
            if let Some(rsdp) = search_rsdp_range(ebda_start, 1024) {
                return Ok(rsdp);
            }
        }
    }

    // Search BIOS ROM area
    if let Some(rsdp) = search_rsdp_range(BIOS_ROM_START, BIOS_ROM_SIZE) {
        return Ok(rsdp);
    }

    Err(AcpiError::RsdpNotFound)
}

/// Search for RSDP in memory range
fn search_rsdp_range(start: usize, length: usize) -> Option<RsdpExtended> {
    for addr in (start..start + length).step_by(RSDP_ALIGNMENT) {
        unsafe {
            let ptr = addr as *const Rsdp;
            let sig = ptr::read_volatile(&(*ptr).signature);

            if sig == RSDP_SIGNATURE {
                let rsdp = ptr::read_volatile(ptr);

                // Validate base checksum
                if !rsdp.validate_checksum() {
                    continue;
                }

                if rsdp.revision >= 2 {
                    // ACPI 2.0+ extended RSDP
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

/// Parse RSDT
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

/// Parse XSDT
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

/// Parse FADT
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

        // Parse DSDT for _Sx sleep type values
        // (Simplified - full AML parsing would be complex)
        // Default S5 sleep type for QEMU/common systems
        registry.data.slp_typ[5] = 0; // S5 SLP_TYPa - varies by system
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
                0 => {
                    // Local APIC
                    if header.length >= mem::size_of::<MadtLocalApic>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const MadtLocalApic);
                        if entry.is_enabled() || entry.is_online_capable() {
                            registry.data.processors.push(ProcessorInfo {
                                apic_id: entry.apic_id as u32,
                                processor_uid: entry.processor_id as u32,
                                proximity_domain: 0,
                                is_x2apic: false,
                                enabled: entry.is_enabled(),
                            });
                        }
                    }
                }
                1 => {
                    // I/O APIC
                    if header.length >= mem::size_of::<MadtIoApic>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const MadtIoApic);
                        registry.data.ioapics.push(IoApicInfo {
                            id: entry.ioapic_id,
                            address: entry.address as u64,
                            gsi_base: entry.gsi_base,
                        });
                    }
                }
                2 => {
                    // Interrupt Source Override
                    if header.length >= mem::size_of::<MadtInterruptOverride>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const MadtInterruptOverride);
                        registry.data.overrides.push(InterruptOverride {
                            source_irq: entry.source,
                            gsi: entry.gsi,
                            polarity: entry.polarity(),
                            trigger_mode: entry.trigger_mode(),
                        });
                    }
                }
                4 => {
                    // Local APIC NMI
                    if header.length >= mem::size_of::<MadtLocalApicNmi>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const MadtLocalApicNmi);
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
                5 => {
                    // Local APIC Address Override
                    if header.length >= mem::size_of::<MadtLocalApicOverride>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const MadtLocalApicOverride);
                        registry.data.lapic_address = entry.address;
                    }
                }
                9 => {
                    // x2APIC
                    if header.length >= mem::size_of::<MadtLocalX2Apic>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const MadtLocalX2Apic);
                        if entry.is_enabled() {
                            registry.data.processors.push(ProcessorInfo {
                                apic_id: entry.x2apic_id,
                                processor_uid: entry.processor_uid,
                                proximity_domain: 0,
                                is_x2apic: true,
                                enabled: true,
                            });
                        }
                    }
                }
                10 => {
                    // x2APIC NMI
                    if header.length >= mem::size_of::<MadtLocalX2ApicNmi>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const MadtLocalX2ApicNmi);
                        registry.data.nmis.push(NmiConfig {
                            processor_uid: entry.processor_uid,
                            lint: entry.lint,
                            flags: entry.flags,
                        });
                    }
                }
                _ => {}
            }

            entry_ptr += header.length as u64;
        }
    }
}

/// Parse HPET
fn parse_hpet(registry: &mut TableRegistry) {
    if let Some(&addr) = registry.tables.get(&SIG_HPET) {
        unsafe {
            let hpet = ptr::read_volatile(addr as *const Hpet);
            if hpet.base_address.is_valid() {
                registry.data.hpet_address = Some(hpet.base_address.address);
            }
        }
    }
}

/// Parse MCFG
fn parse_mcfg(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_MCFG) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let mcfg = ptr::read_volatile(addr as *const Mcfg);
        let entry_count =
            (mcfg.header.length as usize - mem::size_of::<Mcfg>()) / mem::size_of::<McfgEntry>();
        let entries_ptr = (addr + mem::size_of::<Mcfg>() as u64) as *const McfgEntry;

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

/// Parse SRAT
fn parse_srat(registry: &mut TableRegistry) {
    let addr = match registry.tables.get(&SIG_SRAT) {
        Some(&a) => a,
        None => return,
    };

    unsafe {
        let srat = ptr::read_volatile(addr as *const Srat);
        let srat_end = addr + srat.header.length as u64;
        let mut entry_ptr = addr + mem::size_of::<Srat>() as u64;

        while entry_ptr + 2 <= srat_end {
            let entry_type = ptr::read_volatile(entry_ptr as *const u8);
            let length = ptr::read_volatile((entry_ptr + 1) as *const u8);

            if length < 2 || entry_ptr + length as u64 > srat_end {
                break;
            }

            match entry_type {
                0 => {
                    // Processor affinity
                    if length >= mem::size_of::<SratProcessorAffinity>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const SratProcessorAffinity);
                        if entry.is_enabled() {
                            // Update processor proximity domain
                            for proc in &mut registry.data.processors {
                                if proc.apic_id == entry.apic_id as u32 {
                                    proc.proximity_domain = entry.proximity_domain();
                                    break;
                                }
                            }
                        }
                    }
                }
                1 => {
                    // Memory affinity
                    if length >= mem::size_of::<SratMemoryAffinity>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const SratMemoryAffinity);
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
                2 => {
                    // x2APIC affinity
                    if length >= mem::size_of::<SratX2ApicAffinity>() as u8 {
                        let entry = ptr::read_volatile(entry_ptr as *const SratX2ApicAffinity);
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
                _ => {}
            }

            entry_ptr += length as u64;
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Returns true if ACPI is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Get ACPI revision
pub fn revision() -> Option<u8> {
    TABLES.read().as_ref().map(|t| t.data.revision)
}

/// Get OEM ID
pub fn oem_id() -> Option<[u8; 6]> {
    TABLES.read().as_ref().map(|t| t.data.oem_id)
}

/// Get Local APIC base address
pub fn lapic_address() -> Option<u64> {
    TABLES.read().as_ref().map(|t| t.data.lapic_address)
}

/// Check if legacy 8259 PICs are present
pub fn has_legacy_pics() -> Option<bool> {
    TABLES.read().as_ref().map(|t| t.data.has_legacy_pics)
}

/// Get discovered processors
pub fn processors() -> Vec<ProcessorInfo> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.processors.clone())
        .unwrap_or_default()
}

/// Get I/O APIC information
pub fn ioapics() -> Vec<IoApicInfo> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.ioapics.clone())
        .unwrap_or_default()
}

/// Get interrupt source overrides
pub fn interrupt_overrides() -> Vec<InterruptOverride> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.overrides.clone())
        .unwrap_or_default()
}

/// Get NMI configurations
pub fn nmi_configs() -> Vec<NmiConfig> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.nmis.clone())
        .unwrap_or_default()
}

/// Get NUMA memory regions
pub fn numa_regions() -> Vec<NumaMemoryRegion> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.numa_regions.clone())
        .unwrap_or_default()
}

/// Get PCIe segments
pub fn pcie_segments() -> Vec<PcieSegment> {
    TABLES
        .read()
        .as_ref()
        .map(|t| t.data.pcie_segments.clone())
        .unwrap_or_default()
}

/// Get HPET base address
pub fn hpet_address() -> Option<u64> {
    TABLES.read().as_ref().and_then(|t| t.data.hpet_address)
}

/// Get PM profile
pub fn pm_profile() -> Option<PmProfile> {
    TABLES.read().as_ref().map(|t| t.data.pm_profile)
}

/// Get SCI interrupt number
pub fn sci_interrupt() -> Option<u16> {
    TABLES.read().as_ref().map(|t| t.data.sci_interrupt)
}

/// Get statistics
pub fn stats() -> AcpiStats {
    *STATS.read()
}

/// Check if a table exists
pub fn has_table(signature: &[u8; 4]) -> bool {
    let sig = u32::from_le_bytes(*signature);
    TABLES
        .read()
        .as_ref()
        .map(|t| t.tables.contains_key(&sig))
        .unwrap_or(false)
}

/// Get raw table address
pub fn table_address(signature: &[u8; 4]) -> Option<u64> {
    let sig = u32::from_le_bytes(*signature);
    TABLES.read().as_ref().and_then(|t| t.tables.get(&sig).copied())
}

// ============================================================================
// Power Management
// ============================================================================

pub mod power {
    use super::*;

    /// ACPI sleep states
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub enum SleepState {
        /// S0 - Working state
        S0 = 0,
        /// S1 - Power on suspend (CPU stops, power to RAM/CPU)
        S1 = 1,
        /// S2 - CPU off (similar to S1, CPU context lost)
        S2 = 2,
        /// S3 - Suspend to RAM (STR)
        S3 = 3,
        /// S4 - Suspend to Disk (Hibernate)
        S4 = 4,
        /// S5 - Soft Off
        S5 = 5,
    }

    /// PM1 Control register bits
    const PM1_SCI_EN: u16 = 1 << 0;
    const PM1_SLP_TYP_SHIFT: u16 = 10;
    const PM1_SLP_EN: u16 = 1 << 13;

    /// Enter a sleep state
    pub fn enter_sleep_state(state: SleepState) -> AcpiResult<()> {
        let tables = TABLES.read();
        let registry = tables.as_ref().ok_or(AcpiError::NotInitialized)?;

        match state {
            SleepState::S0 => Ok(()), // Already awake
            SleepState::S5 => {
                // Soft off
                let pm1a = registry.data.pm1a_control;
                let pm1b = registry.data.pm1b_control;
                let slp_typ = registry.data.slp_typ[5];

                if pm1a == 0 {
                    return Err(AcpiError::HardwareAccessFailed);
                }

                // Write SLP_TYPa and SLP_EN
                let value = PM1_SLP_EN | ((slp_typ as u16) << PM1_SLP_TYP_SHIFT);

                unsafe {
                    crate::arch::x86_64::port::outw(pm1a as u16, value);
                    if pm1b != 0 {
                        crate::arch::x86_64::port::outw(pm1b as u16, value);
                    }
                }

                // If we get here, S5 failed
                Err(AcpiError::PowerStateNotSupported)
            }
            _ => Err(AcpiError::PowerStateNotSupported),
        }
    }

    /// Shutdown the system (S5)
    pub fn shutdown() -> AcpiResult<()> {
        enter_sleep_state(SleepState::S5)
    }

    /// Reboot the system
    pub fn reboot() -> AcpiResult<()> {
        let tables = TABLES.read();
        let registry = tables.as_ref().ok_or(AcpiError::NotInitialized)?;

        // Try ACPI reset register first
        if let Some(ref reset_reg) = registry.data.reset_reg {
            unsafe {
                match reset_reg.space() {
                    Some(AddressSpace::SystemIo) => {
                        crate::arch::x86_64::port::outb(
                            reset_reg.address as u16,
                            registry.data.reset_value,
                        );
                    }
                    Some(AddressSpace::SystemMemory) => {
                        ptr::write_volatile(
                            reset_reg.address as *mut u8,
                            registry.data.reset_value,
                        );
                    }
                    _ => {}
                }
            }
        }

        // Fallback: keyboard controller reset
        unsafe {
            crate::arch::x86_64::port::outb(0x64, 0xFE);
        }

        // If we get here, triple fault as last resort
        unsafe {
            // Load null IDT and trigger interrupt
            let null_idt: [u8; 6] = [0; 6];
            core::arch::asm!(
                "lidt [{}]",
                "int3",
                in(reg) &null_idt,
                options(noreturn)
            );
        }
    }

    /// Check if a sleep state is supported
    pub fn is_sleep_state_supported(state: SleepState) -> bool {
        match state {
            SleepState::S0 => true,
            SleepState::S5 => {
                TABLES
                    .read()
                    .as_ref()
                    .map(|t| t.data.pm1a_control != 0)
                    .unwrap_or(false)
            }
            _ => false, // S1-S4 require DSDT parsing
        }
    }
}

// ============================================================================
// MADT Parsing Helper (for legacy compatibility)
// ============================================================================

pub mod madt {
    use super::*;

    /// Parsed MADT data (legacy compatibility structure)
    #[derive(Debug)]
    pub struct ParsedMadt {
        pub lapic_addr: u64,
        pub ioapics: Vec<IoApicInfo>,
        pub isos: Vec<InterruptOverride>,
        pub nmis: Vec<NmiConfig>,
    }

    /// Parse MADT and return structured data
    pub fn parse_madt() -> Option<ParsedMadt> {
        let tables = TABLES.read();
        let registry = tables.as_ref()?;

        Some(ParsedMadt {
            lapic_addr: registry.data.lapic_address,
            ioapics: registry.data.ioapics.clone(),
            isos: registry.data.overrides.clone(),
            nmis: registry.data.nmis.clone(),
        })
    }
}

// ============================================================================
// Device Discovery
// ============================================================================

pub mod devices {
    use super::*;

    /// Get HPET base address
    pub fn get_hpet_base() -> Option<u64> {
        hpet_address()
    }

    /// Get Local APIC base address
    pub fn get_lapic_base() -> Option<u64> {
        lapic_address()
    }

    /// Get PCIe ECAM base for a segment/bus
    pub fn get_pcie_ecam(segment: u16, bus: u8) -> Option<u64> {
        for seg in pcie_segments() {
            if seg.segment == segment && bus >= seg.start_bus && bus <= seg.end_bus {
                return Some(seg.base_address);
            }
        }
        None
    }

    /// Enumerate PCI devices using MCFG
    pub fn enumerate_pci_devices() -> Vec<(u16, u8, u8, u8)> {
        let mut devices = Vec::new();

        for seg in pcie_segments() {
            for bus in seg.start_bus..=seg.end_bus {
                for device in 0..32u8 {
                    for function in 0..8u8 {
                        let config_addr = seg.base_address
                            + ((bus as u64) << 20)
                            + ((device as u64) << 15)
                            + ((function as u64) << 12);

                        unsafe {
                            let vendor_id = ptr::read_volatile(config_addr as *const u16);
                            if vendor_id != 0xFFFF {
                                devices.push((seg.segment, bus, device, function));

                                // Check if multi-function
                                if function == 0 {
                                    let header_type =
                                        ptr::read_volatile((config_addr + 0x0E) as *const u8);
                                    if header_type & 0x80 == 0 {
                                        break; // Not multi-function
                                    }
                                }
                            } else if function == 0 {
                                break; // No device at function 0
                            }
                        }
                    }
                }
            }
        }

        devices
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsdp_signature() {
        assert_eq!(&RSDP_SIGNATURE, b"RSD PTR ");
    }

    #[test]
    fn test_table_signatures() {
        assert_eq!(SIG_FADT, u32::from_le_bytes(*b"FACP"));
        assert_eq!(SIG_MADT, u32::from_le_bytes(*b"APIC"));
        assert_eq!(SIG_HPET, u32::from_le_bytes(*b"HPET"));
    }

    #[test]
    fn test_sdt_header_size() {
        assert_eq!(mem::size_of::<SdtHeader>(), 36);
    }

    #[test]
    fn test_rsdp_size() {
        assert_eq!(mem::size_of::<Rsdp>(), 20);
    }

    #[test]
    fn test_rsdp_extended_size() {
        assert_eq!(mem::size_of::<RsdpExtended>(), 36);
    }

    #[test]
    fn test_generic_address_size() {
        assert_eq!(mem::size_of::<GenericAddress>(), 12);
    }

    #[test]
    fn test_acpi_error_messages() {
        assert_eq!(AcpiError::NotInitialized.as_str(), "ACPI not initialized");
        assert_eq!(AcpiError::RsdpNotFound.as_str(), "RSDP not found in memory");
    }

    #[test]
    fn test_pm_profile() {
        assert_eq!(PmProfile::Desktop as u8, 1);
        assert_eq!(PmProfile::Mobile as u8, 2);
    }

    #[test]
    fn test_sleep_state() {
        assert_eq!(power::SleepState::S0 as u8, 0);
        assert_eq!(power::SleepState::S5 as u8, 5);
    }

    #[test]
    fn test_madt_entry_types() {
        assert_eq!(MadtEntryType::LocalApic as u8, 0);
        assert_eq!(MadtEntryType::IoApic as u8, 1);
        assert_eq!(MadtEntryType::LocalX2Apic as u8, 9);
    }

    #[test]
    fn test_stats_initial() {
        let stats = AcpiStats::new();
        assert_eq!(stats.tables_found, 0);
        assert_eq!(stats.processors_found, 0);
    }

    #[test]
    fn test_address_space() {
        assert_eq!(AddressSpace::SystemMemory as u8, 0);
        assert_eq!(AddressSpace::SystemIo as u8, 1);
    }

    #[test]
    fn test_fadt_flags() {
        assert_eq!(fadt_flags::RESET_REG_SUP, 1 << 10);
        assert_eq!(fadt_flags::HW_REDUCED_ACPI, 1 << 20);
    }

    #[test]
    fn test_interrupt_override() {
        let ovr = InterruptOverride {
            source_irq: 0,
            gsi: 2,
            polarity: 1,
            trigger_mode: 3,
        };
        assert_eq!(ovr.source_irq, 0);
        assert_eq!(ovr.gsi, 2);
    }
}
