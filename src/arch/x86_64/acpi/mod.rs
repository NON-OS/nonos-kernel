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

pub mod nonos_acpi;

// ============================================================================
// Error Types
// ============================================================================

pub use nonos_acpi::AcpiError;
pub use nonos_acpi::AcpiResult;

// ============================================================================
// RSDP Structures
// ============================================================================

pub use nonos_acpi::Rsdp;
pub use nonos_acpi::RsdpExtended;

// ============================================================================
// Table Structures
// ============================================================================

pub use nonos_acpi::SdtHeader;
pub use nonos_acpi::GenericAddress;
pub use nonos_acpi::AddressSpace;

// ============================================================================
// FADT
// ============================================================================

pub use nonos_acpi::Fadt;
pub use nonos_acpi::PmProfile;
pub use nonos_acpi::fadt_flags;

// ============================================================================
// MADT
// ============================================================================

pub use nonos_acpi::Madt;
pub use nonos_acpi::MadtEntryType;
pub use nonos_acpi::MadtEntryHeader;
pub use nonos_acpi::MadtLocalApic;
pub use nonos_acpi::MadtIoApic;
pub use nonos_acpi::MadtInterruptOverride;
pub use nonos_acpi::MadtNmiSource;
pub use nonos_acpi::MadtLocalApicNmi;
pub use nonos_acpi::MadtLocalApicOverride;
pub use nonos_acpi::MadtLocalX2Apic;
pub use nonos_acpi::MadtLocalX2ApicNmi;
pub use nonos_acpi::madt_flags;

// ============================================================================
// HPET
// ============================================================================

pub use nonos_acpi::Hpet;

// ============================================================================
// MCFG (PCIe)
// ============================================================================

pub use nonos_acpi::Mcfg;
pub use nonos_acpi::McfgEntry;

// ============================================================================
// SRAT/SLIT (NUMA)
// ============================================================================

pub use nonos_acpi::Srat;
pub use nonos_acpi::SratEntryType;
pub use nonos_acpi::SratProcessorAffinity;
pub use nonos_acpi::SratMemoryAffinity;
pub use nonos_acpi::SratX2ApicAffinity;
pub use nonos_acpi::Slit;

// ============================================================================
// Parsed Data Structures
// ============================================================================

pub use nonos_acpi::ProcessorInfo;
pub use nonos_acpi::IoApicInfo;
pub use nonos_acpi::InterruptOverride;
pub use nonos_acpi::NmiConfig;
pub use nonos_acpi::NumaMemoryRegion;
pub use nonos_acpi::PcieSegment;
pub use nonos_acpi::AcpiData;
pub use nonos_acpi::AcpiStats;

// ============================================================================
// Submodules
// ============================================================================

pub use nonos_acpi::power;
pub use nonos_acpi::madt;
pub use nonos_acpi::devices;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize ACPI subsystem
#[inline]
pub fn init() -> AcpiResult<()> {
    nonos_acpi::init()
}

/// Check if ACPI is initialized
#[inline]
pub fn is_initialized() -> bool {
    nonos_acpi::is_initialized()
}

// ============================================================================
// Query Functions
// ============================================================================

/// Get ACPI revision
#[inline]
pub fn revision() -> Option<u8> {
    nonos_acpi::revision()
}

/// Get OEM ID
#[inline]
pub fn oem_id() -> Option<[u8; 6]> {
    nonos_acpi::oem_id()
}

/// Get Local APIC base address
#[inline]
pub fn lapic_address() -> Option<u64> {
    nonos_acpi::lapic_address()
}

/// Check if legacy 8259 PICs are present
#[inline]
pub fn has_legacy_pics() -> Option<bool> {
    nonos_acpi::has_legacy_pics()
}

/// Get discovered processors
#[inline]
pub fn processors() -> alloc::vec::Vec<ProcessorInfo> {
    nonos_acpi::processors()
}

/// Get I/O APIC information
#[inline]
pub fn ioapics() -> alloc::vec::Vec<IoApicInfo> {
    nonos_acpi::ioapics()
}

/// Get interrupt source overrides
#[inline]
pub fn interrupt_overrides() -> alloc::vec::Vec<InterruptOverride> {
    nonos_acpi::interrupt_overrides()
}

/// Get NMI configurations
#[inline]
pub fn nmi_configs() -> alloc::vec::Vec<NmiConfig> {
    nonos_acpi::nmi_configs()
}

/// Get NUMA memory regions
#[inline]
pub fn numa_regions() -> alloc::vec::Vec<NumaMemoryRegion> {
    nonos_acpi::numa_regions()
}

/// Get PCIe segments
#[inline]
pub fn pcie_segments() -> alloc::vec::Vec<PcieSegment> {
    nonos_acpi::pcie_segments()
}

/// Get HPET base address
#[inline]
pub fn hpet_address() -> Option<u64> {
    nonos_acpi::hpet_address()
}

/// Get PM profile
#[inline]
pub fn pm_profile() -> Option<PmProfile> {
    nonos_acpi::pm_profile()
}

/// Get SCI interrupt number
#[inline]
pub fn sci_interrupt() -> Option<u16> {
    nonos_acpi::sci_interrupt()
}

/// Get statistics
#[inline]
pub fn stats() -> AcpiStats {
    nonos_acpi::stats()
}

/// Check if a table exists
#[inline]
pub fn has_table(signature: &[u8; 4]) -> bool {
    nonos_acpi::has_table(signature)
}

/// Get raw table address
#[inline]
pub fn table_address(signature: &[u8; 4]) -> Option<u64> {
    nonos_acpi::table_address(signature)
}
