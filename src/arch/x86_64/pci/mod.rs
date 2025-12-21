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
// NØNOS x86_64 PCI Module


pub mod nonos_pci;

// ============================================================================
// Structures
// ============================================================================

pub use nonos_pci::PciDevice;
pub use nonos_pci::PciBar;
pub use nonos_pci::PciCapability;
pub use nonos_pci::PciStats;

// ============================================================================
// DMA Support
// ============================================================================

pub use nonos_pci::DmaEngine;
pub use nonos_pci::DmaDirection;
pub use nonos_pci::DmaBuffer;
pub use nonos_pci::DmaDescriptor;

// ============================================================================
// MSI-X Support
// ============================================================================

pub use nonos_pci::MsixCapability;
pub use nonos_pci::MsixTableEntry;

// ============================================================================
// Class Codes
// ============================================================================

pub use nonos_pci::class_codes;
pub use nonos_pci::get_class_name;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize PCI subsystem
#[inline]
pub fn init() -> Result<(), &'static str> {
    nonos_pci::init()
}

// ============================================================================
// Bus Scanning
// ============================================================================

/// Scan PCI bus for all devices
#[inline]
pub fn scan_pci_bus() -> Result<alloc::vec::Vec<PciDevice>, &'static str> {
    nonos_pci::scan_pci_bus()
}

// ============================================================================
// Configuration Space Access
// ============================================================================

/// Read 32-bit value from PCI configuration space
#[inline]
pub fn pci_config_read_dword(bus: u8, slot: u8, function: u8, offset: u16) -> u32 {
    nonos_pci::pci_config_read_dword(bus, slot, function, offset)
}

/// Write 32-bit value to PCI configuration space
#[inline]
pub fn pci_config_write_dword(bus: u8, slot: u8, function: u8, offset: u16, value: u32) {
    nonos_pci::pci_config_write_dword(bus, slot, function, offset, value)
}

/// Read 16-bit value from PCI configuration space
#[inline]
pub fn pci_config_read_word(bus: u8, slot: u8, function: u8, offset: u16) -> u16 {
    nonos_pci::pci_config_read_word(bus, slot, function, offset)
}

/// Write 16-bit value to PCI configuration space
#[inline]
pub fn pci_config_write_word(bus: u8, slot: u8, function: u8, offset: u16, value: u16) {
    nonos_pci::pci_config_write_word(bus, slot, function, offset, value)
}

/// Read 8-bit value from PCI configuration space
#[inline]
pub fn pci_config_read_byte(bus: u8, slot: u8, function: u8, offset: u16) -> u8 {
    nonos_pci::pci_config_read_byte(bus, slot, function, offset)
}

/// Write 8-bit value to PCI configuration space
#[inline]
pub fn pci_config_write_byte(bus: u8, slot: u8, function: u8, offset: u16, value: u8) {
    nonos_pci::pci_config_write_byte(bus, slot, function, offset, value)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get PCI statistics
#[inline]
pub fn get_pci_stats() -> PciStats {
    nonos_pci::get_pci_stats()
}

/// Record a PCI interrupt
#[inline]
pub fn record_interrupt() {
    nonos_pci::record_interrupt()
}

/// Record an MSI/MSI-X interrupt
#[inline]
pub fn record_msi_interrupt() {
    nonos_pci::record_msi_interrupt()
}

/// Record a DMA transfer
#[inline]
pub fn record_dma_transfer(bytes: u64) {
    nonos_pci::record_dma_transfer(bytes)
}

/// Record a PCI error
#[inline]
pub fn record_pci_error() {
    nonos_pci::record_pci_error()
}
