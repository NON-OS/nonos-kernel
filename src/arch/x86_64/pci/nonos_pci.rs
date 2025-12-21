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
//!
//! PCI Bus Management
//! ## Architecture
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         PCI Subsystem                                   │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │   ┌───────────────┐    ┌───────────────┐    ┌───────────────┐           │
//! │   │  Config Space │    │   DMA Engine  │    │   Statistics  │           │
//! │   │  ───────────  │    │  ───────────  │    │  ───────────  │           │
//! │   │  0xCF8/0xCFC  │    │  Coherent     │    │  AtomicU64    │           │
//! │   │  read/write   │    │  Streaming    │    │  RwLock       │           │
//! │   │  byte/word/dw │    │  Sync/Flush   │    │  Lock-free    │           │
//! │   └───────────────┘    └───────────────┘    └───────────────┘           │
//! │                                                                         │
//! │   PCI Configuration Address (0xCF8):                                    │
//! │   ┌─────────────────────────────────────────────────────────────────┐   │
//! │   │ 31    │ 30-24  │ 23-16 │ 15-11  │ 10-8     │ 7-2    │ 1-0       │   │
//! │   │ Enable│Reserved│  Bus  │ Device │ Function │ Offset │ Always 0  │   │
//! │   └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! │   Device Discovery:                                                     │
//! │   ┌─────────────────────────────────────────────────────────────────┐   │
//! │   │  Bus 0-255 → Slot 0-31 → Function 0-7 (if multifunction)        │   │
//! │   │  Check vendor_id != 0xFFFF for device presence                  │   │
//! │   └─────────────────────────────────────────────────────────────────┘   │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘

use alloc::{vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{RwLock, Mutex};
use x86_64::{PhysAddr, VirtAddr};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Maximum number of PCI buses to scan
pub const MAX_PCI_BUSES: u16 = 256;

/// Maximum devices per bus
pub const MAX_DEVICES_PER_BUS: u8 = 32;

/// Maximum functions per device
pub const MAX_FUNCTIONS_PER_DEVICE: u8 = 8;

/// Maximum BARs per device
pub const MAX_BARS: u8 = 6;

/// PCI configuration address port
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;

/// PCI configuration data port
const PCI_CONFIG_DATA: u16 = 0xCFC;

// ============================================================================
// Error Handling
// ============================================================================

/// PCI subsystem errors with detailed context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    /// PCI subsystem not initialized
    NotInitialized,
    /// PCI subsystem already initialized
    AlreadyInitialized,
    /// Device not found at specified location
    DeviceNotFound { bus: u8, slot: u8, function: u8 },
    /// Invalid BAR index (must be 0-5)
    InvalidBarIndex { index: u8 },
    /// BAR not implemented by device
    BarNotImplemented { bar: u8 },
    /// 64-bit BAR requires two consecutive BARs
    Bar64BitSpansTwo { bar: u8 },
    /// PCI capability not found
    CapabilityNotFound { cap_id: u8 },
    /// MSI-X not supported by device
    MsixNotSupported,
    /// MSI not supported by device
    MsiNotSupported,
    /// DMA buffer allocation failed
    DmaAllocationFailed { size: usize },
    /// DMA buffer not aligned to required boundary
    DmaNotAligned { addr: u64, required: usize },
    /// Invalid configuration access parameters
    InvalidConfigAccess { bus: u8, slot: u8, function: u8, offset: u16 },
    /// Bus mastering not enabled on device
    BusMasteringDisabled,
    /// Memory space access not enabled on device
    MemorySpaceDisabled,
    /// I/O space access not enabled on device
    IoSpaceDisabled,
    /// Configuration space access denied
    ConfigAccessDenied,
    /// Device in error state
    DeviceError { status: u16 },
    /// Timeout waiting for device
    Timeout,
}

impl PciError {
    /// Returns human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "PCI subsystem not initialized",
            Self::AlreadyInitialized => "PCI subsystem already initialized",
            Self::DeviceNotFound { .. } => "PCI device not found at specified location",
            Self::InvalidBarIndex { .. } => "invalid BAR index (must be 0-5)",
            Self::BarNotImplemented { .. } => "BAR not implemented by device",
            Self::Bar64BitSpansTwo { .. } => "64-bit BAR spans two consecutive BARs",
            Self::CapabilityNotFound { .. } => "PCI capability not found",
            Self::MsixNotSupported => "MSI-X not supported by device",
            Self::MsiNotSupported => "MSI not supported by device",
            Self::DmaAllocationFailed { .. } => "DMA buffer allocation failed",
            Self::DmaNotAligned { .. } => "DMA buffer not properly aligned",
            Self::InvalidConfigAccess { .. } => "invalid PCI configuration access",
            Self::BusMasteringDisabled => "bus mastering not enabled on device",
            Self::MemorySpaceDisabled => "memory space access not enabled",
            Self::IoSpaceDisabled => "I/O space access not enabled",
            Self::ConfigAccessDenied => "PCI configuration access denied",
            Self::DeviceError { .. } => "PCI device reported error",
            Self::Timeout => "timeout waiting for PCI device",
        }
    }
}

/// Result type for PCI operations
pub type PciResult<T> = Result<T, PciError>;

// ============================================================================
// PCI Configuration Space Offsets
// ============================================================================

/// Standard PCI configuration space offsets
pub mod config {
    pub const VENDOR_ID: u16 = 0x00;
    pub const DEVICE_ID: u16 = 0x02;
    pub const COMMAND: u16 = 0x04;
    pub const STATUS: u16 = 0x06;
    pub const REVISION_ID: u16 = 0x08;
    pub const PROG_IF: u16 = 0x09;
    pub const SUBCLASS: u16 = 0x0A;
    pub const CLASS_CODE: u16 = 0x0B;
    pub const CACHE_LINE_SIZE: u16 = 0x0C;
    pub const LATENCY_TIMER: u16 = 0x0D;
    pub const HEADER_TYPE: u16 = 0x0E;
    pub const BIST: u16 = 0x0F;
    pub const BAR0: u16 = 0x10;
    pub const BAR1: u16 = 0x14;
    pub const BAR2: u16 = 0x18;
    pub const BAR3: u16 = 0x1C;
    pub const BAR4: u16 = 0x20;
    pub const BAR5: u16 = 0x24;
    pub const CARDBUS_CIS: u16 = 0x28;
    pub const SUBSYSTEM_VENDOR_ID: u16 = 0x2C;
    pub const SUBSYSTEM_ID: u16 = 0x2E;
    pub const EXPANSION_ROM: u16 = 0x30;
    pub const CAPABILITIES_PTR: u16 = 0x34;
    pub const INTERRUPT_LINE: u16 = 0x3C;
    pub const INTERRUPT_PIN: u16 = 0x3D;
    pub const MIN_GRANT: u16 = 0x3E;
    pub const MAX_LATENCY: u16 = 0x3F;
}

/// PCI command register bits
pub mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MWI_ENABLE: u16 = 1 << 4;
    pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
    pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
    pub const SERR_ENABLE: u16 = 1 << 8;
    pub const FAST_B2B_ENABLE: u16 = 1 << 9;
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

/// PCI status register bits
pub mod status {
    pub const INTERRUPT_STATUS: u16 = 1 << 3;
    pub const CAPABILITIES_LIST: u16 = 1 << 4;
    pub const MHZ_66_CAPABLE: u16 = 1 << 5;
    pub const FAST_B2B_CAPABLE: u16 = 1 << 7;
    pub const MASTER_DATA_PARITY_ERROR: u16 = 1 << 8;
    pub const SIGNALED_TARGET_ABORT: u16 = 1 << 11;
    pub const RECEIVED_TARGET_ABORT: u16 = 1 << 12;
    pub const RECEIVED_MASTER_ABORT: u16 = 1 << 13;
    pub const SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
    pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
}

/// PCI capability IDs
pub mod capability {
    pub const POWER_MANAGEMENT: u8 = 0x01;
    pub const AGP: u8 = 0x02;
    pub const VPD: u8 = 0x03;
    pub const SLOT_ID: u8 = 0x04;
    pub const MSI: u8 = 0x05;
    pub const HOT_SWAP: u8 = 0x06;
    pub const PCI_X: u8 = 0x07;
    pub const HYPERTRANSPORT: u8 = 0x08;
    pub const VENDOR_SPECIFIC: u8 = 0x09;
    pub const DEBUG_PORT: u8 = 0x0A;
    pub const CPCI_CONTROL: u8 = 0x0B;
    pub const HOT_PLUG: u8 = 0x0C;
    pub const BRIDGE_SUBSYSTEM_VENDOR_ID: u8 = 0x0D;
    pub const AGP_8X: u8 = 0x0E;
    pub const SECURE_DEVICE: u8 = 0x0F;
    pub const PCI_EXPRESS: u8 = 0x10;
    pub const MSIX: u8 = 0x11;
    pub const SATA: u8 = 0x12;
    pub const AF: u8 = 0x13;
}

// ============================================================================
// Global State
// ============================================================================

/// PCI subsystem initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Global PCI statistics (RwLock for concurrent reads)
static PCI_STATS: RwLock<PciStats> = RwLock::new(PciStats::new());

/// Discovered devices cache
static DEVICE_CACHE: RwLock<Vec<PciDevice>> = RwLock::new(Vec::new());

/// Atomic counters for lock-free statistics
static INTERRUPT_COUNTER: AtomicU64 = AtomicU64::new(0);
static MSI_INTERRUPT_COUNTER: AtomicU64 = AtomicU64::new(0);
static DMA_TRANSFER_COUNTER: AtomicU64 = AtomicU64::new(0);
static DMA_BYTES_COUNTER: AtomicU64 = AtomicU64::new(0);
static CONFIG_READ_COUNTER: AtomicU64 = AtomicU64::new(0);
static CONFIG_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);
static ERROR_COUNTER: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Port I/O Helpers (Encapsulated Unsafe)
// ============================================================================

/// Safe wrapper for port I/O operations
mod port_io {
    use super::*;

    /// Read 32-bit value from I/O port
    ///
    /// # Safety
    /// This is safe because we only access known PCI configuration ports.
    #[inline]
    pub fn read_u32(port: u16) -> u32 {
        unsafe {
            let value: u32;
            core::arch::asm!(
                "in eax, dx",
                out("eax") value,
                in("dx") port,
                options(nomem, nostack, preserves_flags)
            );
            value
        }
    }

    /// Write 32-bit value to I/O port
    ///
    /// # Safety
    /// This is safe because we only access known PCI configuration ports.
    #[inline]
    pub fn write_u32(port: u16, value: u32) {
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    /// Flush cache line at address
    #[inline]
    pub fn clflush(addr: usize) {
        unsafe {
            core::arch::asm!(
                "clflush [{}]",
                in(reg) addr,
                options(nostack, preserves_flags)
            );
        }
    }

    /// Memory fence
    #[inline]
    pub fn mfence() {
        unsafe {
            core::arch::asm!("mfence", options(nostack, preserves_flags));
        }
    }
}

// ============================================================================
// PCI Configuration Space Access
// ============================================================================

/// Build PCI configuration address
#[inline]
fn make_config_address(bus: u8, slot: u8, function: u8, offset: u16) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((slot as u32 & 0x1F) << 11)
        | ((function as u32 & 0x07) << 8)
        | ((offset as u32) & 0xFC)
}

/// Read 32-bit value from PCI configuration space
#[inline]
pub fn pci_config_read_dword(bus: u8, slot: u8, function: u8, offset: u16) -> u32 {
    CONFIG_READ_COUNTER.fetch_add(1, Ordering::Relaxed);
    let address = make_config_address(bus, slot, function, offset);
    port_io::write_u32(PCI_CONFIG_ADDRESS, address);
    port_io::read_u32(PCI_CONFIG_DATA)
}

/// Write 32-bit value to PCI configuration space
#[inline]
pub fn pci_config_write_dword(bus: u8, slot: u8, function: u8, offset: u16, value: u32) {
    CONFIG_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let address = make_config_address(bus, slot, function, offset);
    port_io::write_u32(PCI_CONFIG_ADDRESS, address);
    port_io::write_u32(PCI_CONFIG_DATA, value);
}

/// Read 16-bit value from PCI configuration space
#[inline]
pub fn pci_config_read_word(bus: u8, slot: u8, function: u8, offset: u16) -> u16 {
    let dword = pci_config_read_dword(bus, slot, function, offset & 0xFFFC);
    let shift = ((offset & 2) * 8) as u32;
    ((dword >> shift) & 0xFFFF) as u16
}

/// Write 16-bit value to PCI configuration space
#[inline]
pub fn pci_config_write_word(bus: u8, slot: u8, function: u8, offset: u16, value: u16) {
    let aligned_offset = offset & 0xFFFC;
    let mut dword = pci_config_read_dword(bus, slot, function, aligned_offset);
    let shift = ((offset & 2) * 8) as u32;
    dword = (dword & !(0xFFFF << shift)) | ((value as u32) << shift);
    pci_config_write_dword(bus, slot, function, aligned_offset, dword);
}

/// Read 8-bit value from PCI configuration space
#[inline]
pub fn pci_config_read_byte(bus: u8, slot: u8, function: u8, offset: u16) -> u8 {
    let dword = pci_config_read_dword(bus, slot, function, offset & 0xFFFC);
    let shift = ((offset & 3) * 8) as u32;
    ((dword >> shift) & 0xFF) as u8
}

/// Write 8-bit value to PCI configuration space
#[inline]
pub fn pci_config_write_byte(bus: u8, slot: u8, function: u8, offset: u16, value: u8) {
    let aligned_offset = offset & 0xFFFC;
    let mut dword = pci_config_read_dword(bus, slot, function, aligned_offset);
    let shift = ((offset & 3) * 8) as u32;
    dword = (dword & !(0xFF << shift)) | ((value as u32) << shift);
    pci_config_write_dword(bus, slot, function, aligned_offset, dword);
}

// ============================================================================
// PCI Device
// ============================================================================

/// PCI device representation with full configuration
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    /// Bus number (0-255)
    pub bus: u8,
    /// Slot/device number (0-31)
    pub slot: u8,
    /// Function number (0-7)
    pub function: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Class code (major device class)
    pub class_code: u8,
    /// Subclass
    pub subclass: u8,
    /// Programming interface
    pub prog_if: u8,
    /// Revision ID
    pub revision_id: u8,
    /// Header type (0=standard, 1=PCI-PCI bridge, 2=CardBus)
    pub header_type: u8,
    /// Interrupt line
    pub interrupt_line: u8,
    /// Interrupt pin (0=none, 1=INTA, 2=INTB, 3=INTC, 4=INTD)
    pub interrupt_pin: u8,
    /// Subsystem vendor ID
    pub subsystem_vendor_id: u16,
    /// Subsystem ID
    pub subsystem_id: u16,
    /// Whether device is multi-function
    pub multifunction: bool,
}

impl PciDevice {
    /// Create PCI device from bus location
    pub fn new(bus: u8, slot: u8, function: u8) -> Option<Self> {
        let vendor_id = pci_config_read_word(bus, slot, function, config::VENDOR_ID);

        // 0xFFFF means no device present
        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id = pci_config_read_word(bus, slot, function, config::DEVICE_ID);
        let class_code = pci_config_read_byte(bus, slot, function, config::CLASS_CODE);
        let subclass = pci_config_read_byte(bus, slot, function, config::SUBCLASS);
        let prog_if = pci_config_read_byte(bus, slot, function, config::PROG_IF);
        let revision_id = pci_config_read_byte(bus, slot, function, config::REVISION_ID);
        let raw_header_type = pci_config_read_byte(bus, slot, function, config::HEADER_TYPE);
        let header_type = raw_header_type & 0x7F;
        let multifunction = (raw_header_type & 0x80) != 0;
        let interrupt_line = pci_config_read_byte(bus, slot, function, config::INTERRUPT_LINE);
        let interrupt_pin = pci_config_read_byte(bus, slot, function, config::INTERRUPT_PIN);
        let subsystem_vendor_id = pci_config_read_word(bus, slot, function, config::SUBSYSTEM_VENDOR_ID);
        let subsystem_id = pci_config_read_word(bus, slot, function, config::SUBSYSTEM_ID);

        Some(PciDevice {
            bus,
            slot,
            function,
            vendor_id,
            device_id,
            class_code,
            subclass,
            prog_if,
            revision_id,
            header_type,
            interrupt_line,
            interrupt_pin,
            subsystem_vendor_id,
            subsystem_id,
            multifunction,
        })
    }

    /// Get BDF (Bus:Device.Function) address
    #[inline]
    pub fn bdf(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.slot as u16) << 3) | (self.function as u16)
    }

    /// Read command register
    #[inline]
    pub fn read_command(&self) -> u16 {
        pci_config_read_word(self.bus, self.slot, self.function, config::COMMAND)
    }

    /// Write command register
    #[inline]
    pub fn write_command(&self, value: u16) {
        pci_config_write_word(self.bus, self.slot, self.function, config::COMMAND, value);
    }

    /// Read status register
    #[inline]
    pub fn read_status(&self) -> u16 {
        pci_config_read_word(self.bus, self.slot, self.function, config::STATUS)
    }

    /// Enable bus mastering for DMA operations
    pub fn enable_bus_mastering(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::BUS_MASTER;
        self.write_command(cmd);

        // Verify it was set
        if (self.read_command() & command::BUS_MASTER) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::BusMasteringDisabled);
        }
        Ok(())
    }

    /// Enable memory space access
    pub fn enable_memory_space(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::MEMORY_SPACE;
        self.write_command(cmd);

        if (self.read_command() & command::MEMORY_SPACE) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::MemorySpaceDisabled);
        }
        Ok(())
    }

    /// Enable I/O space access
    pub fn enable_io_space(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::IO_SPACE;
        self.write_command(cmd);

        if (self.read_command() & command::IO_SPACE) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::IoSpaceDisabled);
        }
        Ok(())
    }

    /// Disable interrupts
    pub fn disable_interrupts(&self) {
        let mut cmd = self.read_command();
        cmd |= command::INTERRUPT_DISABLE;
        self.write_command(cmd);
    }

    /// Enable interrupts
    pub fn enable_interrupts(&self) {
        let mut cmd = self.read_command();
        cmd &= !command::INTERRUPT_DISABLE;
        self.write_command(cmd);
    }

    /// Get Base Address Register (BAR)
    pub fn get_bar(&self, bar_index: u8) -> PciResult<PciBar> {
        if bar_index >= MAX_BARS {
            return Err(PciError::InvalidBarIndex { index: bar_index });
        }

        let bar_offset = config::BAR0 + (bar_index as u16 * 4);
        let bar_value = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);

        if bar_value == 0 {
            return Err(PciError::BarNotImplemented { bar: bar_index });
        }

        let is_io = (bar_value & 1) != 0;

        if is_io {
            // I/O BAR
            let base_addr = (bar_value & !0x3) as u64;

            // Get size by writing all 1s and reading back
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, 0xFFFFFFFF);
            let size_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, bar_value);

            let size = (!(size_mask & !0x3)).wrapping_add(1) as u64 & 0xFFFF;

            Ok(PciBar {
                base_addr,
                size,
                bar_type: BarType::Io,
                prefetchable: false,
                is_64bit: false,
            })
        } else {
            // Memory BAR
            let prefetchable = (bar_value & 0x08) != 0;
            let bar_type_bits = (bar_value >> 1) & 0x03;
            let is_64bit = bar_type_bits == 2;

            let base_addr = if is_64bit {
                if bar_index >= 5 {
                    return Err(PciError::Bar64BitSpansTwo { bar: bar_index });
                }
                let high = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset + 4);
                ((high as u64) << 32) | ((bar_value & !0xF) as u64)
            } else {
                (bar_value & !0xF) as u64
            };

            // Get size
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, 0xFFFFFFFF);
            let size_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, bar_value);

            let size = if is_64bit {
                pci_config_write_dword(self.bus, self.slot, self.function, bar_offset + 4, 0xFFFFFFFF);
                let high_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset + 4);
                let high_orig = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset + 4);
                pci_config_write_dword(self.bus, self.slot, self.function, bar_offset + 4, high_orig);

                let full_mask = ((high_mask as u64) << 32) | ((size_mask & !0xF) as u64);
                (!full_mask).wrapping_add(1)
            } else {
                (!(size_mask & !0xF)).wrapping_add(1) as u64
            };

            Ok(PciBar {
                base_addr,
                size,
                bar_type: BarType::Memory,
                prefetchable,
                is_64bit,
            })
        }
    }

    /// Find PCI capability by ID
    pub fn find_capability(&self, cap_id: u8) -> Option<u8> {
        let status = self.read_status();
        if (status & status::CAPABILITIES_LIST) == 0 {
            return None;
        }

        let mut cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, config::CAPABILITIES_PTR) & 0xFC;

        // Walk capability list (limit iterations to prevent infinite loop)
        for _ in 0..48 {
            if cap_ptr == 0 {
                break;
            }

            let id = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr as u16);
            if id == cap_id {
                return Some(cap_ptr);
            }

            cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, (cap_ptr + 1) as u16) & 0xFC;
        }

        None
    }

    /// Get all capabilities
    pub fn get_capabilities(&self) -> Vec<PciCapability> {
        let mut caps = Vec::new();
        let status = self.read_status();

        if (status & status::CAPABILITIES_LIST) == 0 {
            return caps;
        }

        let mut cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, config::CAPABILITIES_PTR) & 0xFC;

        for _ in 0..48 {
            if cap_ptr == 0 {
                break;
            }

            let id = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr as u16);
            let next = pci_config_read_byte(self.bus, self.slot, self.function, (cap_ptr + 1) as u16) & 0xFC;

            caps.push(PciCapability {
                id,
                offset: cap_ptr,
                next,
            });

            cap_ptr = next;
        }

        caps
    }

    /// Configure MSI-X interrupts
    pub fn configure_msix(&self, table_index: u16, addr: u64, data: u32) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX)
            .ok_or(PciError::MsixNotSupported)?;

        // Read MSI-X capability structure
        let msg_ctrl = pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        let table_size = (msg_ctrl & 0x7FF) + 1;

        if table_index >= table_size {
            return Err(PciError::InvalidConfigAccess {
                bus: self.bus,
                slot: self.slot,
                function: self.function,
                offset: table_index
            });
        }

        // Get table BAR and offset
        let table_offset_bir = pci_config_read_dword(self.bus, self.slot, self.function, (msix_cap + 4) as u16);
        let bir = (table_offset_bir & 0x7) as u8;
        let table_offset = table_offset_bir & !0x7;

        // Get BAR base address
        let bar = self.get_bar(bir)?;
        let table_addr = bar.base_addr + table_offset as u64;

        // Write MSI-X table entry (would need MMIO mapping in real implementation)
        // For now, just enable MSI-X
        let new_ctrl = msg_ctrl | 0x8000; // Enable MSI-X
        pci_config_write_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16, new_ctrl);

        Ok(())
    }

    /// Enable MSI-X
    pub fn enable_msix(&self) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX)
            .ok_or(PciError::MsixNotSupported)?;

        let msg_ctrl = pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        let new_ctrl = msg_ctrl | 0x8000; // Enable MSI-X
        pci_config_write_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16, new_ctrl);

        Ok(())
    }

    /// Disable MSI-X
    pub fn disable_msix(&self) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX)
            .ok_or(PciError::MsixNotSupported)?;

        let msg_ctrl = pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        let new_ctrl = msg_ctrl & !0x8000; // Disable MSI-X
        pci_config_write_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16, new_ctrl);

        Ok(())
    }

    /// Check if device has MSI-X capability
    pub fn has_msix(&self) -> bool {
        self.find_capability(capability::MSIX).is_some()
    }

    /// Check if device has MSI capability
    pub fn has_msi(&self) -> bool {
        self.find_capability(capability::MSI).is_some()
    }

    /// Check for and clear device errors
    pub fn check_and_clear_errors(&self) -> Option<u16> {
        let status = self.read_status();
        let error_bits = status & (
            status::MASTER_DATA_PARITY_ERROR |
            status::SIGNALED_TARGET_ABORT |
            status::RECEIVED_TARGET_ABORT |
            status::RECEIVED_MASTER_ABORT |
            status::SIGNALED_SYSTEM_ERROR |
            status::DETECTED_PARITY_ERROR
        );

        if error_bits != 0 {
            // Clear by writing 1 to error bits
            pci_config_write_word(self.bus, self.slot, self.function, config::STATUS, error_bits);
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            Some(error_bits)
        } else {
            None
        }
    }
}

// ============================================================================
// BAR Types
// ============================================================================

/// BAR type (I/O or Memory)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarType {
    /// I/O space BAR
    Io,
    /// Memory space BAR
    Memory,
}

/// PCI Base Address Register (BAR) information
#[derive(Debug, Clone, Copy)]
pub struct PciBar {
    /// Base address
    pub base_addr: u64,
    /// Size in bytes
    pub size: u64,
    /// BAR type
    pub bar_type: BarType,
    /// Prefetchable (memory BARs only)
    pub prefetchable: bool,
    /// 64-bit BAR
    pub is_64bit: bool,
}

/// PCI capability descriptor
#[derive(Debug, Clone, Copy)]
pub struct PciCapability {
    /// Capability ID
    pub id: u8,
    /// Offset in config space
    pub offset: u8,
    /// Next capability pointer
    pub next: u8,
}

// ============================================================================
// DMA Engine
// ============================================================================

/// DMA transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// CPU writes, device reads
    ToDevice,
    /// Device writes, CPU reads
    FromDevice,
    /// Bidirectional transfer
    Bidirectional,
}

/// DMA buffer descriptor
pub struct DmaBuffer {
    /// Virtual address for CPU access
    pub virt_addr: VirtAddr,
    /// Physical address for device access
    pub phys_addr: PhysAddr,
    /// Buffer size in bytes
    pub size: usize,
    /// Whether buffer is coherent (uncached)
    pub coherent: bool,
}

/// DMA descriptor for scatter-gather operations
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct DmaDescriptor {
    /// Physical address of data
    pub addr: u64,
    /// Length in bytes
    pub length: u32,
    /// Flags
    pub flags: u32,
}

impl DmaDescriptor {
    /// End of chain flag
    pub const FLAG_EOC: u32 = 0x8000_0000;
    /// Interrupt on completion flag
    pub const FLAG_IOC: u32 = 0x4000_0000;

    /// Create a new DMA descriptor
    pub const fn new(addr: u64, length: u32, flags: u32) -> Self {
        Self { addr, length, flags }
    }

    /// Mark as end of chain
    pub fn set_end_of_chain(&mut self) {
        self.flags |= Self::FLAG_EOC;
    }

    /// Mark for interrupt on completion
    pub fn set_interrupt(&mut self) {
        self.flags |= Self::FLAG_IOC;
    }
}

/// DMA engine for PCI devices
pub struct DmaEngine {
    /// Associated PCI device
    device: PciDevice,
    /// Coherent (uncached) DMA buffers
    coherent_buffers: Vec<DmaBuffer>,
    /// Streaming (cached) DMA buffers
    streaming_buffers: Vec<DmaBuffer>,
    /// Total transfers performed
    total_transfers: u64,
    /// Total bytes transferred
    total_bytes: u64,
}

impl DmaEngine {
    /// Create a new DMA engine for a PCI device
    pub fn new(device: PciDevice) -> PciResult<Self> {
        // Enable bus mastering for DMA
        device.enable_bus_mastering()?;
        device.enable_memory_space()?;

        // Update global stats
        {
            let mut stats = PCI_STATS.write();
            stats.dma_engines += 1;
        }

        Ok(DmaEngine {
            device,
            coherent_buffers: Vec::new(),
            streaming_buffers: Vec::new(),
            total_transfers: 0,
            total_bytes: 0,
        })
    }

    /// Allocate coherent DMA buffer (uncached, for descriptor rings)
    pub fn alloc_coherent(&mut self, size: usize) -> PciResult<&DmaBuffer> {
        let phys_addr = crate::memory::nonos_dma::allocate_dma_buffer(size)
            .map_err(|_| PciError::DmaAllocationFailed { size })?;
        let virt_addr = crate::memory::phys_to_virt(phys_addr);

        let buffer = DmaBuffer {
            virt_addr,
            phys_addr,
            size,
            coherent: true,
        };

        self.coherent_buffers.push(buffer);
        Ok(self.coherent_buffers.last().unwrap())
    }

    /// Allocate streaming DMA buffer (for data transfers)
    pub fn alloc_streaming(&mut self, size: usize) -> PciResult<&DmaBuffer> {
        let phys_addr = crate::memory::nonos_dma::allocate_dma_buffer(size)
            .map_err(|_| PciError::DmaAllocationFailed { size })?;
        let virt_addr = crate::memory::phys_to_virt(phys_addr);

        let buffer = DmaBuffer {
            virt_addr,
            phys_addr,
            size,
            coherent: false,
        };

        self.streaming_buffers.push(buffer);
        Ok(self.streaming_buffers.last().unwrap())
    }

    /// Sync buffer for device access (flush CPU cache)
    pub fn sync_for_device(&self, buffer: &DmaBuffer) {
        if buffer.coherent {
            return; // Coherent buffers don't need sync
        }

        let start = buffer.virt_addr.as_u64() as usize;
        let end = start + buffer.size;

        // Flush cache lines
        for addr in (start..end).step_by(64) {
            port_io::clflush(addr);
        }
        port_io::mfence();
    }

    /// Sync buffer for CPU access (invalidate cache)
    pub fn sync_for_cpu(&self, buffer: &DmaBuffer) {
        // On x86, CLFLUSH both flushes and invalidates
        self.sync_for_device(buffer);
    }

    /// Perform a DMA transfer (records statistics)
    pub fn transfer(&mut self, direction: DmaDirection, buffer: &DmaBuffer) -> PciResult<()> {
        // Record statistics
        self.total_transfers += 1;
        self.total_bytes += buffer.size as u64;
        DMA_TRANSFER_COUNTER.fetch_add(1, Ordering::Relaxed);
        DMA_BYTES_COUNTER.fetch_add(buffer.size as u64, Ordering::Relaxed);

        // Sync cache based on direction
        match direction {
            DmaDirection::ToDevice => self.sync_for_device(buffer),
            DmaDirection::FromDevice => self.sync_for_cpu(buffer),
            DmaDirection::Bidirectional => self.sync_for_device(buffer),
        }

        Ok(())
    }

    /// Free all DMA buffers
    pub fn free_all(&mut self) {
        for buffer in self.coherent_buffers.drain(..) {
            let _ = crate::memory::nonos_dma::free_dma_buffer(buffer.phys_addr, buffer.size);
        }
        for buffer in self.streaming_buffers.drain(..) {
            let _ = crate::memory::nonos_dma::free_dma_buffer(buffer.phys_addr, buffer.size);
        }
    }

    /// Get transfer statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.total_transfers, self.total_bytes)
    }

    /// Get associated device
    pub fn device(&self) -> &PciDevice {
        &self.device
    }
}

impl Drop for DmaEngine {
    fn drop(&mut self) {
        self.free_all();

        let mut stats = PCI_STATS.write();
        stats.dma_engines = stats.dma_engines.saturating_sub(1);
    }
}

// ============================================================================
// MSI-X Structures
// ============================================================================

/// MSI-X capability structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    pub cap_id: u8,
    pub next_ptr: u8,
    pub message_control: u16,
    pub table_offset_bir: u32,
    pub pba_offset_bir: u32,
}

/// MSI-X table entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    pub message_addr_low: u32,
    pub message_addr_high: u32,
    pub message_data: u32,
    pub vector_control: u32,
}

impl MsixTableEntry {
    /// Vector is masked
    pub const MASKED: u32 = 1 << 0;

    /// Create new entry
    pub const fn new(addr: u64, data: u32) -> Self {
        Self {
            message_addr_low: addr as u32,
            message_addr_high: (addr >> 32) as u32,
            message_data: data,
            vector_control: 0,
        }
    }

    /// Mask this vector
    pub fn mask(&mut self) {
        self.vector_control |= Self::MASKED;
    }

    /// Unmask this vector
    pub fn unmask(&mut self) {
        self.vector_control &= !Self::MASKED;
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// PCI subsystem statistics
#[derive(Debug, Clone)]
pub struct PciStats {
    /// Total devices discovered
    pub total_devices: usize,
    /// Devices by class code
    pub devices_by_class: BTreeMap<u8, usize>,
    /// MSI-X capable devices
    pub msix_devices: usize,
    /// Active DMA engines
    pub dma_engines: usize,
    /// Configuration reads
    pub config_reads: u64,
    /// Configuration writes
    pub config_writes: u64,
    /// DMA transfers
    pub dma_transfers: u64,
    /// DMA bytes transferred
    pub dma_bytes: u64,
    /// Interrupts handled
    pub interrupts: u64,
    /// MSI/MSI-X interrupts
    pub msi_interrupts: u64,
    /// Errors encountered
    pub errors: u64,
}

impl PciStats {
    const fn new() -> Self {
        Self {
            total_devices: 0,
            devices_by_class: BTreeMap::new(),
            msix_devices: 0,
            dma_engines: 0,
            config_reads: 0,
            config_writes: 0,
            dma_transfers: 0,
            dma_bytes: 0,
            interrupts: 0,
            msi_interrupts: 0,
            errors: 0,
        }
    }
}

impl Default for PciStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Get PCI statistics snapshot
pub fn get_pci_stats() -> PciStats {
    let stats = PCI_STATS.read();
    PciStats {
        total_devices: stats.total_devices,
        devices_by_class: stats.devices_by_class.clone(),
        msix_devices: stats.msix_devices,
        dma_engines: stats.dma_engines,
        config_reads: CONFIG_READ_COUNTER.load(Ordering::Relaxed),
        config_writes: CONFIG_WRITE_COUNTER.load(Ordering::Relaxed),
        dma_transfers: DMA_TRANSFER_COUNTER.load(Ordering::Relaxed),
        dma_bytes: DMA_BYTES_COUNTER.load(Ordering::Relaxed),
        interrupts: INTERRUPT_COUNTER.load(Ordering::Relaxed),
        msi_interrupts: MSI_INTERRUPT_COUNTER.load(Ordering::Relaxed),
        errors: ERROR_COUNTER.load(Ordering::Relaxed),
    }
}

/// Record a PCI interrupt
#[inline]
pub fn record_interrupt() {
    INTERRUPT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

/// Record an MSI/MSI-X interrupt
#[inline]
pub fn record_msi_interrupt() {
    MSI_INTERRUPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    INTERRUPT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

/// Record a DMA transfer
#[inline]
pub fn record_dma_transfer(bytes: u64) {
    DMA_TRANSFER_COUNTER.fetch_add(1, Ordering::Relaxed);
    DMA_BYTES_COUNTER.fetch_add(bytes, Ordering::Relaxed);
}

/// Record a PCI error
#[inline]
pub fn record_pci_error() {
    ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Device Class Codes
// ============================================================================

/// PCI device class codes
pub mod class_codes {
    pub const UNCLASSIFIED: u8 = 0x00;
    pub const STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const COMMUNICATION: u8 = 0x07;
    pub const SYSTEM: u8 = 0x08;
    pub const INPUT: u8 = 0x09;
    pub const DOCKING: u8 = 0x0A;
    pub const PROCESSOR: u8 = 0x0B;
    pub const SERIAL_BUS: u8 = 0x0C;
    pub const WIRELESS: u8 = 0x0D;
    pub const INTELLIGENT_IO: u8 = 0x0E;
    pub const SATELLITE: u8 = 0x0F;
    pub const ENCRYPTION: u8 = 0x10;
    pub const SIGNAL_PROCESSING: u8 = 0x11;
    pub const PROCESSING_ACCELERATOR: u8 = 0x12;
    pub const NON_ESSENTIAL: u8 = 0x13;
    pub const COPROCESSOR: u8 = 0x40;
    pub const UNASSIGNED: u8 = 0xFF;
}

/// Get human-readable class name
pub fn get_class_name(class_code: u8) -> &'static str {
    match class_code {
        class_codes::UNCLASSIFIED => "Unclassified",
        class_codes::STORAGE => "Storage Controller",
        class_codes::NETWORK => "Network Controller",
        class_codes::DISPLAY => "Display Controller",
        class_codes::MULTIMEDIA => "Multimedia Controller",
        class_codes::MEMORY => "Memory Controller",
        class_codes::BRIDGE => "Bridge Device",
        class_codes::COMMUNICATION => "Communication Controller",
        class_codes::SYSTEM => "System Peripheral",
        class_codes::INPUT => "Input Device",
        class_codes::DOCKING => "Docking Station",
        class_codes::PROCESSOR => "Processor",
        class_codes::SERIAL_BUS => "Serial Bus Controller",
        class_codes::WIRELESS => "Wireless Controller",
        class_codes::INTELLIGENT_IO => "Intelligent I/O Controller",
        class_codes::SATELLITE => "Satellite Controller",
        class_codes::ENCRYPTION => "Encryption Controller",
        class_codes::SIGNAL_PROCESSING => "Signal Processing Controller",
        class_codes::PROCESSING_ACCELERATOR => "Processing Accelerator",
        class_codes::NON_ESSENTIAL => "Non-Essential Instrumentation",
        class_codes::COPROCESSOR => "Coprocessor",
        class_codes::UNASSIGNED => "Unassigned",
        _ => "Unknown",
    }
}

// ============================================================================
// Bus Scanning
// ============================================================================

/// Scan PCI bus for all devices
pub fn scan_pci_bus() -> PciResult<Vec<PciDevice>> {
    let mut devices = Vec::with_capacity(256);

    for bus in 0..MAX_PCI_BUSES as u8 {
        for slot in 0..MAX_DEVICES_PER_BUS {
            if let Some(device) = PciDevice::new(bus, slot, 0) {
                devices.push(device);

                // Check for multi-function device
                if device.multifunction {
                    for function in 1..MAX_FUNCTIONS_PER_DEVICE {
                        if let Some(mf_device) = PciDevice::new(bus, slot, function) {
                            devices.push(mf_device);
                        }
                    }
                }
            }
        }
    }

    // Update statistics and cache
    update_device_cache(&devices);

    Ok(devices)
}

/// Update device cache and statistics
fn update_device_cache(devices: &[PciDevice]) {
    let mut stats = PCI_STATS.write();
    stats.total_devices = devices.len();
    stats.devices_by_class.clear();
    stats.msix_devices = 0;

    for device in devices {
        *stats.devices_by_class.entry(device.class_code).or_insert(0) += 1;
        if device.has_msix() {
            stats.msix_devices += 1;
        }
    }

    // Update cache
    let mut cache = DEVICE_CACHE.write();
    cache.clear();
    cache.extend_from_slice(devices);
}

/// Get cached devices (requires prior scan)
pub fn get_cached_devices() -> Vec<PciDevice> {
    DEVICE_CACHE.read().clone()
}

/// Find device by vendor and device ID
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    DEVICE_CACHE.read().iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
        .copied()
}

/// Find devices by class
pub fn find_devices_by_class(class_code: u8) -> Vec<PciDevice> {
    DEVICE_CACHE.read().iter()
        .filter(|d| d.class_code == class_code)
        .copied()
        .collect()
}

/// Find devices by class and subclass
pub fn find_devices_by_class_subclass(class_code: u8, subclass: u8) -> Vec<PciDevice> {
    DEVICE_CACHE.read().iter()
        .filter(|d| d.class_code == class_code && d.subclass == subclass)
        .copied()
        .collect()
}

// ============================================================================
// Initialization
// ============================================================================

/// Check if PCI subsystem is initialized
#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Initialize PCI subsystem
pub fn init() -> PciResult<()> {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        return Err(PciError::AlreadyInitialized);
    }

    // Scan for devices
    let devices = scan_pci_bus()?;

    crate::log::info!("PCI: found {} devices", devices.len());

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_as_str() {
        assert_eq!(PciError::NotInitialized.as_str(), "PCI subsystem not initialized");
        assert_eq!(PciError::DeviceNotFound { bus: 0, slot: 0, function: 0 }.as_str(),
                   "PCI device not found at specified location");
    }

    #[test]
    fn test_make_config_address() {
        let addr = make_config_address(0, 0, 0, 0);
        assert_eq!(addr, 0x8000_0000);

        let addr = make_config_address(1, 2, 3, 0x10);
        assert_eq!(addr, 0x8001_1310);
    }

    #[test]
    fn test_bar_type() {
        assert_eq!(BarType::Io, BarType::Io);
        assert_ne!(BarType::Io, BarType::Memory);
    }

    #[test]
    fn test_dma_descriptor() {
        let mut desc = DmaDescriptor::new(0x1000, 4096, 0);
        assert_eq!(desc.addr, 0x1000);
        assert_eq!(desc.length, 4096);
        assert_eq!(desc.flags, 0);

        desc.set_end_of_chain();
        assert_eq!(desc.flags & DmaDescriptor::FLAG_EOC, DmaDescriptor::FLAG_EOC);

        desc.set_interrupt();
        assert_eq!(desc.flags & DmaDescriptor::FLAG_IOC, DmaDescriptor::FLAG_IOC);
    }

    #[test]
    fn test_pci_stats_default() {
        let stats = PciStats::new();
        assert_eq!(stats.total_devices, 0);
        assert_eq!(stats.dma_engines, 0);
    }
}
