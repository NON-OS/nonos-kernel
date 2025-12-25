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
//! AHCI data structures per AHCI 1.3.1 specification.

use alloc::string::String;
use core::sync::atomic::AtomicU64;

// ============================================================================
// HBA Memory Structures (AHCI 1.3.1 Spec Section 3)
// ============================================================================

/// AHCI Host Bus Adapter (HBA) register block.
///
/// This structure maps to the HBA memory-mapped registers at the base address
/// specified in PCI BAR5. All fields are little-endian and hardware-mapped.
#[repr(C)]
pub struct AhciHba {
    /// Host Capabilities - indicates features supported by the HBA
    pub cap: u32,
    /// Global Host Control - controls HBA behavior
    pub ghc: u32,
    /// Interrupt Status - indicates pending port interrupts
    pub is: u32,
    /// Ports Implemented - bitmap of implemented ports (0-31)
    pub pi: u32,
    /// AHCI Version - major.minor.subminor version
    pub vs: u32,
    /// Command Completion Coalescing Control
    pub ccc_ctl: u32,
    /// Command Completion Coalescing Ports - bitmap
    pub ccc_pts: u32,
    /// Enclosure Management Location
    pub em_loc: u32,
    /// Enclosure Management Control
    pub em_ctl: u32,
    /// Extended Host Capabilities
    pub cap2: u32,
    /// BIOS/OS Handoff Control and Status
    pub bohc: u32,
}

/// Command Header structure (AHCI 1.3.1 Spec Section 4.2.2).
///
/// Each port has 32 command header entries in the Command List.
/// Each entry describes one command to be executed by the HBA.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommandHeader {
    /// Flags field:
    /// - Bits 4:0: Command FIS Length (CFL) in DWORDs (2-16)
    /// - Bit 5: ATAPI command (A)
    /// - Bit 6: Write direction (W) - 1=H2D, 0=D2H
    /// - Bit 7: Prefetchable (P)
    /// - Bit 8: Reset (R)
    /// - Bit 9: BIST (B)
    /// - Bit 10: Clear Busy upon R_OK (C)
    /// - Bits 15:11: Reserved
    pub flags: u16,
    /// Physical Region Descriptor Table Length (entries)
    pub prdtl: u16,
    /// Physical Region Descriptor Byte Count (updated by HBA)
    pub prdbc: u32,
    /// Command Table Base Address (lower 32 bits, 128-byte aligned)
    pub ctba: u32,
    /// Command Table Base Address (upper 32 bits)
    pub ctbau: u32,
    /// Reserved (must be zero)
    pub reserved: [u32; 4],
}

/// Physical Region Descriptor Table (PRDT) entry (AHCI 1.3.1 Spec Section 4.2.3).
///
/// Each entry describes a memory region for DMA transfer, supporting up to
/// 4MB per entry (22 bits of byte count).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PhysicalRegionDescriptor {
    /// Data Base Address (lower 32 bits, word-aligned)
    pub dba: u32,
    /// Data Base Address (upper 32 bits)
    pub dbau: u32,
    /// Reserved (must be zero)
    pub reserved0: u32,
    /// Data Byte Count:
    /// - Bits 21:0: Byte count minus 1 (max 4MB)
    /// - Bit 31: Interrupt on Completion (IOC)
    pub dbc: u32,
}

/// Command Table structure (AHCI 1.3.1 Spec Section 4.2.3).
///
/// Contains the Command FIS, ATAPI command (if applicable), and PRDT entries.
/// Must be 128-byte aligned per AHCI specification.
#[repr(C, align(128))]
pub struct CommandTable {
    /// Command FIS (Frame Information Structure) - up to 64 bytes
    pub cfis: [u8; 64],
    /// ATAPI Command buffer (for SATAPI devices)
    pub acmd: [u8; 16],
    /// Reserved (must be zero)
    pub reserved: [u8; 48],
    /// Physical Region Descriptor Table (single entry in this implementation)
    pub prdt: [PhysicalRegionDescriptor; 1],
}

// ============================================================================
// Information about a detected AHCI/SATA device.
// ============================================================================
pub struct AhciDevice {
    /// Port number (0-31) where this device is connected
    pub port: u32,
    /// Device type determined from signature
    pub device_type: AhciDeviceType,
    /// Total addressable sectors (LBA count)
    pub sectors: u64,
    /// Sector size in bytes (typically 512 or 4096)
    pub sector_size: u32,
    /// Device model string from IDENTIFY data
    pub model: String,
    /// Device serial number from IDENTIFY data
    pub serial: String,
    /// Device firmware revision from IDENTIFY data
    pub firmware: String,
    /// Native Command Queuing support
    pub supports_ncq: bool,
    /// DATA SET MANAGEMENT (TRIM) support
    pub supports_trim: bool,
    /// Whether encryption is enabled for this device
    pub encrypted: bool,
    /// ATA Security Erase support
    pub supports_security_erase: bool,
    /// SHA-256 checksum of IDENTIFY data for integrity verification
    pub identify_checksum: [u8; 32],
    /// Whether device passed integrity verification
    pub integrity_verified: bool,
    /// Timestamp of last TRIM operation (for rate limiting)
    pub last_trim_timestamp: AtomicU64,
}

/// The device type is determined by reading PORT_SIG after device detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciDeviceType {
    /// SATA hard drive or SSD (signature 0x0000_0101)
    Sata,
    /// SATA ATAPI device like CD/DVD (signature 0xEB14_0101)
    Satapi,
    /// Enclosure Management Bridge (signature 0xC33C_0101)
    Semb,
    /// Port Multiplier (signature 0x9669_0101)
    Pm,
}

impl AhciDeviceType {
    /// Returns the device type name as a string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sata => "SATA",
            Self::Satapi => "SATAPI",
            Self::Semb => "SEMB",
            Self::Pm => "Port Multiplier",
        }
    }

    /// Determines device type from port signature register value.
    pub const fn from_signature(sig: u32) -> Option<Self> {
        match sig {
            0x0000_0101 => Some(Self::Sata),
            0xEB14_0101 => Some(Self::Satapi),
            0xC33C_0101 => Some(Self::Semb),
            0x9669_0101 => Some(Self::Pm),
            _ => None,
        }
    }
}
