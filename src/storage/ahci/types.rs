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


extern crate alloc;

use alloc::string::String;

#[repr(C)]
pub struct AhciHba {
    pub cap: u32,        // Host Capabilities
    pub ghc: u32,        // Global Host Control
    pub is: u32,         // Interrupt Status
    pub pi: u32,         // Ports Implemented
    pub vs: u32,         // Version
    pub ccc_ctl: u32,    // Command Completion Coalescing Control
    pub ccc_ports: u32,  // Command Completion Coalescing Ports
    pub em_loc: u32,     // Enclosure Management Location
    pub em_ctl: u32,     // Enclosure Management Control
    pub cap2: u32,       // Host Capabilities Extended
    pub bohc: u32,       // BIOS/OS Handoff Control
    pub _reserved: [u8; 0xa0 - 0x2c],
    pub ports: [AhciPortRegs; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AhciPortRegs {
    pub clb: u32,        // Command List Base Address (low)
    pub clbu: u32,       // Command List Base Address (high)
    pub fb: u32,         // FIS Base Address (low)
    pub fbu: u32,        // FIS Base Address (high)
    pub is: u32,         // Interrupt Status
    pub ie: u32,         // Interrupt Enable
    pub cmd: u32,        // Command and Status
    pub _reserved0: u32,
    pub tfd: u32,        // Task File Data
    pub sig: u32,        // Signature
    pub ssts: u32,       // SATA Status (SCR0: SStatus)
    pub sctl: u32,       // SATA Control (SCR2: SControl)
    pub serr: u32,       // SATA Error (SCR1: SError)
    pub sact: u32,       // SATA Active (SCR3: SActive)
    pub ci: u32,         // Command Issue
    pub sntf: u32,       // SATA Notification (SCR4: SNotification)
    pub fbs: u32,        // FIS-based Switching Control
    pub devslp: u32,     // Device Sleep
    pub _reserved1: [u32; 10],
    pub vendor: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AhciCommandHeader {
    pub dw0: u32,        // DW0: Flags + PRD Table Length + ATAPI + etc
    pub prdtl: u32,      // PRD Byte Count (transferred)
    pub ctba: u32,       // Command Table Base Address (low)
    pub ctbau: u32,      // Command Table Base Address (high)
    pub _reserved: [u32; 4],
}

#[repr(C)]
pub struct AhciCommandTable {
    pub cfis: [u8; 64],      // Command FIS
    pub acmd: [u8; 16],      // ATAPI command
    pub _reserved: [u8; 48],
    pub prdt: [AhciPrdtEntry; 8],  // PRD entries (simplified)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AhciPrdtEntry {
    pub dba: u32,        // Data Base Address (low)
    pub dbau: u32,       // Data Base Address (high)
    pub _reserved: u32,
    pub dbc: u32,        // Byte Count + Interrupt on Completion
}

pub const AHCI_SIG_SATA: u32 = 0x00000101;    // SATA drive
pub const AHCI_SIG_SATAPI: u32 = 0xEB140101;  // SATAPI device
pub const AHCI_SIG_SEMB: u32 = 0xC33C0101;    // Enclosure management bridge
pub const AHCI_SIG_PM: u32 = 0x96690101;      // Port multiplier

pub const HBA_CAP_S64A: u32 = 1 << 31;        // 64-bit addressing
pub const HBA_CAP_NCQ: u32 = 1 << 30;         // Native Command Queuing
pub const HBA_CAP_SSS: u32 = 1 << 27;         // Staggered Spin-up
pub const HBA_CAP_SMPS: u32 = 1 << 28;        // Mechanical Presence Switch
pub const HBA_CAP_SALP: u32 = 1 << 26;        // Aggressive Link Power Management

pub const PORT_CMD_ST: u32 = 1 << 0;          // Start
pub const PORT_CMD_FRE: u32 = 1 << 4;         // FIS Receive Enable
pub const PORT_CMD_FR: u32 = 1 << 14;         // FIS Receive Running
pub const PORT_CMD_CR: u32 = 1 << 15;         // Command List Running

pub const GHC_AE: u32 = 1 << 31;              // AHCI Enable
pub const GHC_IE: u32 = 1 << 1;               // Interrupt Enable
pub const GHC_HR: u32 = 1 << 0;               // HBA Reset

pub const AHCI_HBA_PORT_DET_PRESENT: u32 = 0x3;
pub const AHCI_HBA_PORT_IPM_ACTIVE: u32 = 0x1;

pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
pub const ATA_CMD_FLUSH_EXT: u8 = 0xEA;
pub const ATA_CMD_SMART: u8 = 0xB0;

#[derive(Debug, Clone)]
pub struct AhciController {
    pub vendor_id: u16,
    pub device_id: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub bar5_phys: u64,
    pub bar5_virt: u64,
    pub version: u32,
    pub ports_implemented: u32,
    pub max_ports: u8,
    pub command_slots: u8,
    pub supports_64bit: bool,
    pub supports_ncq: bool,
    pub supports_staggered_spinup: bool,
}

#[derive(Debug, Clone)]
pub struct AhciPort {
    pub port_num: u8,
    pub device_type: AhciDeviceType,
    pub signature: u32,
    pub sata_status: u32,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub size_sectors: u64,
    pub sector_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AhciDeviceType {
    None,
    Sata,
    Satapi,
    EnclosureBridge,
    PortMultiplier,
}
