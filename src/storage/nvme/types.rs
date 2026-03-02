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
pub struct NvmeControllerRegs {
    pub cap: u64,        // Controller Capabilities
    pub vs: u32,         // Version
    pub intms: u32,      // Interrupt Mask Set
    pub intmc: u32,      // Interrupt Mask Clear
    pub cc: u32,         // Controller Configuration
    pub _reserved0: u32,
    pub csts: u32,       // Controller Status
    pub nssr: u32,       // NVM Subsystem Reset
    pub aqa: u32,        // Admin Queue Attributes
    pub asq: u64,        // Admin Submission Queue Base Address
    pub acq: u64,        // Admin Completion Queue Base Address
    pub cmbloc: u32,     // Controller Memory Buffer Location
    pub cmbsz: u32,      // Controller Memory Buffer Size
    pub bpinfo: u32,     // Boot Partition Information
    pub bprsel: u32,     // Boot Partition Read Select
    pub bpmbl: u64,      // Boot Partition Memory Buffer Location
    pub _reserved1: [u8; 0xE00 - 0x50],
    pub sq0tdbl: u32,    // Submission Queue 0 Tail Doorbell
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NvmeSubmissionQueueEntry {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NvmeCompletionQueueEntry {
    pub dw0: u32,        // Command-specific
    pub dw1: u32,        // Reserved
    pub sq_head: u16,    // Submission Queue Head Pointer
    pub sq_id: u16,      // Submission Queue Identifier
    pub command_id: u16, // Command Identifier
    pub status: u16,     // Status Field
}

#[repr(C)]
#[derive(Clone)]
pub struct NvmeIdentifyController {
    pub vid: u16,            // 0: PCI Vendor ID
    pub ssvid: u16,          // 2: PCI Subsystem Vendor ID
    pub sn: [u8; 20],        // 4: Serial Number
    pub mn: [u8; 40],        // 24: Model Number
    pub fr: [u8; 8],         // 64: Firmware Revision
    pub rab: u8,             // 72: Recommended Arbitration Burst
    pub ieee: [u8; 3],       // 73: IEEE OUI Identifier
    pub cmic: u8,            // 76: Controller Multi-Path I/O
    pub mdts: u8,            // 77: Maximum Data Transfer Size
    pub cntlid: u16,         // 78: Controller ID
    pub ver: u32,            // 80: Version
    pub rtd3r: u32,          // 84: RTD3 Resume Latency
    pub rtd3e: u32,          // 88: RTD3 Entry Latency
    pub oaes: u32,           // 92: Optional Async Events Supported
    pub ctratt: u32,         // 96: Controller Attributes
    pub _reserved0: [u8; 12],    // 100-111
    pub fguid: [u8; 16],     // 112: FRU Globally Unique ID
    pub _reserved1: [u8; 128],   // 128-255
    pub oacs: u16,           // 256: Optional Admin Command Support
    pub acl: u8,             // 258: Abort Command Limit
    pub aerl: u8,            // 259: Async Event Request Limit
    pub frmw: u8,            // 260: Firmware Updates
    pub lpa: u8,             // 261: Log Page Attributes
    pub elpe: u8,            // 262: Error Log Page Entries
    pub npss: u8,            // 263: Number of Power States Support
    pub avscc: u8,           // 264: Admin Vendor Specific Command Config
    pub apsta: u8,           // 265: Autonomous Power State Transition Attributes
    pub wctemp: u16,         // 266: Warning Composite Temp Threshold
    pub cctemp: u16,         // 268: Critical Composite Temp Threshold
    pub mtfa: u16,           // 270: Maximum Time for Firmware Activation
    pub hmpre: u32,          // 272: Host Memory Buffer Preferred Size
    pub hmmin: u32,          // 276: Host Memory Buffer Minimum Size
    pub tnvmcap: [u8; 16],   // 280: Total NVM Capacity
    pub unvmcap: [u8; 16],   // 296: Unallocated NVM Capacity
}

#[repr(C)]
#[derive(Clone)]
pub struct NvmeIdentifyNamespace {
    pub nsze: u64,           // 0: Namespace Size (in logical blocks)
    pub ncap: u64,           // 8: Namespace Capacity
    pub nuse: u64,           // 16: Namespace Utilization
    pub nsfeat: u8,          // 24: Namespace Features
    pub nlbaf: u8,           // 25: Number of LBA Formats
    pub flbas: u8,           // 26: Formatted LBA Size
    pub mc: u8,              // 27: Metadata Capabilities
    pub dpc: u8,             // 28: Data Protection Capabilities
    pub dps: u8,             // 29: Data Protection Settings
    pub nmic: u8,            // 30: Namespace Multi-path I/O
    pub rescap: u8,          // 31: Reservation Capabilities
    pub fpi: u8,             // 32: Format Progress Indicator
    pub dlfeat: u8,          // 33: Deallocate Logical Block Features
    pub nawun: u16,          // 34: Namespace Atomic Write Unit Normal
    pub nawupf: u16,         // 36: Namespace Atomic Write Unit Power Fail
    pub nacwu: u16,          // 38: Namespace Atomic Compare & Write Unit
    pub nabsn: u16,          // 40: Namespace Atomic Boundary Size Normal
    pub nabo: u16,           // 42: Namespace Atomic Boundary Offset
    pub nabspf: u16,         // 44: Namespace Atomic Boundary Size Power Fail
    pub noiob: u16,          // 46: Namespace Optimal IO Boundary
    pub nvmcap: [u8; 16],    // 48: NVM Capacity
    pub _reserved0: [u8; 40],    // 64-103
    pub nguid: [u8; 16],     // 104: Namespace GUID
    pub eui64: u64,          // 120: IEEE Extended Unique Identifier
    pub lbaf: [u32; 16],     // 128: LBA Format Support (4 bytes each)
}

#[repr(u8)]
pub enum NvmeAdminOpcode {
    DeleteIoSq = 0x00,
    CreateIoSq = 0x01,
    GetLogPage = 0x02,
    DeleteIoCq = 0x04,
    CreateIoCq = 0x05,
    Identify = 0x06,
    Abort = 0x08,
    SetFeatures = 0x09,
    GetFeatures = 0x0A,
    AsyncEventRequest = 0x0C,
    NamespaceManagement = 0x0D,
    FirmwareCommit = 0x10,
    FirmwareDownload = 0x11,
    FormatNvm = 0x80,
    SecuritySend = 0x81,
    SecurityReceive = 0x82,
    Sanitize = 0x84,
}

#[repr(u8)]
pub enum NvmeIoOpcode {
    Flush = 0x00,
    Write = 0x01,
    Read = 0x02,
    WriteUncorrectable = 0x04,
    Compare = 0x05,
    WriteZeroes = 0x08,
    DatasetManagement = 0x09,
}

pub const CAP_MQES_MASK: u64 = 0xFFFF;           // Maximum Queue Entries Supported
pub const CAP_CQR: u64 = 1 << 16;                // Contiguous Queues Required
pub const CAP_AMS_WRR: u64 = 1 << 17;            // Weighted Round Robin
pub const CAP_AMS_VS: u64 = 1 << 18;             // Vendor Specific
pub const CAP_TO_SHIFT: u64 = 24;                // Timeout (500ms units)
pub const CAP_TO_MASK: u64 = 0xFF << CAP_TO_SHIFT;
pub const CAP_DSTRD_SHIFT: u64 = 32;             // Doorbell Stride
pub const CAP_DSTRD_MASK: u64 = 0xF << CAP_DSTRD_SHIFT;
pub const CAP_NSSRS: u64 = 1 << 36;              // NVM Subsystem Reset Supported
pub const CAP_CSS_NVM: u64 = 1 << 37;            // NVM Command Set
pub const CAP_MPSMIN_SHIFT: u64 = 48;            // Memory Page Size Minimum
pub const CAP_MPSMAX_SHIFT: u64 = 52;            // Memory Page Size Maximum

pub const CC_EN: u32 = 1 << 0;                   // Enable
pub const CC_CSS_NVM: u32 = 0 << 4;              // I/O Command Set NVM
pub const CC_MPS_SHIFT: u32 = 7;                 // Memory Page Size
pub const CC_AMS_RR: u32 = 0 << 11;              // Arbitration: Round Robin
pub const CC_SHN_NONE: u32 = 0 << 14;            // Shutdown Notification: None
pub const CC_SHN_NORMAL: u32 = 1 << 14;          // Shutdown Notification: Normal
pub const CC_SHN_ABRUPT: u32 = 2 << 14;          // Shutdown Notification: Abrupt
pub const CC_IOSQES_SHIFT: u32 = 16;             // I/O Submission Queue Entry Size
pub const CC_IOCQES_SHIFT: u32 = 20;             // I/O Completion Queue Entry Size

pub const CSTS_RDY: u32 = 1 << 0;                // Ready
pub const CSTS_CFS: u32 = 1 << 1;                // Controller Fatal Status
pub const CSTS_SHST_MASK: u32 = 3 << 2;          // Shutdown Status
pub const CSTS_NSSRO: u32 = 1 << 4;              // NVM Subsystem Reset Occurred
pub const CSTS_PP: u32 = 1 << 5;                 // Processing Paused

#[derive(Debug, Clone)]
pub struct NvmeController {
    pub vendor_id: u16,
    pub device_id: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub bar0_phys: u64,
    pub bar0_virt: u64,
    pub version: u32,
    pub serial_number: String,
    pub model_number: String,
    pub firmware_rev: String,
    pub max_transfer_size: u32,
    pub num_namespaces: u32,
    pub max_queue_entries: u16,
    pub doorbell_stride: u8,
    pub controller_id: u16,
    pub total_capacity: u128,
}

#[derive(Debug, Clone)]
pub struct NvmeNamespace {
    pub nsid: u32,
    pub size_blocks: u64,
    pub block_size: u32,
    pub capacity_bytes: u64,
    pub formatted_lba_size: u8,
    pub namespace_features: u8,
}
