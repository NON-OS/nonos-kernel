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


use alloc::string::String;
use core::sync::atomic::AtomicU64;

#[repr(C)]
pub struct AhciHba {
    pub cap: u32,
    pub ghc: u32,
    pub is: u32,
    pub pi: u32,
    pub vs: u32,
    pub ccc_ctl: u32,
    pub ccc_pts: u32,
    pub em_loc: u32,
    pub em_ctl: u32,
    pub cap2: u32,
    pub bohc: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommandHeader {
    pub flags: u16,
    pub prdtl: u16,
    pub prdbc: u32,
    pub ctba: u32,
    pub ctbau: u32,
    pub reserved: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PhysicalRegionDescriptor {
    pub dba: u32,
    pub dbau: u32,
    pub reserved0: u32,
    pub dbc: u32,
}

#[repr(C, align(128))]
pub struct CommandTable {
    pub cfis: [u8; 64],
    pub acmd: [u8; 16],
    pub reserved: [u8; 48],
    pub prdt: [PhysicalRegionDescriptor; 1],
}

pub struct AhciDevice {
    pub port: u32,
    pub device_type: AhciDeviceType,
    pub sectors: u64,
    pub sector_size: u32,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub supports_ncq: bool,
    pub supports_trim: bool,
    pub encrypted: bool,
    pub supports_security_erase: bool,
    pub identify_checksum: [u8; 32],
    pub integrity_verified: bool,
    pub last_trim_timestamp: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciDeviceType {
    Sata,
    Satapi,
    Semb,
    Pm,
}

impl AhciDeviceType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sata => "SATA",
            Self::Satapi => "SATAPI",
            Self::Semb => "SEMB",
            Self::Pm => "Port Multiplier",
        }
    }

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
