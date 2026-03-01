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

pub const REALTEK_VENDOR_ID: u16 = 0x10EC;

pub const RTL8168_DEVICE_IDS: &[u16] = &[
    0x8168, // RTL8168B/8111B/8111C/8111D/8111E/8111F/8111G/8111H
    0x8161, // RTL8168B (older variant)
    0x8136, // RTL8101E/RTL8102E
    0x8167, // RTL8169SC
    0x8169, // RTL8169 (original)
    0x8162, // RTL8168K
    0x8125, // RTL8125 (2.5GbE)
    0x3000, // RTL8168L
];

pub mod reg {
    pub const MAC0: u16 = 0x00;
    pub const MAC4: u16 = 0x04;
    pub const MAR0: u16 = 0x08;
    pub const MAR4: u16 = 0x0C;
    pub const DTCCR: u16 = 0x10;
    pub const TNPDS_LOW: u16 = 0x20;
    pub const TNPDS_HIGH: u16 = 0x24;
    pub const THPDS_LOW: u16 = 0x28;
    pub const THPDS_HIGH: u16 = 0x2C;
    pub const FLASH: u16 = 0x30;
    pub const ERBCR: u16 = 0x34;
    pub const ERSR: u16 = 0x36;
    pub const CR: u16 = 0x37;
    pub const TPP: u16 = 0x38;
    pub const IMR: u16 = 0x3C;
    pub const ISR: u16 = 0x3E;
    pub const TCR: u16 = 0x40;
    pub const RCR: u16 = 0x44;
    pub const TCTR: u16 = 0x48;
    pub const MPC: u16 = 0x4C;
    pub const EECMD: u16 = 0x50;
    pub const CONFIG0: u16 = 0x51;
    pub const CONFIG1: u16 = 0x52;
    pub const CONFIG2: u16 = 0x53;
    pub const CONFIG3: u16 = 0x54;
    pub const CONFIG4: u16 = 0x55;
    pub const CONFIG5: u16 = 0x56;
    pub const PHY_AR: u16 = 0x60;
    pub const PHY_DR: u16 = 0x64;
    pub const PHY_STATUS: u16 = 0x6C;
    pub const RMS: u16 = 0xDA;
    pub const CPCR: u16 = 0xE0;
    pub const RDSAR_LOW: u16 = 0xE4;
    pub const RDSAR_HIGH: u16 = 0xE8;
    pub const MTPS: u16 = 0xEC;
}

pub mod cmd {
    pub const RST: u8 = 1 << 4;
    pub const RE: u8 = 1 << 3;
    pub const TE: u8 = 1 << 2;
}

pub mod rcr {
    pub const AAP: u32 = 1 << 0;
    pub const APM: u32 = 1 << 1;
    pub const AM: u32 = 1 << 2;
    pub const AB: u32 = 1 << 3;
    pub const AR: u32 = 1 << 4;
    pub const AER: u32 = 1 << 5;
    pub const RXFTH_NONE: u32 = 7 << 13;
    pub const MXDMA_UNLIM: u32 = 7 << 8;
}

pub mod tcr {
    pub const IFG_STD: u32 = 3 << 24;
    pub const MXDMA_UNLIM: u32 = 7 << 8;
}

pub mod int {
    pub const ROK: u16 = 1 << 0;
    pub const RER: u16 = 1 << 1;
    pub const TOK: u16 = 1 << 2;
    pub const TER: u16 = 1 << 3;
    pub const RDU: u16 = 1 << 4;
    pub const LINK_CHG: u16 = 1 << 5;
    pub const FOVW: u16 = 1 << 6;
    pub const TDU: u16 = 1 << 7;
    pub const SW_INT: u16 = 1 << 8;
    pub const TIMEOUT: u16 = 1 << 14;
    pub const SERR: u16 = 1 << 15;
}

pub mod desc_status {
    pub const OWN: u32 = 1 << 31;
    pub const EOR: u32 = 1 << 30;
    pub const FS: u32 = 1 << 29;
    pub const LS: u32 = 1 << 28;
}

pub mod tx_desc {
    pub const OWN: u32 = 1 << 31;
    pub const EOR: u32 = 1 << 30;
    pub const FS: u32 = 1 << 29;
    pub const LS: u32 = 1 << 28;
}

pub const RX_DESC_COUNT: usize = 256;
pub const TX_DESC_COUNT: usize = 256;
pub const RX_BUFFER_SIZE: usize = 2048;
pub const TX_BUFFER_SIZE: usize = 2048;
pub const MAX_MTU: usize = 1500;
