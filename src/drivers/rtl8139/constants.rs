// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
pub const RTL8139_DEVICE_IDS: &[u16] = &[
    0x8139,
    0x8138,
];

pub mod reg {
    pub const IDR0: u16 = 0x00;
    pub const IDR4: u16 = 0x04;
    pub const MAR0: u16 = 0x08;
    pub const MAR4: u16 = 0x0C;
    pub const TSD0: u16 = 0x10;
    pub const TSD1: u16 = 0x14;
    pub const TSD2: u16 = 0x18;
    pub const TSD3: u16 = 0x1C;
    pub const TSAD0: u16 = 0x20;
    pub const TSAD1: u16 = 0x24;
    pub const TSAD2: u16 = 0x28;
    pub const TSAD3: u16 = 0x2C;
    pub const RBSTART: u16 = 0x30;
    pub const ERBCR: u16 = 0x34;
    pub const ERSR: u16 = 0x36;
    pub const CR: u16 = 0x37;
    pub const CAPR: u16 = 0x38;
    pub const CBR: u16 = 0x3A;
    pub const IMR: u16 = 0x3C;
    pub const ISR: u16 = 0x3E;
    pub const TCR: u16 = 0x40;
    pub const RCR: u16 = 0x44;
    pub const TCTR: u16 = 0x48;
    pub const MPC: u16 = 0x4C;
    pub const CONFIG0: u16 = 0x51;
    pub const CONFIG1: u16 = 0x52;
    pub const MSR: u16 = 0x58;
    pub const CONFIG3: u16 = 0x59;
    pub const CONFIG4: u16 = 0x5A;
    pub const BMCR: u16 = 0x62;
    pub const BMSR: u16 = 0x64;
}

pub mod cmd {
    pub const BUFE: u8 = 1 << 0;
    pub const TE: u8 = 1 << 2;
    pub const RE: u8 = 1 << 3;
    pub const RST: u8 = 1 << 4;
}

pub mod rcr {
    pub const AAP: u32 = 1 << 0;
    pub const APM: u32 = 1 << 1;
    pub const AM: u32 = 1 << 2;
    pub const AB: u32 = 1 << 3;
    pub const AR: u32 = 1 << 4;
    pub const AER: u32 = 1 << 5;
    pub const WRAP: u32 = 1 << 7;
    pub const RBLEN_8K: u32 = 0 << 11;
    pub const RBLEN_16K: u32 = 1 << 11;
    pub const RBLEN_32K: u32 = 2 << 11;
    pub const RBLEN_64K: u32 = 3 << 11;
}

pub mod tcr {
    pub const CLRABT: u32 = 1 << 0;
    pub const MXDMA_16: u32 = 0 << 8;
    pub const MXDMA_32: u32 = 1 << 8;
    pub const MXDMA_64: u32 = 2 << 8;
    pub const MXDMA_128: u32 = 3 << 8;
    pub const MXDMA_256: u32 = 4 << 8;
    pub const MXDMA_512: u32 = 5 << 8;
    pub const MXDMA_1024: u32 = 6 << 8;
    pub const MXDMA_UNLIM: u32 = 7 << 8;
    pub const IFG_STD: u32 = 3 << 24;
}

pub mod tsd {
    pub const OWN: u32 = 1 << 13;
    pub const TUN: u32 = 1 << 14;
    pub const TOK: u32 = 1 << 15;
}

pub mod int {
    pub const ROK: u16 = 1 << 0;
    pub const RER: u16 = 1 << 1;
    pub const TOK: u16 = 1 << 2;
    pub const TER: u16 = 1 << 3;
    pub const RXOVW: u16 = 1 << 4;
    pub const PUN: u16 = 1 << 5;
    pub const FOVW: u16 = 1 << 6;
    pub const TIMEOUT: u16 = 1 << 14;
    pub const SERR: u16 = 1 << 15;
}

pub mod msr {
    pub const RXPF: u8 = 1 << 0;
    pub const TXPF: u8 = 1 << 1;
    pub const LINKB: u8 = 1 << 2;
    pub const SPEED10: u8 = 1 << 3;
    pub const AUXSTS: u8 = 1 << 4;
    pub const RXFCE: u8 = 1 << 6;
    pub const TXFCE: u8 = 1 << 7;
}

pub const RX_BUFFER_SIZE: usize = 8192 + 16 + 1500;
pub const TX_DESC_COUNT: usize = 4;
pub const TX_BUFFER_SIZE: usize = 1536;
pub const MIN_FRAME_SIZE: usize = 14;
pub const MAX_MTU: usize = 1500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_ids() {
        assert!(RTL8139_DEVICE_IDS.contains(&0x8139));
        assert!(RTL8139_DEVICE_IDS.contains(&0x8138));
    }

    #[test]
    fn test_register_offsets() {
        assert_eq!(reg::CR, 0x37);
        assert_eq!(reg::ISR, 0x3E);
        assert_eq!(reg::RCR, 0x44);
    }
}
