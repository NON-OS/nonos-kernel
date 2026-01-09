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

pub const INTEL_VENDOR_ID: u16 = 0x8086;
pub const E1000_DEVICE_IDS: &[u16] = &[
    0x100E, 0x100F, 0x1015, 0x1016, 0x1017, 0x1019, 0x101D, 0x101E, 0x1026, 0x1027, 0x1028, 0x1076,
    0x1078, 0x1079, 0x107A, 0x107B, 0x10B9, 0x10D3, 0x10F5, 0x1533, 0x153A, 0x153B, 0x15A2, 0x15A3,
    0x15B7, 0x15B8, 0x15D7, 0x15D8, 0x15E3,
];

pub mod reg {
    pub const CTRL: u32 = 0x0000;
    pub const STATUS: u32 = 0x0008;
    pub const EECD: u32 = 0x0010;
    pub const EERD: u32 = 0x0014;
    pub const ICR: u32 = 0x00C0;
    pub const ITR: u32 = 0x00C4;
    pub const ICS: u32 = 0x00C8;
    pub const IMS: u32 = 0x00D0;
    pub const IMC: u32 = 0x00D8;
    pub const RCTL: u32 = 0x0100;
    pub const TCTL: u32 = 0x0400;
    pub const TIPG: u32 = 0x0410;
    pub const RDBAL: u32 = 0x2800;
    pub const RDBAH: u32 = 0x2804;
    pub const RDLEN: u32 = 0x2808;
    pub const RDH: u32 = 0x2810;
    pub const RDT: u32 = 0x2818;
    pub const TDBAL: u32 = 0x3800;
    pub const TDBAH: u32 = 0x3804;
    pub const TDLEN: u32 = 0x3808;
    pub const TDH: u32 = 0x3810;
    pub const TDT: u32 = 0x3818;
    pub const RAL0: u32 = 0x5400;
    pub const RAH0: u32 = 0x5404;
    pub const MTA: u32 = 0x5200;
}

pub mod ctrl {
    pub const FD: u32 = 1 << 0;
    pub const LRST: u32 = 1 << 3;
    pub const ASDE: u32 = 1 << 5;
    pub const SLU: u32 = 1 << 6;
    pub const ILOS: u32 = 1 << 7;
    pub const RST: u32 = 1 << 26;
    pub const VME: u32 = 1 << 30;
    pub const PHY_RST: u32 = 1u32 << 31;
}

pub mod status {
    pub const FD: u32 = 1 << 0;
    pub const LU: u32 = 1 << 1;
    pub const TXOFF: u32 = 1 << 4;
    pub const SPEED_MASK: u32 = 3 << 6;
    pub const SPEED_10: u32 = 0 << 6;
    pub const SPEED_100: u32 = 1 << 6;
    pub const SPEED_1000: u32 = 2 << 6;
}

pub mod rctl {
    pub const EN: u32 = 1 << 1;
    pub const SBP: u32 = 1 << 2;
    pub const UPE: u32 = 1 << 3;
    pub const MPE: u32 = 1 << 4;
    pub const LPE: u32 = 1 << 5;
    pub const LBM_NONE: u32 = 0 << 6;
    pub const RDMTS_HALF: u32 = 0 << 8;
    pub const BAM: u32 = 1 << 15;
    pub const BSIZE_2048: u32 = 0 << 16;
    pub const BSIZE_1024: u32 = 1 << 16;
    pub const BSIZE_512: u32 = 2 << 16;
    pub const BSIZE_256: u32 = 3 << 16;
    pub const SECRC: u32 = 1 << 26;
}

pub mod tctl {
    pub const EN: u32 = 1 << 1;
    pub const PSP: u32 = 1 << 3;
    pub const CT_SHIFT: u32 = 4;
    pub const COLD_SHIFT: u32 = 12;
    pub const SWXOFF: u32 = 1 << 22;
    pub const RTLC: u32 = 1 << 24;
}

pub mod int {
    pub const TXDW: u32 = 1 << 0;
    pub const TXQE: u32 = 1 << 1;
    pub const LSC: u32 = 1 << 2;
    pub const RXSEQ: u32 = 1 << 3;
    pub const RXDMT0: u32 = 1 << 4;
    pub const RXO: u32 = 1 << 6;
    pub const RXT0: u32 = 1 << 7;
}

pub mod tx_cmd {
    pub const EOP: u8 = 1 << 0;
    pub const IFCS: u8 = 1 << 1;
    pub const IC: u8 = 1 << 2;
    pub const RS: u8 = 1 << 3;
    pub const RPS: u8 = 1 << 4;
    pub const DEXT: u8 = 1 << 5;
    pub const VLE: u8 = 1 << 6;
    pub const IDE: u8 = 1 << 7;
}

pub const RX_DESC_COUNT: usize = 32;
pub const TX_DESC_COUNT: usize = 32;
pub const BUFFER_SIZE: usize = 2048;
pub const MIN_FRAME_SIZE: usize = 14;
pub const MAX_MTU: usize = 1500;
pub const DESC_ALIGNMENT: usize = 128;
pub const DEFAULT_TIPG: u32 = 0x0060200A;
pub const DEFAULT_COLLISION_THRESHOLD: u32 = 15;
pub const DEFAULT_COLLISION_DISTANCE: u32 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_ids() {
        assert!(E1000_DEVICE_IDS.contains(&0x100E));
        assert!(E1000_DEVICE_IDS.contains(&0x10D3));
    }

    #[test]
    fn test_register_offsets() {
        assert_eq!(reg::CTRL, 0x0000);
        assert_eq!(reg::STATUS, 0x0008);
        assert_eq!(reg::RDBAL, 0x2800);
        assert_eq!(reg::TDBAL, 0x3800);
    }
}
