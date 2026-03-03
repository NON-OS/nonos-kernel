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

pub const CAP_CAPLENGTH: usize = 0x00;
pub const CAP_HCSPARAMS1: usize = 0x04;
pub const CAP_HCSPARAMS2: usize = 0x08;
pub const CAP_HCSPARAMS3: usize = 0x0C;
pub const CAP_HCCPARAMS1: usize = 0x10;
pub const CAP_DBOFF: usize = 0x14;
pub const CAP_RTSOFF: usize = 0x18;
pub const CAP_HCCPARAMS2: usize = 0x1C;

pub const HCSPARAMS1_MAXSLOTS_MASK: u32 = 0xFF;
pub const HCSPARAMS1_MAXINTRS_MASK: u32 = 0x7FF << 8;
pub const HCSPARAMS1_MAXINTRS_SHIFT: u32 = 8;
pub const HCSPARAMS1_MAXPORTS_MASK: u32 = 0xFF << 24;
pub const HCSPARAMS1_MAXPORTS_SHIFT: u32 = 24;

pub const HCSPARAMS2_IST_MASK: u32 = 0xF;
pub const HCSPARAMS2_ERST_MAX_MASK: u32 = 0xF << 4;
pub const HCSPARAMS2_ERST_MAX_SHIFT: u32 = 4;
pub const HCSPARAMS2_SPB_HI_MASK: u32 = 0x1F << 21;
pub const HCSPARAMS2_SPB_HI_SHIFT: u32 = 21;
pub const HCSPARAMS2_SPR: u32 = 1 << 26;
pub const HCSPARAMS2_SPB_LO_MASK: u32 = 0x1F << 27;
pub const HCSPARAMS2_SPB_LO_SHIFT: u32 = 27;

pub const HCCPARAMS1_AC64: u32 = 1 << 0;
pub const HCCPARAMS1_BNC: u32 = 1 << 1;
pub const HCCPARAMS1_CSZ: u32 = 1 << 2;
pub const HCCPARAMS1_PPC: u32 = 1 << 3;
pub const HCCPARAMS1_PIND: u32 = 1 << 4;
pub const HCCPARAMS1_LHRC: u32 = 1 << 5;
pub const HCCPARAMS1_LTC: u32 = 1 << 6;
pub const HCCPARAMS1_NSS: u32 = 1 << 7;
pub const HCCPARAMS1_PAE: u32 = 1 << 8;
pub const HCCPARAMS1_SPC: u32 = 1 << 9;
pub const HCCPARAMS1_SEC: u32 = 1 << 10;
pub const HCCPARAMS1_CFC: u32 = 1 << 11;
pub const HCCPARAMS1_MAXPSASIZE_MASK: u32 = 0xF << 12;
pub const HCCPARAMS1_MAXPSASIZE_SHIFT: u32 = 12;
pub const HCCPARAMS1_XECP_MASK: u32 = 0xFFFF << 16;
pub const HCCPARAMS1_XECP_SHIFT: u32 = 16;

pub const OP_USBCMD: usize = 0x00;
pub const OP_USBSTS: usize = 0x04;
pub const OP_PAGESIZE: usize = 0x08;
pub const OP_DNCTRL: usize = 0x14;
pub const OP_CRCR: usize = 0x18;
pub const OP_DCBAAP: usize = 0x30;
pub const OP_CONFIG: usize = 0x38;
pub const OP_PORTSC_BASE: usize = 0x400;
pub const OP_PORT_REG_STRIDE: usize = 0x10;

pub const USBCMD_RS: u32 = 1 << 0;
pub const USBCMD_HCRST: u32 = 1 << 1;
pub const USBCMD_INTE: u32 = 1 << 2;
pub const USBCMD_HSEE: u32 = 1 << 3;
pub const USBCMD_LHCRST: u32 = 1 << 7;
pub const USBCMD_CSS: u32 = 1 << 8;
pub const USBCMD_CRS: u32 = 1 << 9;
pub const USBCMD_EWE: u32 = 1 << 10;
pub const USBCMD_EU3S: u32 = 1 << 11;
pub const USBCMD_CME: u32 = 1 << 13;
pub const USBCMD_ETE: u32 = 1 << 14;
pub const USBCMD_TSC_EN: u32 = 1 << 15;

pub const USBSTS_HCH: u32 = 1 << 0;
pub const USBSTS_HSE: u32 = 1 << 2;
pub const USBSTS_EINT: u32 = 1 << 3;
pub const USBSTS_PCD: u32 = 1 << 4;
pub const USBSTS_SSS: u32 = 1 << 8;
pub const USBSTS_RSS: u32 = 1 << 9;
pub const USBSTS_SRE: u32 = 1 << 10;
pub const USBSTS_CNR: u32 = 1 << 11;
pub const USBSTS_HCE: u32 = 1 << 12;

pub const PORTSC_CCS: u32 = 1 << 0;
pub const PORTSC_PED: u32 = 1 << 1;
pub const PORTSC_OCA: u32 = 1 << 3;
pub const PORTSC_PR: u32 = 1 << 4;
pub const PORTSC_PLS_MASK: u32 = 0xF << 5;
pub const PORTSC_PLS_SHIFT: u32 = 5;
pub const PORTSC_PP: u32 = 1 << 9;
pub const PORTSC_SPEED_MASK: u32 = 0xF << 10;
pub const PORTSC_SPEED_SHIFT: u32 = 10;
pub const PORTSC_PIC_MASK: u32 = 0x3 << 14;
pub const PORTSC_LWS: u32 = 1 << 16;
pub const PORTSC_CSC: u32 = 1 << 17;
pub const PORTSC_PEC: u32 = 1 << 18;
pub const PORTSC_WRC: u32 = 1 << 19;
pub const PORTSC_OCC: u32 = 1 << 20;
pub const PORTSC_PRC: u32 = 1 << 21;
pub const PORTSC_PLC: u32 = 1 << 22;
pub const PORTSC_CEC: u32 = 1 << 23;
pub const PORTSC_CAS: u32 = 1 << 24;
pub const PORTSC_WCE: u32 = 1 << 25;
pub const PORTSC_WDE: u32 = 1 << 26;
pub const PORTSC_WOE: u32 = 1 << 27;
pub const PORTSC_DR: u32 = 1 << 30;
pub const PORTSC_WPR: u32 = 1 << 31;

pub const PORTSC_CHANGE_BITS: u32 =
    PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

pub const PLS_U0: u32 = 0;
pub const PLS_U1: u32 = 1;
pub const PLS_U2: u32 = 2;
pub const PLS_U3: u32 = 3;
pub const PLS_DISABLED: u32 = 4;
pub const PLS_RXDETECT: u32 = 5;
pub const PLS_INACTIVE: u32 = 6;
pub const PLS_POLLING: u32 = 7;
pub const PLS_RECOVERY: u32 = 8;
pub const PLS_HOT_RESET: u32 = 9;
pub const PLS_COMPLIANCE: u32 = 10;
pub const PLS_TEST: u32 = 11;
pub const PLS_RESUME: u32 = 15;

pub const SPEED_FULL: u32 = 1;
pub const SPEED_LOW: u32 = 2;
pub const SPEED_HIGH: u32 = 3;
pub const SPEED_SUPER: u32 = 4;
pub const SPEED_SUPER_PLUS: u32 = 5;

pub const RT_MFINDEX: usize = 0x00;
pub const RT_IR0_IMAN: usize = 0x20;
pub const RT_IR0_IMOD: usize = 0x24;
pub const RT_IR0_ERSTSZ: usize = 0x28;
pub const RT_IR0_ERSTBA: usize = 0x30;
pub const RT_IR0_ERDP: usize = 0x38;
pub const RT_IR_STRIDE: usize = 0x20;

pub const IMAN_IP: u32 = 1 << 0;
pub const IMAN_IE: u32 = 1 << 1;

pub const ERDP_DESI_MASK: u64 = 0x7;
pub const ERDP_EHB: u64 = 1 << 3;

pub const CRCR_RCS: u64 = 1 << 0;
pub const CRCR_CS: u64 = 1 << 1;
pub const CRCR_CA: u64 = 1 << 2;
pub const CRCR_CRR: u64 = 1 << 3;
