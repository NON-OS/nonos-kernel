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

pub const IDE1_DATA: u16 = 0x1F0;
pub const IDE1_ERROR: u16 = 0x1F1;
pub const IDE1_FEATURES: u16 = 0x1F1;
pub const IDE1_SECTOR_COUNT: u16 = 0x1F2;
pub const IDE1_LBA_LOW: u16 = 0x1F3;
pub const IDE1_LBA_MID: u16 = 0x1F4;
pub const IDE1_LBA_HIGH: u16 = 0x1F5;
pub const IDE1_DRIVE_HEAD: u16 = 0x1F6;
pub const IDE1_STATUS: u16 = 0x1F7;
pub const IDE1_COMMAND: u16 = 0x1F7;
pub const IDE1_CONTROL: u16 = 0x3F6;
pub const IDE1_ALT_STATUS: u16 = 0x3F6;

pub const IDE2_DATA: u16 = 0x170;
pub const IDE2_ERROR: u16 = 0x171;
pub const IDE2_FEATURES: u16 = 0x171;
pub const IDE2_SECTOR_COUNT: u16 = 0x172;
pub const IDE2_LBA_LOW: u16 = 0x173;
pub const IDE2_LBA_MID: u16 = 0x174;
pub const IDE2_LBA_HIGH: u16 = 0x175;
pub const IDE2_DRIVE_HEAD: u16 = 0x176;
pub const IDE2_STATUS: u16 = 0x177;
pub const IDE2_COMMAND: u16 = 0x177;
pub const IDE2_CONTROL: u16 = 0x376;
pub const IDE2_ALT_STATUS: u16 = 0x376;

pub const LPT1_DATA: u16 = 0x378;
pub const LPT1_STATUS: u16 = 0x379;
pub const LPT1_CONTROL: u16 = 0x37A;
pub const LPT2_DATA: u16 = 0x278;
pub const LPT2_STATUS: u16 = 0x279;
pub const LPT2_CONTROL: u16 = 0x27A;

pub const COM1_BASE: u16 = 0x3F8;
pub const COM2_BASE: u16 = 0x2F8;
pub const COM3_BASE: u16 = 0x3E8;
pub const COM4_BASE: u16 = 0x2E8;

pub const UART_RBR: u16 = 0;
pub const UART_THR: u16 = 0;
pub const UART_DLL: u16 = 0;
pub const UART_IER: u16 = 1;
pub const UART_DLH: u16 = 1;
pub const UART_IIR: u16 = 2;
pub const UART_FCR: u16 = 2;
pub const UART_LCR: u16 = 3;
pub const UART_MCR: u16 = 4;
pub const UART_LSR: u16 = 5;
pub const UART_MSR: u16 = 6;
pub const UART_SCR: u16 = 7;

pub const FDC1_STATUS_A: u16 = 0x3F0;
pub const FDC1_STATUS_B: u16 = 0x3F1;
pub const FDC1_DOR: u16 = 0x3F2;
pub const FDC1_TDR: u16 = 0x3F3;
pub const FDC1_MSR: u16 = 0x3F4;
pub const FDC1_DSR: u16 = 0x3F4;
pub const FDC1_FIFO: u16 = 0x3F5;
pub const FDC1_DIR: u16 = 0x3F7;
pub const FDC1_CCR: u16 = 0x3F7;
