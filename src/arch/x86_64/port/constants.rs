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

pub const DMA1_ADDR_CH0: u16 = 0x00;
pub const DMA1_COUNT_CH0: u16 = 0x01;
pub const DMA1_ADDR_CH1: u16 = 0x02;
pub const DMA1_COUNT_CH1: u16 = 0x03;
pub const DMA1_ADDR_CH2: u16 = 0x04;
pub const DMA1_COUNT_CH2: u16 = 0x05;
pub const DMA1_ADDR_CH3: u16 = 0x06;
pub const DMA1_COUNT_CH3: u16 = 0x07;
pub const DMA1_STATUS_CMD: u16 = 0x08;
pub const DMA1_REQUEST: u16 = 0x09;
pub const DMA1_SINGLE_MASK: u16 = 0x0A;
pub const DMA1_MODE: u16 = 0x0B;
pub const DMA1_CLEAR_FLIP_FLOP: u16 = 0x0C;
pub const DMA1_MASTER_CLEAR: u16 = 0x0D;
pub const DMA1_CLEAR_MASK: u16 = 0x0E;
pub const DMA1_WRITE_MASK: u16 = 0x0F;

pub const PIC1_COMMAND: u16 = 0x20;
pub const PIC1_DATA: u16 = 0x21;
pub const PIC2_COMMAND: u16 = 0xA0;
pub const PIC2_DATA: u16 = 0xA1;

pub const PIT_CHANNEL0: u16 = 0x40;
pub const PIT_CHANNEL1: u16 = 0x41;
pub const PIT_CHANNEL2: u16 = 0x42;
pub const PIT_COMMAND: u16 = 0x43;

pub const PS2_DATA: u16 = 0x60;
pub const PS2_STATUS: u16 = 0x64;
pub const PS2_COMMAND: u16 = 0x64;

pub const CMOS_ADDRESS: u16 = 0x70;
pub const CMOS_DATA: u16 = 0x71;
pub const NMI_STATUS: u16 = 0x61;

pub const DMA_PAGE_CH0: u16 = 0x87;
pub const DMA_PAGE_CH1: u16 = 0x83;
pub const DMA_PAGE_CH2: u16 = 0x81;
pub const DMA_PAGE_CH3: u16 = 0x82;
pub const DMA_PAGE_CH5: u16 = 0x8B;
pub const DMA_PAGE_CH6: u16 = 0x89;
pub const DMA_PAGE_CH7: u16 = 0x8A;

pub const DMA2_ADDR_CH4: u16 = 0xC0;
pub const DMA2_COUNT_CH4: u16 = 0xC2;
pub const DMA2_ADDR_CH5: u16 = 0xC4;
pub const DMA2_COUNT_CH5: u16 = 0xC6;
pub const DMA2_ADDR_CH6: u16 = 0xC8;
pub const DMA2_COUNT_CH6: u16 = 0xCA;
pub const DMA2_ADDR_CH7: u16 = 0xCC;
pub const DMA2_COUNT_CH7: u16 = 0xCE;
pub const DMA2_STATUS_CMD: u16 = 0xD0;
pub const DMA2_REQUEST: u16 = 0xD2;
pub const DMA2_SINGLE_MASK: u16 = 0xD4;
pub const DMA2_MODE: u16 = 0xD6;
pub const DMA2_CLEAR_FLIP_FLOP: u16 = 0xD8;
pub const DMA2_MASTER_CLEAR: u16 = 0xDA;
pub const DMA2_CLEAR_MASK: u16 = 0xDC;
pub const DMA2_WRITE_MASK: u16 = 0xDE;

pub const FPU_CLEAR_BUSY: u16 = 0xF0;
pub const FPU_RESET: u16 = 0xF1;

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

pub const VGA_MISC_WRITE: u16 = 0x3C2;
pub const VGA_MISC_READ: u16 = 0x3CC;
pub const VGA_SEQ_INDEX: u16 = 0x3C4;
pub const VGA_SEQ_DATA: u16 = 0x3C5;
pub const VGA_GC_INDEX: u16 = 0x3CE;
pub const VGA_GC_DATA: u16 = 0x3CF;
pub const VGA_CRTC_INDEX: u16 = 0x3D4;
pub const VGA_CRTC_DATA: u16 = 0x3D5;
pub const VGA_AC_INDEX: u16 = 0x3C0;
pub const VGA_AC_WRITE: u16 = 0x3C0;
pub const VGA_AC_READ: u16 = 0x3C1;
pub const VGA_DAC_READ_INDEX: u16 = 0x3C7;
pub const VGA_DAC_WRITE_INDEX: u16 = 0x3C8;
pub const VGA_DAC_DATA: u16 = 0x3C9;
pub const VGA_INPUT_STATUS_1: u16 = 0x3DA;

pub const FDC1_STATUS_A: u16 = 0x3F0;
pub const FDC1_STATUS_B: u16 = 0x3F1;
pub const FDC1_DOR: u16 = 0x3F2;
pub const FDC1_TDR: u16 = 0x3F3;
pub const FDC1_MSR: u16 = 0x3F4;
pub const FDC1_DSR: u16 = 0x3F4;
pub const FDC1_FIFO: u16 = 0x3F5;
pub const FDC1_DIR: u16 = 0x3F7;
pub const FDC1_CCR: u16 = 0x3F7;

pub const FDC2_STATUS_A: u16 = 0x370;
pub const FDC2_STATUS_B: u16 = 0x371;
pub const FDC2_DOR: u16 = 0x372;
pub const FDC2_TDR: u16 = 0x373;
pub const FDC2_MSR: u16 = 0x374;
pub const FDC2_DSR: u16 = 0x374;
pub const FDC2_FIFO: u16 = 0x375;
pub const FDC2_DIR: u16 = 0x377;
pub const FDC2_CCR: u16 = 0x377;

pub const QEMU_DEBUG: u16 = 0x402;
pub const BOCHS_DEBUG: u16 = 0xE9;

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

pub const ACPI_PM1A_EVT_BLK: u16 = 0x600;
pub const ACPI_PM1A_CNT_BLK: u16 = 0x604;
pub const ACPI_PM_TMR_BLK: u16 = 0x608;
pub const ACPI_GPE0_BLK: u16 = 0x620;

pub const PC_SPEAKER: u16 = 0x61;

pub const fn port_name(port: u16) -> &'static str {
    match port {
        0x20 => "PIC1 Command",
        0x21 => "PIC1 Data",
        0xA0 => "PIC2 Command",
        0xA1 => "PIC2 Data",
        0x40..=0x43 => "PIT Timer",
        0x60 => "PS/2 Data",
        0x64 => "PS/2 Command/Status",
        0x70 => "CMOS Address",
        0x71 => "CMOS Data",
        0x1F0..=0x1F7 => "Primary IDE",
        0x170..=0x177 => "Secondary IDE",
        0x3F8..=0x3FF => "COM1",
        0x2F8..=0x2FF => "COM2",
        0x3E8..=0x3EF => "COM3",
        0x2E8..=0x2EF => "COM4",
        0x378..=0x37F => "LPT1",
        0x278..=0x27F => "LPT2",
        0x3C0..=0x3DF => "VGA",
        0x3F0..=0x3F7 => "Floppy",
        0xCF8 => "PCI Config Address",
        0xCFC..=0xCFF => "PCI Config Data",
        0x402 => "QEMU Debug",
        0xE9 => "Bochs Debug",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_addresses() {
        assert_eq!(COM1_BASE, 0x3F8);
        assert_eq!(COM2_BASE, 0x2F8);
        assert_eq!(PIC1_COMMAND, 0x20);
        assert_eq!(PIC2_COMMAND, 0xA0);
        assert_eq!(PCI_CONFIG_ADDRESS, 0xCF8);
    }

    #[test]
    fn test_port_names() {
        assert_eq!(port_name(0x20), "PIC1 Command");
        assert_eq!(port_name(0x60), "PS/2 Data");
        assert_eq!(port_name(0x3F8), "COM1");
        assert_eq!(port_name(0x1234), "Unknown");
    }
}
