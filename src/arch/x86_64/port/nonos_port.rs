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
//! NØNOS x86_64 Port I/O Operations
//! ┌─────────────────────────────────────────────────────────────┐
//! │              x86 I/O PORT ADDRESS SPACE                     │
//! │                 (64KB / 65536 ports)                        │
//! ├───────────────┬─────────────────────────────────────────────┤
//! │ 0x0000-0x001F │ DMA Controller 1 (8237A)                    │
//! │ 0x0020-0x003F │ PIC 1 (8259A Master)                        │
//! │ 0x0040-0x005F │ PIT (8254 Programmable Interval Timer)      │
//! │ 0x0060-0x006F │ PS/2 Keyboard/Mouse Controller (8042)       │
//! │ 0x0070-0x007F │ RTC / CMOS / NMI Control                    │
//! │ 0x0080-0x008F │ DMA Page Registers                          │
//! │ 0x00A0-0x00BF │ PIC 2 (8259A Slave)                         │
//! │ 0x00C0-0x00DF │ DMA Controller 2 (8237A)                    │
//! │ 0x00F0        │ Math Coprocessor Clear Busy                 │
//! │ 0x0170-0x0177 │ Secondary IDE Controller                    │
//! │ 0x01F0-0x01F7 │ Primary IDE Controller                      │
//! │ 0x0278-0x027F │ Parallel Port 2 (LPT2)                      │
//! │ 0x02E8-0x02EF │ Serial Port 4 (COM4)                        │
//! │ 0x02F8-0x02FF │ Serial Port 2 (COM2)                        │
//! │ 0x0370-0x0377 │ Secondary Floppy Controller                 │
//! │ 0x0376        │ Secondary IDE Control                       │
//! │ 0x0378-0x037F │ Parallel Port 1 (LPT1)                      │
//! │ 0x03B0-0x03BF │ VGA Monochrome                              │
//! │ 0x03C0-0x03DF │ VGA Color                                   │
//! │ 0x03E8-0x03EF │ Serial Port 3 (COM3)                        │
//! │ 0x03F0-0x03F7 │ Primary Floppy Controller                   │
//! │ 0x03F6        │ Primary IDE Control                         │
//! │ 0x03F8-0x03FF │ Serial Port 1 (COM1)                        │
//! │ 0x0402        │ QEMU Debug Port                             │
//! │ 0x0CF8-0x0CFF │ PCI Configuration Space                     │
//! │ 0x1000-0xFFFF │ Device-specific / PCI BAR I/O               │
//! └─────────────┴───────────────────────────────────────────────┘
//! # Port I/O Instructions
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Instruction │ Description                │ Size             │
//! ├─────────────┼────────────────────────────┼──────────────────┤
//! │ IN AL, DX   │ Read byte from port        │ 8-bit            │
//! │ IN AX, DX   │ Read word from port        │ 16-bit           │
//! │ IN EAX, DX  │ Read dword from port       │ 32-bit           │
//! │ OUT DX, AL  │ Write byte to port         │ 8-bit            │
//! │ OUT DX, AX  │ Write word to port         │ 16-bit           │
//! │ OUT DX, EAX │ Write dword to port        │ 32-bit           │
//! │ INSB        │ Read byte string from port │ REP prefix       │
//! │ INSW        │ Read word string from port │ REP prefix       │
//! │ INSD        │ Read dword string from port│ REP prefix       │
//! │ OUTSB       │ Write byte string to port  │ REP prefix       │
//! │ OUTSW       │ Write word string to port  │ REP prefix       │
//! │ OUTSD       │ Write dword string to port │ REP prefix       │
//! └─────────────┴────────────────────────────┴──────────────────┘

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;

// ============================================================================
// Well-Known Port Constants
// ============================================================================

/// Well-known x86 I/O ports
pub mod ports {
    // DMA Controller 1
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

    // PIC (Programmable Interrupt Controller)
    pub const PIC1_COMMAND: u16 = 0x20;
    pub const PIC1_DATA: u16 = 0x21;
    pub const PIC2_COMMAND: u16 = 0xA0;
    pub const PIC2_DATA: u16 = 0xA1;

    // PIT (Programmable Interval Timer)
    pub const PIT_CHANNEL0: u16 = 0x40;
    pub const PIT_CHANNEL1: u16 = 0x41;
    pub const PIT_CHANNEL2: u16 = 0x42;
    pub const PIT_COMMAND: u16 = 0x43;

    // PS/2 Controller (8042)
    pub const PS2_DATA: u16 = 0x60;
    pub const PS2_STATUS: u16 = 0x64;
    pub const PS2_COMMAND: u16 = 0x64;

    // RTC / CMOS
    pub const CMOS_ADDRESS: u16 = 0x70;
    pub const CMOS_DATA: u16 = 0x71;
    pub const NMI_STATUS: u16 = 0x61;

    // DMA Page Registers
    pub const DMA_PAGE_CH0: u16 = 0x87;
    pub const DMA_PAGE_CH1: u16 = 0x83;
    pub const DMA_PAGE_CH2: u16 = 0x81;
    pub const DMA_PAGE_CH3: u16 = 0x82;
    pub const DMA_PAGE_CH5: u16 = 0x8B;
    pub const DMA_PAGE_CH6: u16 = 0x89;
    pub const DMA_PAGE_CH7: u16 = 0x8A;

    // DMA Controller 2
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

    // Math Coprocessor
    pub const FPU_CLEAR_BUSY: u16 = 0xF0;
    pub const FPU_RESET: u16 = 0xF1;

    // IDE Controllers
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

    // Parallel Ports
    pub const LPT1_DATA: u16 = 0x378;
    pub const LPT1_STATUS: u16 = 0x379;
    pub const LPT1_CONTROL: u16 = 0x37A;
    pub const LPT2_DATA: u16 = 0x278;
    pub const LPT2_STATUS: u16 = 0x279;
    pub const LPT2_CONTROL: u16 = 0x27A;

    // Serial Ports (UARTs)
    pub const COM1_BASE: u16 = 0x3F8;
    pub const COM2_BASE: u16 = 0x2F8;
    pub const COM3_BASE: u16 = 0x3E8;
    pub const COM4_BASE: u16 = 0x2E8;

    // UART Register Offsets (add to COMx_BASE)
    pub const UART_RBR: u16 = 0; // Receive Buffer Register (read)
    pub const UART_THR: u16 = 0; // Transmit Holding Register (write)
    pub const UART_DLL: u16 = 0; // Divisor Latch Low (DLAB=1)
    pub const UART_IER: u16 = 1; // Interrupt Enable Register
    pub const UART_DLH: u16 = 1; // Divisor Latch High (DLAB=1)
    pub const UART_IIR: u16 = 2; // Interrupt Identification Register (read)
    pub const UART_FCR: u16 = 2; // FIFO Control Register (write)
    pub const UART_LCR: u16 = 3; // Line Control Register
    pub const UART_MCR: u16 = 4; // Modem Control Register
    pub const UART_LSR: u16 = 5; // Line Status Register
    pub const UART_MSR: u16 = 6; // Modem Status Register
    pub const UART_SCR: u16 = 7; // Scratch Register

    // VGA Ports
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

    // Floppy Controller
    pub const FDC1_STATUS_A: u16 = 0x3F0;
    pub const FDC1_STATUS_B: u16 = 0x3F1;
    pub const FDC1_DOR: u16 = 0x3F2; // Digital Output Register
    pub const FDC1_TDR: u16 = 0x3F3; // Tape Drive Register
    pub const FDC1_MSR: u16 = 0x3F4; // Main Status Register
    pub const FDC1_DSR: u16 = 0x3F4; // Data Rate Select Register
    pub const FDC1_FIFO: u16 = 0x3F5;
    pub const FDC1_DIR: u16 = 0x3F7; // Digital Input Register
    pub const FDC1_CCR: u16 = 0x3F7; // Configuration Control Register

    pub const FDC2_STATUS_A: u16 = 0x370;
    pub const FDC2_STATUS_B: u16 = 0x371;
    pub const FDC2_DOR: u16 = 0x372;
    pub const FDC2_TDR: u16 = 0x373;
    pub const FDC2_MSR: u16 = 0x374;
    pub const FDC2_DSR: u16 = 0x374;
    pub const FDC2_FIFO: u16 = 0x375;
    pub const FDC2_DIR: u16 = 0x377;
    pub const FDC2_CCR: u16 = 0x377;

    // QEMU Debug Port
    pub const QEMU_DEBUG: u16 = 0x402;
    pub const BOCHS_DEBUG: u16 = 0xE9;

    // PCI Configuration Space
    pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
    pub const PCI_CONFIG_DATA: u16 = 0xCFC;

    // ACPI Ports (typical, can vary)
    pub const ACPI_PM1A_EVT_BLK: u16 = 0x600;
    pub const ACPI_PM1A_CNT_BLK: u16 = 0x604;
    pub const ACPI_PM_TMR_BLK: u16 = 0x608;
    pub const ACPI_GPE0_BLK: u16 = 0x620;

    // PC Speaker
    pub const PC_SPEAKER: u16 = 0x61;

    /// Get a human-readable name for a port number
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
}

// ============================================================================
// Error Types
// ============================================================================

/// Port I/O errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// Port access denied (I/O permission)
    AccessDenied { port: u16 },
    /// Port is reserved by another subsystem
    PortReserved { port: u16 },
    /// Invalid port range
    InvalidRange { start: u16, end: u16 },
    /// Read timeout
    ReadTimeout { port: u16 },
    /// Write timeout
    WriteTimeout { port: u16 },
    /// Buffer too small for string I/O
    BufferTooSmall { required: usize, provided: usize },
    /// Subsystem not initialized
    NotInitialized,
}

impl PortError {
    /// Get a static string description of the error
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AccessDenied { .. } => "Port access denied",
            Self::PortReserved { .. } => "Port is reserved",
            Self::InvalidRange { .. } => "Invalid port range",
            Self::ReadTimeout { .. } => "Port read timeout",
            Self::WriteTimeout { .. } => "Port write timeout",
            Self::BufferTooSmall { .. } => "Buffer too small for string I/O",
            Self::NotInitialized => "Port subsystem not initialized",
        }
    }
}

impl core::fmt::Display for PortError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AccessDenied { port } => {
                write!(f, "Port access denied: 0x{:04X} ({})", port, ports::port_name(*port))
            }
            Self::PortReserved { port } => {
                write!(f, "Port 0x{:04X} ({}) is reserved", port, ports::port_name(*port))
            }
            Self::InvalidRange { start, end } => {
                write!(f, "Invalid port range: 0x{:04X}-0x{:04X}", start, end)
            }
            Self::ReadTimeout { port } => {
                write!(f, "Port read timeout: 0x{:04X} ({})", port, ports::port_name(*port))
            }
            Self::WriteTimeout { port } => {
                write!(f, "Port write timeout: 0x{:04X} ({})", port, ports::port_name(*port))
            }
            Self::BufferTooSmall { required, provided } => {
                write!(
                    f,
                    "Buffer too small for string I/O: need {} bytes, provided {}",
                    required, provided
                )
            }
            Self::NotInitialized => {
                write!(f, "Port I/O subsystem not initialized")
            }
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Port I/O statistics
pub struct PortStats {
    /// Total bytes read
    pub bytes_read: AtomicU64,
    /// Total bytes written
    pub bytes_written: AtomicU64,
    /// Total read operations
    pub read_ops: AtomicU64,
    /// Total write operations
    pub write_ops: AtomicU64,
    /// String read operations
    pub string_read_ops: AtomicU64,
    /// String write operations
    pub string_write_ops: AtomicU64,
    /// I/O delays performed
    pub io_delays: AtomicU64,
}

impl PortStats {
    const fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            string_read_ops: AtomicU64::new(0),
            string_write_ops: AtomicU64::new(0),
            io_delays: AtomicU64::new(0),
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.bytes_read.store(0, Ordering::SeqCst);
        self.bytes_written.store(0, Ordering::SeqCst);
        self.read_ops.store(0, Ordering::SeqCst);
        self.write_ops.store(0, Ordering::SeqCst);
        self.string_read_ops.store(0, Ordering::SeqCst);
        self.string_write_ops.store(0, Ordering::SeqCst);
        self.io_delays.store(0, Ordering::SeqCst);
    }
}

// ============================================================================
// Port Traits
// ============================================================================

/// Trait for types that can be read from/written to I/O ports
pub trait PortValue: Copy + Default {
    /// Read this value type from a port
    ///
    /// # Safety
    /// Reading from I/O ports can have side effects on hardware.
    unsafe fn read_from_port(port: u16) -> Self;

    /// Write this value type to a port
    ///
    /// # Safety
    /// Writing to I/O ports can have side effects on hardware.
    unsafe fn write_to_port(port: u16, value: Self);

    /// Read multiple values from a port (string I/O)
    ///
    /// # Safety
    /// Reading from I/O ports can have side effects on hardware.
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]);

    /// Write multiple values to a port (string I/O)
    ///
    /// # Safety
    /// Writing to I/O ports can have side effects on hardware.
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]);

    /// Size of this value type in bytes
    fn size() -> usize;
}

impl PortValue for u8 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insb",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsb",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize {
        1
    }
}

impl PortValue for u16 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u16;
        core::arch::asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insw",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsw",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize {
        2
    }
}

impl PortValue for u32 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u32;
        core::arch::asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insd",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsd",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize {
        4
    }
}

// ============================================================================
// Type-Safe Port Wrapper
// ============================================================================

/// A type-safe wrapper around an I/O port.
///
/// This struct provides safe abstractions for reading and writing to I/O ports
/// with a specific value type (u8, u16, or u32).
#[derive(Debug, Clone, Copy)]
pub struct Port<T: PortValue> {
    port: u16,
    _marker: PhantomData<T>,
}

impl<T: PortValue> Port<T> {
    /// Create a new port wrapper.
    ///
    /// # Arguments
    /// * `port` - The I/O port number (0-65535)
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _marker: PhantomData,
        }
    }

    /// Get the port number
    #[inline]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Read a value from the port.
    ///
    /// # Safety
    /// Reading from I/O ports can have side effects on hardware state.
    #[inline]
    pub unsafe fn read(&self) -> T {
        PORT_MANAGER.stats.read_ops.fetch_add(1, Ordering::Relaxed);
        PORT_MANAGER.stats.bytes_read.fetch_add(T::size() as u64, Ordering::Relaxed);
        T::read_from_port(self.port)
    }

    /// Write a value to the port.
    ///
    /// # Safety
    /// Writing to I/O ports can affect hardware state.
    #[inline]
    pub unsafe fn write(&self, value: T) {
        PORT_MANAGER.stats.write_ops.fetch_add(1, Ordering::Relaxed);
        PORT_MANAGER.stats.bytes_written.fetch_add(T::size() as u64, Ordering::Relaxed);
        T::write_to_port(self.port, value);
    }

    /// Read multiple values from the port using string I/O.
    ///
    /// This uses the REP INSB/INSW/INSD instructions for efficient
    /// bulk reads from a port.
    ///
    /// # Safety
    /// Reading from I/O ports can have side effects on hardware state.
    #[inline]
    pub unsafe fn read_string(&self, buffer: &mut [T]) {
        PORT_MANAGER.stats.string_read_ops.fetch_add(1, Ordering::Relaxed);
        PORT_MANAGER.stats.bytes_read.fetch_add((buffer.len() * T::size()) as u64, Ordering::Relaxed);
        T::read_string_from_port(self.port, buffer);
    }

    /// Write multiple values to the port using string I/O.
    ///
    /// This uses the REP OUTSB/OUTSW/OUTSD instructions for efficient
    /// bulk writes to a port.
    ///
    /// # Safety
    /// Writing to I/O ports can affect hardware state.
    #[inline]
    pub unsafe fn write_string(&self, buffer: &[T]) {
        PORT_MANAGER.stats.string_write_ops.fetch_add(1, Ordering::Relaxed);
        PORT_MANAGER.stats.bytes_written.fetch_add((buffer.len() * T::size()) as u64, Ordering::Relaxed);
        T::write_string_to_port(self.port, buffer);
    }
}

/// A read-only I/O port
#[derive(Debug, Clone, Copy)]
pub struct PortReadOnly<T: PortValue> {
    port: Port<T>,
}

impl<T: PortValue> PortReadOnly<T> {
    /// Create a new read-only port wrapper
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self {
            port: Port::new(port),
        }
    }

    /// Get the port number
    #[inline]
    pub const fn port(&self) -> u16 {
        self.port.port()
    }

    /// Read a value from the port
    ///
    /// # Safety
    /// Reading from I/O ports can have side effects on hardware state.
    #[inline]
    pub unsafe fn read(&self) -> T {
        self.port.read()
    }

    /// Read multiple values from the port using string I/O
    ///
    /// # Safety
    /// Reading from I/O ports can have side effects on hardware state.
    #[inline]
    pub unsafe fn read_string(&self, buffer: &mut [T]) {
        self.port.read_string(buffer);
    }
}

/// A write-only I/O port
#[derive(Debug, Clone, Copy)]
pub struct PortWriteOnly<T: PortValue> {
    port: Port<T>,
}

impl<T: PortValue> PortWriteOnly<T> {
    /// Create a new write-only port wrapper
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self {
            port: Port::new(port),
        }
    }

    /// Get the port number
    #[inline]
    pub const fn port(&self) -> u16 {
        self.port.port()
    }

    /// Write a value to the port
    ///
    /// # Safety
    /// Writing to I/O ports can affect hardware state.
    #[inline]
    pub unsafe fn write(&self, value: T) {
        self.port.write(value);
    }

    /// Write multiple values to the port using string I/O
    ///
    /// # Safety
    /// Writing to I/O ports can affect hardware state.
    #[inline]
    pub unsafe fn write_string(&self, buffer: &[T]) {
        self.port.write_string(buffer);
    }
}

// ============================================================================
// Port Range
// ============================================================================

/// Represents a contiguous range of I/O ports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    count: u16,
}

impl PortRange {
    /// Create a new port range
    pub const fn new(start: u16, count: u16) -> Self {
        Self { start, count }
    }

    /// Get the starting port number
    pub const fn start(&self) -> u16 {
        self.start
    }

    /// Get the number of ports in the range
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// Get the ending port number (exclusive)
    pub const fn end(&self) -> u16 {
        self.start.saturating_add(self.count)
    }

    /// Check if a port is within this range
    pub const fn contains(&self, port: u16) -> bool {
        port >= self.start && port < self.end()
    }

    /// Check if two ranges overlap
    pub const fn overlaps(&self, other: &PortRange) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

// ============================================================================
// I/O Delay
// ============================================================================

/// Perform a short I/O delay.
///
/// Some legacy hardware requires a brief delay between I/O operations.
/// This function performs a dummy I/O operation to port 0x80 (POST diagnostic)
/// which provides approximately 1 microsecond delay on most systems.
///
/// # Safety
/// Port 0x80 is the POST code port and writing to it is generally safe,
/// though it may affect system diagnostics displays.
#[inline]
pub unsafe fn io_delay() {
    PORT_MANAGER.stats.io_delays.fetch_add(1, Ordering::Relaxed);
    // Port 0x80 is the POST diagnostic port, commonly used for I/O delays
    core::arch::asm!(
        "out 0x80, al",
        in("al") 0u8,
        options(nomem, nostack, preserves_flags)
    );
}

/// Perform multiple I/O delays
///
/// # Safety
/// See `io_delay`
#[inline]
pub unsafe fn io_delay_n(count: u32) {
    for _ in 0..count {
        io_delay();
    }
}

// ============================================================================
// Raw I/O Functions
// ============================================================================

/// Read a byte from an I/O port.
///
/// # Safety
/// Reading from I/O ports can have side effects on hardware state.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    PORT_MANAGER.stats.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_read.fetch_add(1, Ordering::Relaxed);
    u8::read_from_port(port)
}

/// Read a word from an I/O port.
///
/// # Safety
/// Reading from I/O ports can have side effects on hardware state.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    PORT_MANAGER.stats.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_read.fetch_add(2, Ordering::Relaxed);
    u16::read_from_port(port)
}

/// Read a dword from an I/O port.
///
/// # Safety
/// Reading from I/O ports can have side effects on hardware state.
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    PORT_MANAGER.stats.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_read.fetch_add(4, Ordering::Relaxed);
    u32::read_from_port(port)
}

/// Write a byte to an I/O port.
///
/// # Safety
/// Writing to I/O ports can affect hardware state.
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    PORT_MANAGER.stats.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_written.fetch_add(1, Ordering::Relaxed);
    u8::write_to_port(port, value);
}

/// Write a word to an I/O port.
///
/// # Safety
/// Writing to I/O ports can affect hardware state.
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    PORT_MANAGER.stats.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_written.fetch_add(2, Ordering::Relaxed);
    u16::write_to_port(port, value);
}

/// Write a dword to an I/O port.
///
/// # Safety
/// Writing to I/O ports can affect hardware state.
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    PORT_MANAGER.stats.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_written.fetch_add(4, Ordering::Relaxed);
    u32::write_to_port(port, value);
}

/// Read a byte from an I/O port with delay.
///
/// # Safety
/// Reading from I/O ports can have side effects on hardware state.
#[inline]
pub unsafe fn inb_p(port: u16) -> u8 {
    let value = inb(port);
    io_delay();
    value
}

/// Write a byte to an I/O port with delay.
///
/// # Safety
/// Writing to I/O ports can affect hardware state.
#[inline]
pub unsafe fn outb_p(port: u16, value: u8) {
    outb(port, value);
    io_delay();
}

/// Read multiple bytes from an I/O port.
///
/// # Safety
/// Reading from I/O ports can have side effects on hardware state.
#[inline]
pub unsafe fn insb(port: u16, buffer: &mut [u8]) {
    PORT_MANAGER.stats.string_read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    u8::read_string_from_port(port, buffer);
}

/// Read multiple words from an I/O port.
///
/// # Safety
/// Reading from I/O ports can have side effects on hardware state.
#[inline]
pub unsafe fn insw(port: u16, buffer: &mut [u16]) {
    PORT_MANAGER.stats.string_read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_read.fetch_add((buffer.len() * 2) as u64, Ordering::Relaxed);
    u16::read_string_from_port(port, buffer);
}

/// Read multiple dwords from an I/O port.
///
/// # Safety
/// Reading from I/O ports can have side effects on hardware state.
#[inline]
pub unsafe fn insl(port: u16, buffer: &mut [u32]) {
    PORT_MANAGER.stats.string_read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_read.fetch_add((buffer.len() * 4) as u64, Ordering::Relaxed);
    u32::read_string_from_port(port, buffer);
}

/// Write multiple bytes to an I/O port.
///
/// # Safety
/// Writing to I/O ports can affect hardware state.
#[inline]
pub unsafe fn outsb(port: u16, buffer: &[u8]) {
    PORT_MANAGER.stats.string_write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_written.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    u8::write_string_to_port(port, buffer);
}

/// Write multiple words to an I/O port.
///
/// # Safety
/// Writing to I/O ports can affect hardware state.
#[inline]
pub unsafe fn outsw(port: u16, buffer: &[u16]) {
    PORT_MANAGER.stats.string_write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_written.fetch_add((buffer.len() * 2) as u64, Ordering::Relaxed);
    u16::write_string_to_port(port, buffer);
}

/// Write multiple dwords to an I/O port.
///
/// # Safety
/// Writing to I/O ports can affect hardware state.
#[inline]
pub unsafe fn outsl(port: u16, buffer: &[u32]) {
    PORT_MANAGER.stats.string_write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_MANAGER.stats.bytes_written.fetch_add((buffer.len() * 4) as u64, Ordering::Relaxed);
    u32::write_string_to_port(port, buffer);
}

// ============================================================================
// Global State
// ============================================================================

/// Global port manager instance
pub static PORT_MANAGER: PortManager = PortManager::new();

/// Port I/O manager
pub struct PortManager {
    initialized: AtomicBool,
    stats: PortStats,
    /// Reserved port ranges (to prevent conflicts)
    reserved_ranges: RwLock<[Option<PortRange>; 32]>,
}

impl PortManager {
    /// Create a new port manager
    pub const fn new() -> Self {
        const NONE: Option<PortRange> = None;
        Self {
            initialized: AtomicBool::new(false),
            stats: PortStats::new(),
            reserved_ranges: RwLock::new([NONE; 32]),
        }
    }

    /// Initialize the port manager
    pub fn initialize(&self) -> Result<(), PortError> {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already initialized
        }

        // Reserve standard system ports
        self.reserve_range(PortRange::new(ports::PIC1_COMMAND, 2))?;  // PIC1
        self.reserve_range(PortRange::new(ports::PIC2_COMMAND, 2))?;  // PIC2
        self.reserve_range(PortRange::new(ports::PIT_CHANNEL0, 4))?;  // PIT
        self.reserve_range(PortRange::new(ports::PS2_DATA, 1))?;       // PS/2 data
        self.reserve_range(PortRange::new(ports::PS2_COMMAND, 1))?;    // PS/2 cmd
        self.reserve_range(PortRange::new(ports::CMOS_ADDRESS, 2))?;   // CMOS

        crate::log::info!("Port I/O subsystem initialized");
        Ok(())
    }

    /// Check if the subsystem is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Reserve a range of ports for exclusive use
    pub fn reserve_range(&self, range: PortRange) -> Result<(), PortError> {
        let mut ranges = self.reserved_ranges.write();

        // Check for conflicts
        for existing in ranges.iter().flatten() {
            if existing.overlaps(&range) {
                return Err(PortError::PortReserved { port: range.start });
            }
        }

        // Find empty slot
        for slot in ranges.iter_mut() {
            if slot.is_none() {
                *slot = Some(range);
                return Ok(());
            }
        }

        // No empty slots - shouldn't happen with 32 slots
        Err(PortError::InvalidRange {
            start: range.start,
            end: range.end(),
        })
    }

    /// Release a reserved port range
    pub fn release_range(&self, range: PortRange) {
        let mut ranges = self.reserved_ranges.write();
        for slot in ranges.iter_mut() {
            if let Some(existing) = slot {
                if existing.start == range.start && existing.count == range.count {
                    *slot = None;
                    return;
                }
            }
        }
    }

    /// Check if a port is reserved
    pub fn is_reserved(&self, port: u16) -> bool {
        let ranges = self.reserved_ranges.read();
        for range in ranges.iter().flatten() {
            if range.contains(port) {
                return true;
            }
        }
        false
    }

    /// Get statistics
    pub fn stats(&self) -> &PortStats {
        &self.stats
    }

    /// Get total I/O operations count
    pub fn total_ops(&self) -> u64 {
        self.stats.read_ops.load(Ordering::Relaxed)
            + self.stats.write_ops.load(Ordering::Relaxed)
            + self.stats.string_read_ops.load(Ordering::Relaxed)
            + self.stats.string_write_ops.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Initialize the port I/O subsystem
pub fn init() -> Result<(), PortError> {
    PORT_MANAGER.initialize()
}

/// Get a type-safe port wrapper
pub const fn port<T: PortValue>(port: u16) -> Port<T> {
    Port::new(port)
}

/// Get a read-only port wrapper
pub const fn port_read_only<T: PortValue>(port: u16) -> PortReadOnly<T> {
    PortReadOnly::new(port)
}

/// Get a write-only port wrapper
pub const fn port_write_only<T: PortValue>(port: u16) -> PortWriteOnly<T> {
    PortWriteOnly::new(port)
}

/// Reserve a range of ports
pub fn reserve_range(start: u16, count: u16) -> Result<(), PortError> {
    PORT_MANAGER.reserve_range(PortRange::new(start, count))
}

/// Release a reserved port range
pub fn release_range(start: u16, count: u16) {
    PORT_MANAGER.release_range(PortRange::new(start, count));
}

/// Get I/O statistics
pub fn stats() -> &'static PortStats {
    PORT_MANAGER.stats()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_range() {
        let range = PortRange::new(0x100, 8);
        assert_eq!(range.start(), 0x100);
        assert_eq!(range.count(), 8);
        assert_eq!(range.end(), 0x108);

        assert!(range.contains(0x100));
        assert!(range.contains(0x107));
        assert!(!range.contains(0x108));
        assert!(!range.contains(0x99));
    }

    #[test]
    fn test_port_range_overlap() {
        let range1 = PortRange::new(0x100, 8);
        let range2 = PortRange::new(0x104, 8);
        let range3 = PortRange::new(0x108, 8);
        let range4 = PortRange::new(0x90, 8);

        assert!(range1.overlaps(&range2));
        assert!(!range1.overlaps(&range3));
        assert!(!range1.overlaps(&range4));
    }

    #[test]
    fn test_port_value_sizes() {
        assert_eq!(u8::size(), 1);
        assert_eq!(u16::size(), 2);
        assert_eq!(u32::size(), 4);
    }

    #[test]
    fn test_port_names() {
        assert_eq!(ports::port_name(0x20), "PIC1 Command");
        assert_eq!(ports::port_name(0x21), "PIC1 Data");
        assert_eq!(ports::port_name(0x60), "PS/2 Data");
        assert_eq!(ports::port_name(0x3F8), "COM1");
        assert_eq!(ports::port_name(0xCF8), "PCI Config Address");
        assert_eq!(ports::port_name(0x402), "QEMU Debug");
        assert_eq!(ports::port_name(0x1234), "Unknown");
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            PortError::AccessDenied { port: 0x60 }.as_str(),
            "Port access denied"
        );
        assert_eq!(
            PortError::PortReserved { port: 0x60 }.as_str(),
            "Port is reserved"
        );
        assert_eq!(
            PortError::ReadTimeout { port: 0x60 }.as_str(),
            "Port read timeout"
        );
        assert_eq!(
            PortError::NotInitialized.as_str(),
            "Port subsystem not initialized"
        );
    }

    #[test]
    fn test_port_stats() {
        let stats = PortStats::new();
        assert_eq!(stats.read_ops.load(Ordering::SeqCst), 0);
        assert_eq!(stats.write_ops.load(Ordering::SeqCst), 0);

        stats.read_ops.fetch_add(5, Ordering::SeqCst);
        stats.write_ops.fetch_add(3, Ordering::SeqCst);
        assert_eq!(stats.read_ops.load(Ordering::SeqCst), 5);
        assert_eq!(stats.write_ops.load(Ordering::SeqCst), 3);

        stats.reset();
        assert_eq!(stats.read_ops.load(Ordering::SeqCst), 0);
        assert_eq!(stats.write_ops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_port_creation() {
        let port8: Port<u8> = Port::new(0x3F8);
        let port16: Port<u16> = Port::new(0x1F0);
        let port32: Port<u32> = Port::new(0xCFC);

        assert_eq!(port8.port(), 0x3F8);
        assert_eq!(port16.port(), 0x1F0);
        assert_eq!(port32.port(), 0xCFC);
    }

    #[test]
    fn test_port_readonly_writeonly() {
        let ro: PortReadOnly<u8> = PortReadOnly::new(0x64);
        let wo: PortWriteOnly<u8> = PortWriteOnly::new(0x64);

        assert_eq!(ro.port(), 0x64);
        assert_eq!(wo.port(), 0x64);
    }

    #[test]
    fn test_well_known_ports() {
        // Test some well-known port constants
        assert_eq!(ports::COM1_BASE, 0x3F8);
        assert_eq!(ports::COM2_BASE, 0x2F8);
        assert_eq!(ports::PIC1_COMMAND, 0x20);
        assert_eq!(ports::PIC2_COMMAND, 0xA0);
        assert_eq!(ports::PIT_CHANNEL0, 0x40);
        assert_eq!(ports::PS2_DATA, 0x60);
        assert_eq!(ports::CMOS_ADDRESS, 0x70);
        assert_eq!(ports::IDE1_DATA, 0x1F0);
        assert_eq!(ports::PCI_CONFIG_ADDRESS, 0xCF8);
        assert_eq!(ports::PCI_CONFIG_DATA, 0xCFC);
        assert_eq!(ports::QEMU_DEBUG, 0x402);
    }

    #[test]
    fn test_uart_offsets() {
        // Test UART register offsets
        assert_eq!(ports::COM1_BASE + ports::UART_RBR, 0x3F8);
        assert_eq!(ports::COM1_BASE + ports::UART_THR, 0x3F8);
        assert_eq!(ports::COM1_BASE + ports::UART_IER, 0x3F9);
        assert_eq!(ports::COM1_BASE + ports::UART_LCR, 0x3FB);
        assert_eq!(ports::COM1_BASE + ports::UART_LSR, 0x3FD);
    }

    #[test]
    fn test_error_display() {
        extern crate alloc;
        use alloc::format;

        let err = PortError::AccessDenied { port: 0x60 };
        let msg = format!("{}", err);
        assert!(msg.contains("0x0060"));
        assert!(msg.contains("PS/2 Data"));

        let err = PortError::PortReserved { port: 0x3F8 };
        let msg = format!("{}", err);
        assert!(msg.contains("0x03F8"));
        assert!(msg.contains("COM1"));

        let err = PortError::InvalidRange { start: 0x100, end: 0x110 };
        let msg = format!("{}", err);
        assert!(msg.contains("0x0100"));
        assert!(msg.contains("0x0110"));

        let err = PortError::BufferTooSmall { required: 512, provided: 256 };
        let msg = format!("{}", err);
        assert!(msg.contains("512"));
        assert!(msg.contains("256"));
    }
}
