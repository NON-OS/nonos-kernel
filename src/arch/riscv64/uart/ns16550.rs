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

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

const RBR: u64 = 0;
const THR: u64 = 0;
const IER: u64 = 1;
const FCR: u64 = 2;
const ISR: u64 = 2;
const LCR: u64 = 3;
const MCR: u64 = 4;
const LSR: u64 = 5;
const MSR: u64 = 6;
const SCR: u64 = 7;

const DLL: u64 = 0;
const DLM: u64 = 1;

const LSR_DR: u8 = 1 << 0;
const LSR_OE: u8 = 1 << 1;
const LSR_PE: u8 = 1 << 2;
const LSR_FE: u8 = 1 << 3;
const LSR_BI: u8 = 1 << 4;
const LSR_THRE: u8 = 1 << 5;
const LSR_TEMT: u8 = 1 << 6;

const LCR_DLAB: u8 = 1 << 7;
const LCR_8N1: u8 = 0x03;

const FCR_ENABLE: u8 = 1 << 0;
const FCR_CLEAR_RX: u8 = 1 << 1;
const FCR_CLEAR_TX: u8 = 1 << 2;
const FCR_TRIGGER_14: u8 = 0xC0;

const IER_RDA: u8 = 1 << 0;
const IER_THRE: u8 = 1 << 1;

const MCR_DTR: u8 = 1 << 0;
const MCR_RTS: u8 = 1 << 1;
const MCR_OUT2: u8 = 1 << 3;

static UART_BASE: AtomicU64 = AtomicU64::new(0x1000_0000);

pub struct Ns16550 {
    base: u64,
}

impl Ns16550 {
    pub fn new(base: u64) -> Self {
        Self { base }
    }

    pub fn init(&self, baud: u32, clock: u32) {
        let divisor = clock / (16 * baud);

        self.write_reg(IER, 0);

        self.write_reg(LCR, LCR_DLAB);
        self.write_reg(DLL, (divisor & 0xFF) as u8);
        self.write_reg(DLM, ((divisor >> 8) & 0xFF) as u8);

        self.write_reg(LCR, LCR_8N1);

        self.write_reg(FCR, FCR_ENABLE | FCR_CLEAR_RX | FCR_CLEAR_TX | FCR_TRIGGER_14);

        self.write_reg(MCR, MCR_DTR | MCR_RTS | MCR_OUT2);

        self.write_reg(IER, IER_RDA);
    }

    pub fn putc(&self, c: u8) {
        while self.read_reg(LSR) & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        self.write_reg(THR, c);
    }

    pub fn puts(&self, s: &[u8]) {
        for &c in s {
            if c == b'\n' {
                self.putc(b'\r');
            }
            self.putc(c);
        }
    }

    pub fn getc(&self) -> Option<u8> {
        if self.read_reg(LSR) & LSR_DR != 0 {
            Some(self.read_reg(RBR))
        } else {
            None
        }
    }

    pub fn getc_blocking(&self) -> u8 {
        while self.read_reg(LSR) & LSR_DR == 0 {
            core::hint::spin_loop();
        }
        self.read_reg(RBR)
    }

    pub fn is_rx_ready(&self) -> bool {
        self.read_reg(LSR) & LSR_DR != 0
    }

    pub fn is_tx_ready(&self) -> bool {
        self.read_reg(LSR) & LSR_THRE != 0
    }

    pub fn flush(&self) {
        while self.read_reg(LSR) & LSR_TEMT == 0 {
            core::hint::spin_loop();
        }
    }

    fn read_reg(&self, offset: u64) -> u8 {
        unsafe { read_volatile((self.base + offset) as *const u8) }
    }

    fn write_reg(&self, offset: u64, value: u8) {
        unsafe { write_volatile((self.base + offset) as *mut u8, value) }
    }
}

pub fn init_uart(base: u64) {
    UART_BASE.store(base, Ordering::Release);

    let uart = Ns16550::new(base);
    uart.init(115200, 1_843_200);
}

pub fn putc(c: char) {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Ns16550::new(base);
    uart.putc(c as u8);
}

pub fn puts(s: &[u8]) {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Ns16550::new(base);
    uart.puts(s);
}

pub fn getc() -> Option<u8> {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Ns16550::new(base);
    uart.getc()
}

pub fn handle_uart_interrupt() {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Ns16550::new(base);

    while let Some(c) = uart.getc() {
        crate::drivers::input::handle_char(c);
    }
}
