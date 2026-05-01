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

const UARTDR: u64 = 0x000;
const UARTFR: u64 = 0x018;
const UARTIBRD: u64 = 0x024;
const UARTFBRD: u64 = 0x028;
const UARTLCR_H: u64 = 0x02C;
const UARTCR: u64 = 0x030;
const UARTIMSC: u64 = 0x038;
const UARTRIS: u64 = 0x03C;
const UARTMIS: u64 = 0x040;
const UARTICR: u64 = 0x044;

const FR_RXFE: u32 = 1 << 4;
const FR_TXFF: u32 = 1 << 5;
const FR_BUSY: u32 = 1 << 3;

const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

const LCR_WLEN_8: u32 = 0b11 << 5;
const LCR_FEN: u32 = 1 << 4;

const IMSC_RXIM: u32 = 1 << 4;
const IMSC_TXIM: u32 = 1 << 5;

static UART_BASE: AtomicU64 = AtomicU64::new(0x0900_0000);

pub struct Pl011 {
    base: u64,
}

impl Pl011 {
    pub fn new(base: u64) -> Self {
        Self { base }
    }

    pub fn init(&self, baud: u32, clock: u32) {
        self.disable();

        let divisor = clock / (16 * baud);
        let fractional = ((clock % (16 * baud)) * 64 + baud / 2) / baud;

        self.write_reg(UARTIBRD, divisor);
        self.write_reg(UARTFBRD, fractional);

        self.write_reg(UARTLCR_H, LCR_WLEN_8 | LCR_FEN);

        self.enable();
    }

    fn enable(&self) {
        self.write_reg(UARTCR, CR_UARTEN | CR_TXE | CR_RXE);
    }

    fn disable(&self) {
        self.write_reg(UARTCR, 0);
    }

    pub fn putc(&self, c: u8) {
        while self.read_reg(UARTFR) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        self.write_reg(UARTDR, c as u32);
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
        if self.read_reg(UARTFR) & FR_RXFE != 0 {
            None
        } else {
            Some((self.read_reg(UARTDR) & 0xFF) as u8)
        }
    }

    pub fn getc_blocking(&self) -> u8 {
        while self.read_reg(UARTFR) & FR_RXFE != 0 {
            core::hint::spin_loop();
        }
        (self.read_reg(UARTDR) & 0xFF) as u8
    }

    pub fn is_rx_ready(&self) -> bool {
        self.read_reg(UARTFR) & FR_RXFE == 0
    }

    pub fn is_tx_ready(&self) -> bool {
        self.read_reg(UARTFR) & FR_TXFF == 0
    }

    pub fn flush(&self) {
        while self.read_reg(UARTFR) & FR_BUSY != 0 {
            core::hint::spin_loop();
        }
    }

    pub fn enable_rx_interrupt(&self) {
        let imsc = self.read_reg(UARTIMSC);
        self.write_reg(UARTIMSC, imsc | IMSC_RXIM);
    }

    pub fn disable_rx_interrupt(&self) {
        let imsc = self.read_reg(UARTIMSC);
        self.write_reg(UARTIMSC, imsc & !IMSC_RXIM);
    }

    pub fn clear_interrupts(&self) {
        self.write_reg(UARTICR, 0x7FF);
    }

    pub fn pending_interrupts(&self) -> u32 {
        self.read_reg(UARTMIS)
    }

    fn read_reg(&self, offset: u64) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    fn write_reg(&self, offset: u64, value: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }
}

pub fn init_uart(base: u64) {
    UART_BASE.store(base, Ordering::Release);

    let uart = Pl011::new(base);
    uart.init(115200, 24_000_000);
}

pub fn putc(c: char) {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Pl011::new(base);
    uart.putc(c as u8);
}

pub fn puts(s: &[u8]) {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Pl011::new(base);
    uart.puts(s);
}

pub fn getc() -> Option<u8> {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Pl011::new(base);
    uart.getc()
}

pub fn handle_uart_interrupt() {
    let base = UART_BASE.load(Ordering::Acquire);
    let uart = Pl011::new(base);

    while let Some(c) = uart.getc() {
        crate::drivers::input::handle_char(c);
    }

    uart.clear_interrupts();
}
