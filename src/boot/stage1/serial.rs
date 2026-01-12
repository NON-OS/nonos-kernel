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

use core::fmt::Write;
use spin::Mutex;
use x86_64::instructions::port::Port;

const COM1: u16 = 0x3F8;
const LSR_TX_EMPTY: u8 = 0x20;
const MAX_TX_WAIT: u32 = 100_000; // Timeout for transmit wait

static SERIAL_LOCK: Mutex<()> = Mutex::new(());
/// # Safety {
/// Must be called exactly once during early boot before any serial output.
/// Writes directly to I/O ports }
pub unsafe fn init_serial() {
    let _lock = SERIAL_LOCK.lock();
    unsafe {
        let mut data = Port::<u8>::new(COM1);
        let mut ier = Port::<u8>::new(COM1 + 1);
        let mut lcr = Port::<u8>::new(COM1 + 3);
        let mut fcr = Port::<u8>::new(COM1 + 2);
        let mut mcr = Port::<u8>::new(COM1 + 4);
      
        ier.write(0x00); // Disable interrupts
        lcr.write(0x80); // Enable DLAB (set baud rate divisor)
      
        // Set divisor to 3 (38400 baud)
        data.write(0x03); // Low byte
        ier.write(0x00);  // High byte
  
        lcr.write(0x03); // 8 bits, no parity, one stop bit
        fcr.write(0xC7); // Enable FIFO, clear TX/RX queues, 14-byte threshold
        mcr.write(0x0B); // Enable DTR, RTS, and OUT2 (required for interrupts)
        ier.write(0x01); // Enable receive interrupts
    }
}

struct SerialWriter;
impl SerialWriter {
    /// # Safety {
    /// Direct port I/O for serial transmission }
    #[inline]
    unsafe fn write_byte(&mut self, byte: u8) {
        let mut port = Port::<u8>::new(COM1);
        let mut lsr = Port::<u8>::new(COM1 + 5);
        let mut wait_count = 0u32;
        while unsafe { lsr.read() } & LSR_TX_EMPTY == 0 {
            wait_count += 1;
            if wait_count >= MAX_TX_WAIT {
                break;
            }
            core::hint::spin_loop();
        }
        // # SAFETY: Port I/O is safe after initialization
        unsafe { port.write(byte) };
    }
}

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            // # SAFETY: Serial port initialized before use
            unsafe { self.write_byte(byte) };
        }
        Ok(())
    }
}

pub fn serial_print(args: core::fmt::Arguments) {
    let _lock = SERIAL_LOCK.lock();
    let _ = SerialWriter.write_fmt(args);
}
