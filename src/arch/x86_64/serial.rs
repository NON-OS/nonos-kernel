//! Advanced Serial Port Driver
//! 
//! High-performance serial communication for debugging and logging

use crate::arch::x86_64::port::{inb, outb};
use core::fmt::{Write, Result};

pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    /// Create new serial port instance
    pub fn new(port: u16) -> Self {
        let mut serial = SerialPort { port };
        serial.init();
        serial
    }
    
    /// Initialize serial port with advanced configuration
    fn init(&mut self) {
        unsafe {
            // Disable interrupts
            outb(self.port + 1, 0x00);
            
            // Enable DLAB (set baud rate divisor)
            outb(self.port + 3, 0x80);
            
            // Set divisor to 3 (38400 baud)
            outb(self.port + 0, 0x03);
            outb(self.port + 1, 0x00);
            
            // 8 bits, no parity, one stop bit
            outb(self.port + 3, 0x03);
            
            // Enable FIFO, clear, with 14-byte threshold
            outb(self.port + 2, 0xC7);
            
            // Enable IRQs, set RTS/DSR
            outb(self.port + 4, 0x0B);
        }
    }
    
    /// Check if transmit buffer is empty
    fn is_transmit_empty(&self) -> bool {
        unsafe { inb(self.port + 5) & 0x20 != 0 }
    }
    
    /// Write a byte to the serial port
    fn write_byte(&self, byte: u8) {
        while !self.is_transmit_empty() {
            unsafe { core::arch::asm!("pause"); }
        }
        unsafe {
            outb(self.port, byte);
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

static mut COM1: Option<SerialPort> = None;

/// Get COM1 serial port
pub unsafe fn get_serial() -> Option<&'static mut SerialPort> {
    if COM1.is_none() {
        COM1 = Some(SerialPort::new(0x3F8));
    }
    COM1.as_mut()
}

/// Write a single byte to the serial port
pub fn write_byte(byte: u8) {
    unsafe {
        if let Some(serial) = get_serial() {
            serial.write_byte(byte);
        }
    }
}

/// Initialize serial subsystem
pub fn init() {
    unsafe {
        let _ = get_serial();
    }
}

/// Handle serial port interrupt
pub fn handle_interrupt() {
    unsafe {
        if let Some(serial) = get_serial() {
            // Read interrupt identification register
            let iir = inb(serial.port + 2);
            
            match iir & 0x0E {
                0x04 => {
                    // Received data available
                    let _data = inb(serial.port);
                    // Process received data (simplified)
                },
                0x02 => {
                    // Transmitter holding register empty
                    // Can send more data if needed
                },
                0x06 => {
                    // Receiver line status
                    let _lsr = inb(serial.port + 5);
                    // Handle line status errors
                },
                0x0C => {
                    // Character timeout
                    // Handle timeout condition
                },
                _ => {
                    // Unknown interrupt
                }
            }
        }
    }
}
