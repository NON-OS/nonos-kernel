// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//! NONOS Serial Port Driver
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
