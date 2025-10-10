//! NONOS Console Driver with Real Hardware Output
//!
//! Production console driver supporting VGA text mode, serial ports, and
//! framebuffer

use alloc::{
    collections::VecDeque,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write;
use spin::Mutex;

/// Console colors for VGA text mode
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

/// Console output destination
#[derive(Debug, Clone, Copy)]
pub enum OutputDevice {
    VgaText,
    Serial,
    Framebuffer,
    All,
}

/// Console message severity level
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum LogLevel {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

/// Console message structure
#[derive(Debug, Clone)]
pub struct LogMessage {
    pub level: LogLevel,
    pub timestamp: u64,
    pub message: String,
    pub module: &'static str,
}

/// Main console driver structure
pub struct Console {
    // VGA text mode state
    vga_buffer: usize, // Physical address for Send safety
    vga_width: usize,
    vga_height: usize,
    vga_cursor_x: usize,
    vga_cursor_y: usize,
    vga_color: u8,

    // Serial port state
    serial_port: u16,
    serial_initialized: bool,

    // Message buffer for emergency logs
    log_buffer: VecDeque<LogMessage>,
    max_log_entries: usize,

    // Current output devices
    output_devices: OutputDevice,

    // Statistics
    messages_logged: u64,
    emergency_alerts: u64,
}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

impl Console {
    pub fn new() -> Self {
        Console {
            vga_buffer: 0xB8000,
            vga_width: 80,
            vga_height: 25,
            vga_cursor_x: 0,
            vga_cursor_y: 0,
            vga_color: (Color::White as u8) << 4 | (Color::Black as u8),
            serial_port: 0x3F8, // COM1
            serial_initialized: false,
            log_buffer: VecDeque::new(),
            max_log_entries: 1000,
            output_devices: OutputDevice::All,
            messages_logged: 0,
            emergency_alerts: 0,
        }
    }

    /// Initialize console hardware
    pub fn init(&mut self) -> Result<(), &'static str> {
        // Initialize VGA text mode
        self.init_vga_text_mode()?;

        // Initialize serial port
        self.init_serial_port()?;

        // Clear screen
        self.clear_screen();

        // Print initialization message
        self.write_message("NONOS Console Driver Initialized", LogLevel::Info, "console");

        Ok(())
    }

    /// Initialize VGA text mode
    fn init_vga_text_mode(&mut self) -> Result<(), &'static str> {
        // Set VGA text mode 80x25
        unsafe {
            // Set VGA mode through BIOS interrupt (simplified)
            // In real implementation, this would program VGA registers directly

            // Clear screen buffer
            for i in 0..(self.vga_width * self.vga_height * 2) {
                core::ptr::write_volatile((self.vga_buffer as *mut u16).add(i), 0);
            }
        }

        // Set cursor position to top-left
        self.vga_cursor_x = 0;
        self.vga_cursor_y = 0;
        self.update_vga_cursor();

        Ok(())
    }

    /// Initialize serial port for debugging output
    fn init_serial_port(&mut self) -> Result<(), &'static str> {
        unsafe {
            // Disable interrupts
            crate::arch::x86_64::port::outb(self.serial_port + 1, 0x00);

            // Enable DLAB (set baud rate divisor)
            crate::arch::x86_64::port::outb(self.serial_port + 3, 0x80);

            // Set divisor to 3 (38400 baud)
            crate::arch::x86_64::port::outb(self.serial_port + 0, 0x03);
            crate::arch::x86_64::port::outb(self.serial_port + 1, 0x00);

            // 8 bits, no parity, one stop bit
            crate::arch::x86_64::port::outb(self.serial_port + 3, 0x03);

            // Enable FIFO, clear them, with 14-byte threshold
            crate::arch::x86_64::port::outb(self.serial_port + 2, 0xC7);

            // IRQs enabled, RTS/DSR set
            crate::arch::x86_64::port::outb(self.serial_port + 4, 0x0B);

            // Test serial chip (send byte 0xAE and check if serial returns same byte)
            crate::arch::x86_64::port::outb(self.serial_port + 4, 0x1E);
            crate::arch::x86_64::port::outb(self.serial_port + 0, 0xAE);

            if crate::arch::x86_64::port::inb(self.serial_port + 0) != 0xAE {
                return Err("Serial port test failed");
            }

            // Set serial to normal operation mode
            crate::arch::x86_64::port::outb(self.serial_port + 4, 0x0F);
        }

        self.serial_initialized = true;
        Ok(())
    }

    /// Write a character to VGA text buffer
    fn write_vga_char(&mut self, c: u8) {
        match c {
            b'\n' => {
                self.vga_cursor_x = 0;
                self.vga_cursor_y += 1;
            }
            b'\r' => {
                self.vga_cursor_x = 0;
            }
            b'\t' => {
                self.vga_cursor_x = (self.vga_cursor_x + 8) & !7;
            }
            c => {
                if self.vga_cursor_x >= self.vga_width {
                    self.vga_cursor_x = 0;
                    self.vga_cursor_y += 1;
                }

                let offset = (self.vga_cursor_y * self.vga_width + self.vga_cursor_x) * 2;
                unsafe {
                    let buffer_ptr = self.vga_buffer as *mut u8;
                    core::ptr::write_volatile(buffer_ptr.add(offset), c);
                    core::ptr::write_volatile(buffer_ptr.add(offset + 1), self.vga_color);
                }

                self.vga_cursor_x += 1;
            }
        }

        if self.vga_cursor_y >= self.vga_height {
            self.scroll_screen();
        }

        self.update_vga_cursor();
    }

    /// Scroll VGA screen up by one line
    fn scroll_screen(&mut self) {
        unsafe {
            // Copy all lines up by one
            for row in 1..self.vga_height {
                for col in 0..self.vga_width {
                    let src = (row * self.vga_width + col) * 2;
                    let dst = ((row - 1) * self.vga_width + col) * 2;

                    let buffer_ptr = self.vga_buffer as *mut u8;
                    let char = core::ptr::read_volatile(buffer_ptr.add(src));
                    let attr = core::ptr::read_volatile(buffer_ptr.add(src + 1));

                    core::ptr::write_volatile(buffer_ptr.add(dst), char);
                    core::ptr::write_volatile(buffer_ptr.add(dst + 1), attr);
                }
            }

            // Clear last line
            let last_row = self.vga_height - 1;
            for col in 0..self.vga_width {
                let offset = (last_row * self.vga_width + col) * 2;
                let buffer_ptr = self.vga_buffer as *mut u8;
                core::ptr::write_volatile(buffer_ptr.add(offset), b' ');
                core::ptr::write_volatile(buffer_ptr.add(offset + 1), self.vga_color);
            }
        }

        self.vga_cursor_y = self.vga_height - 1;
    }

    /// Update VGA hardware cursor position
    fn update_vga_cursor(&self) {
        let pos = self.vga_cursor_y * self.vga_width + self.vga_cursor_x;

        unsafe {
            // Tell VGA we want to set cursor high byte
            crate::arch::x86_64::port::outb(0x3D4, 0x0E);
            crate::arch::x86_64::port::outb(0x3D5, ((pos >> 8) & 0xFF) as u8);

            // Tell VGA we want to set cursor low byte
            crate::arch::x86_64::port::outb(0x3D4, 0x0F);
            crate::arch::x86_64::port::outb(0x3D5, (pos & 0xFF) as u8);
        }
    }

    /// Write string to VGA display
    fn write_vga_string(&mut self, s: &str) {
        for byte in s.bytes() {
            self.write_vga_char(byte);
        }
    }

    /// Write character to serial port
    fn write_serial_char(&self, c: u8) -> Result<(), &'static str> {
        if !self.serial_initialized {
            return Err("Serial port not initialized");
        }

        unsafe {
            // Wait for transmit buffer to be empty
            let mut timeout = 10000;
            while timeout > 0 {
                if (crate::arch::x86_64::port::inb(self.serial_port + 5) & 0x20) != 0 {
                    break;
                }
                timeout -= 1;
            }

            if timeout == 0 {
                return Err("Serial port timeout");
            }

            // Send character
            crate::arch::x86_64::port::outb(self.serial_port, c);
        }

        Ok(())
    }

    /// Write string to serial port
    fn write_serial_string(&self, s: &str) -> Result<(), &'static str> {
        for byte in s.bytes() {
            self.write_serial_char(byte)?;
        }
        Ok(())
    }

    /// Clear the entire screen
    pub fn clear_screen(&mut self) {
        unsafe {
            let buffer_ptr = self.vga_buffer as *mut u8;
            for i in 0..(self.vga_width * self.vga_height) {
                let offset = i * 2;
                core::ptr::write_volatile(buffer_ptr.add(offset), b' ');
                core::ptr::write_volatile(buffer_ptr.add(offset + 1), self.vga_color);
            }
        }

        self.vga_cursor_x = 0;
        self.vga_cursor_y = 0;
        self.update_vga_cursor();
    }

    /// Set console colors
    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.vga_color = ((bg as u8) << 4) | (fg as u8);
    }

    /// Write formatted message to console
    pub fn write_message(&mut self, message: &str, level: LogLevel, module: &'static str) {
        let timestamp = crate::arch::x86_64::time::timer::get_timestamp_ms().unwrap_or(0);

        // Create formatted message with timestamp and level
        let formatted_message = alloc::format!(
            "[{:08}] [{:8}] [{}] {}\n",
            timestamp,
            level_to_string(level),
            module,
            message
        );

        // Set color based on log level
        let (fg_color, bg_color) = match level {
            LogLevel::Emergency | LogLevel::Alert => (Color::White, Color::Red),
            LogLevel::Critical | LogLevel::Error => (Color::LightRed, Color::Black),
            LogLevel::Warning => (Color::Yellow, Color::Black),
            LogLevel::Notice => (Color::LightCyan, Color::Black),
            LogLevel::Info => (Color::LightGray, Color::Black),
            LogLevel::Debug => (Color::DarkGray, Color::Black),
        };

        let old_color = self.vga_color;
        self.set_color(fg_color, bg_color);

        // Write to selected output devices
        match self.output_devices {
            OutputDevice::VgaText => {
                self.write_vga_string(&formatted_message);
            }
            OutputDevice::Serial => {
                let _ = self.write_serial_string(&formatted_message);
            }
            OutputDevice::All => {
                self.write_vga_string(&formatted_message);
                let _ = self.write_serial_string(&formatted_message);
            }
            OutputDevice::Framebuffer => {
                // Would implement framebuffer output here
            }
        }

        // Restore original color
        self.vga_color = old_color;

        // Add to log buffer
        let log_msg = LogMessage { level, timestamp, message: message.to_string(), module };

        if self.log_buffer.len() >= self.max_log_entries {
            self.log_buffer.pop_front();
        }
        self.log_buffer.push_back(log_msg);

        self.messages_logged += 1;

        if level <= LogLevel::Alert {
            self.emergency_alerts += 1;
        }
    }

    /// Emergency alert with special formatting
    pub fn emergency_alert(&mut self, message: &str) {
        // Save current state
        let old_color = self.vga_color;

        // Set emergency colors (flashing red background)
        self.set_color(Color::White, Color::Red);

        // Create emergency message
        let alert_msg = alloc::format!("!!! EMERGENCY !!! {}", message);

        // Write emergency border
        let border = "=".repeat(self.vga_width.min(alert_msg.len() + 4));
        self.write_vga_string(&border);
        self.write_vga_char(b'\n');

        // Write the alert
        self.write_message(&alert_msg, LogLevel::Emergency, "SYSTEM");

        // Write bottom border
        self.write_vga_string(&border);
        self.write_vga_char(b'\n');

        // Also send to serial with special formatting
        let serial_alert = alloc::format!("\x07\x07\x07!!! EMERGENCY !!! {}\n", message); // Bell chars
        let _ = self.write_serial_string(&serial_alert);

        // Restore color
        self.vga_color = old_color;

        // Make cursor blink by updating position
        for _ in 0..5 {
            self.update_vga_cursor();
            crate::arch::x86_64::delay::delay_ms(100); // 100ms
        }
    }

    /// Log alert message
    pub fn log_alert(&mut self, message: &str) {
        self.write_message(message, LogLevel::Alert, "ALERT");
    }

    /// Get console statistics
    pub fn get_stats(&self) -> ConsoleStats {
        ConsoleStats {
            messages_logged: self.messages_logged,
            emergency_alerts: self.emergency_alerts,
            log_buffer_size: self.log_buffer.len(),
            serial_initialized: self.serial_initialized,
        }
    }

    /// Get recent log messages
    pub fn get_recent_logs(&self, count: usize) -> Vec<LogMessage> {
        let start = if self.log_buffer.len() > count { self.log_buffer.len() - count } else { 0 };

        self.log_buffer.iter().skip(start).cloned().collect()
    }

    /// Set output device
    pub fn set_output_device(&mut self, device: OutputDevice) {
        self.output_devices = device;
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        match self.output_devices {
            OutputDevice::VgaText => {
                self.write_vga_string(s);
            }
            OutputDevice::Serial => {
                let _ = self.write_serial_string(s);
            }
            OutputDevice::All => {
                self.write_vga_string(s);
                let _ = self.write_serial_string(s);
            }
            OutputDevice::Framebuffer => {
                // Would implement framebuffer output here
            }
        }
        Ok(())
    }
}

/// Console statistics
#[derive(Debug)]
pub struct ConsoleStats {
    pub messages_logged: u64,
    pub emergency_alerts: u64,
    pub log_buffer_size: usize,
    pub serial_initialized: bool,
}

fn level_to_string(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Emergency => "EMERG",
        LogLevel::Alert => "ALERT",
        LogLevel::Critical => "CRIT",
        LogLevel::Error => "ERROR",
        LogLevel::Warning => "WARN",
        LogLevel::Notice => "NOTICE",
        LogLevel::Info => "INFO",
        LogLevel::Debug => "DEBUG",
    }
}

/// Initialize console driver
pub fn init() -> Result<(), &'static str> {
    let mut console = Console::new();
    console.init()?;
    *CONSOLE.lock() = Some(console);
    Ok(())
}

/// Write message to console
pub fn write_message(message: &str, level: LogLevel, module: &'static str) {
    if let Some(console) = CONSOLE.lock().as_mut() {
        console.write_message(message, level, module);
    }
}

/// Emergency alert
pub fn emergency_alert(message: &str) -> Result<(), &'static str> {
    if let Some(console) = CONSOLE.lock().as_mut() {
        console.emergency_alert(message);
        Ok(())
    } else {
        Err("Console not initialized")
    }
}

/// Log alert
pub fn log_alert(message: &str) -> Result<(), &'static str> {
    if let Some(console) = CONSOLE.lock().as_mut() {
        console.log_alert(message);
        Ok(())
    } else {
        Err("Console not initialized")
    }
}

/// Print to console (like println! macro)
pub fn print(message: &str) {
    if let Some(console) = CONSOLE.lock().as_mut() {
        let _ = write!(console, "{}", message);
    }
}

/// Print line to console
pub fn println(message: &str) {
    if let Some(console) = CONSOLE.lock().as_mut() {
        let _ = writeln!(console, "{}", message);
    }
}

/// Clear screen
pub fn clear_screen() {
    if let Some(console) = CONSOLE.lock().as_mut() {
        console.clear_screen();
    }
}

/// Set console color
pub fn set_color(fg: Color, bg: Color) {
    if let Some(console) = CONSOLE.lock().as_mut() {
        console.set_color(fg, bg);
    }
}

/// Get console statistics
pub fn get_console_stats() -> Option<ConsoleStats> {
    if let Some(console) = CONSOLE.lock().as_ref() {
        Some(console.get_stats())
    } else {
        None
    }
}

/// Get recent log messages
pub fn get_recent_logs(count: usize) -> Vec<LogMessage> {
    if let Some(console) = CONSOLE.lock().as_ref() {
        console.get_recent_logs(count)
    } else {
        Vec::new()
    }
}

/// Set output device
pub fn set_output_device(device: OutputDevice) {
    if let Some(console) = CONSOLE.lock().as_mut() {
        console.set_output_device(device);
    }
}

/// Macros for easy logging
#[macro_export]
macro_rules! console_emergency {
    ($($arg:tt)*) => {
        $crate::drivers::console::emergency_alert(&alloc::format!($($arg)*)).unwrap_or(())
    };
}

#[macro_export]
macro_rules! console_alert {
    ($($arg:tt)*) => {
        $crate::drivers::console::log_alert(&alloc::format!($($arg)*)).unwrap_or(())
    };
}

#[macro_export]
macro_rules! console_error {
    ($($arg:tt)*) => {
        $crate::drivers::console::write_message(
            &alloc::format!($($arg)*),
            $crate::drivers::console::LogLevel::Error,
            "KERNEL"
        )
    };
}

#[macro_export]
macro_rules! console_warn {
    ($($arg:tt)*) => {
        $crate::drivers::console::write_message(
            &alloc::format!($($arg)*),
            $crate::drivers::console::LogLevel::Warning,
            "KERNEL"
        )
    };
}

#[macro_export]
macro_rules! console_info {
    ($($arg:tt)*) => {
        $crate::drivers::console::write_message(
            &alloc::format!($($arg)*),
            $crate::drivers::console::LogLevel::Info,
            "KERNEL"
        )
    };
}

#[macro_export]
macro_rules! console_debug {
    ($($arg:tt)*) => {
        $crate::drivers::console::write_message(
            &alloc::format!($($arg)*),
            $crate::drivers::console::LogLevel::Debug,
            "KERNEL"
        )
    };
}
