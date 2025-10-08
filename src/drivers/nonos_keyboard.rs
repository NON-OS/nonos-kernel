//! PS/2 Keyboard Driver
//!
//! Real keyboard driver with scancode processing and input buffering

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::cell::UnsafeCell;
use spin::Mutex;
use x86_64::instructions::port::{Port, PortReadOnly, PortWriteOnly};

/// Keyboard controller I/O ports
const KEYBOARD_DATA_PORT: u16 = 0x60;
const KEYBOARD_STATUS_PORT: u16 = 0x64;
const KEYBOARD_COMMAND_PORT: u16 = 0x64;

/// Keyboard status register bits
const STATUS_OUTPUT_BUFFER_FULL: u8 = 0x01;
const STATUS_INPUT_BUFFER_FULL: u8 = 0x02;
const STATUS_SYSTEM_FLAG: u8 = 0x04;
const STATUS_COMMAND_DATA: u8 = 0x08;
const STATUS_KEYBOARD_LOCK: u8 = 0x10;
const STATUS_AUXILIARY_BUFFER_FULL: u8 = 0x20;
const STATUS_TIMEOUT_ERROR: u8 = 0x40;
const STATUS_PARITY_ERROR: u8 = 0x80;

/// Keyboard commands
const CMD_SET_LEDS: u8 = 0xED;
const CMD_ECHO: u8 = 0xEE;
const CMD_GET_SET_SCANCODE: u8 = 0xF0;
const CMD_IDENTIFY: u8 = 0xF2;
const CMD_SET_REPEAT_RATE: u8 = 0xF3;
const CMD_ENABLE_SCANNING: u8 = 0xF4;
const CMD_DISABLE_SCANNING: u8 = 0xF5;
const CMD_SET_DEFAULTS: u8 = 0xF6;
const CMD_RESEND: u8 = 0xFE;
const CMD_RESET: u8 = 0xFF;

/// Controller commands
const CTRL_CMD_READ_CONFIG: u8 = 0x20;
const CTRL_CMD_WRITE_CONFIG: u8 = 0x60;
const CTRL_CMD_DISABLE_SECOND_PORT: u8 = 0xA7;
const CTRL_CMD_ENABLE_SECOND_PORT: u8 = 0xA8;
const CTRL_CMD_TEST_SECOND_PORT: u8 = 0xA9;
const CTRL_CMD_CONTROLLER_TEST: u8 = 0xAA;
const CTRL_CMD_TEST_FIRST_PORT: u8 = 0xAB;
const CTRL_CMD_DISABLE_FIRST_PORT: u8 = 0xAD;
const CTRL_CMD_ENABLE_FIRST_PORT: u8 = 0xAE;

/// Keyboard responses
const RESP_ACK: u8 = 0xFA;
const RESP_RESEND: u8 = 0xFE;
const RESP_TEST_FAILED: u8 = 0xFC;
const RESP_TEST_PASSED: u8 = 0x55;

/// Key modifiers
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyModifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl Default for KeyModifiers {
    fn default() -> Self {
        KeyModifiers {
            shift: false,
            ctrl: false,
            alt: false,
            caps_lock: false,
            num_lock: false,
            scroll_lock: false,
        }
    }
}

/// Key event
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyEvent {
    pub scancode: u8,
    pub ascii: Option<char>,
    pub modifiers: KeyModifiers,
    pub pressed: bool,
}

/// Keyboard state
struct KeyboardState {
    modifiers: KeyModifiers,
    input_buffer: VecDeque<KeyEvent>,
    led_state: u8,
}

/// PS/2 Keyboard driver
pub struct PS2Keyboard {
    data_port: UnsafeCell<Port<u8>>,
    status_port: UnsafeCell<PortReadOnly<u8>>,
    command_port: UnsafeCell<PortWriteOnly<u8>>,
    state: Mutex<KeyboardState>,
    initialized: AtomicBool,
    
    // Statistics
    keys_pressed: AtomicU64,
    invalid_scancodes: AtomicU64,
}

impl PS2Keyboard {
    /// Create new PS/2 keyboard driver
    pub fn new() -> Self {
        PS2Keyboard {
            data_port: UnsafeCell::new(Port::new(KEYBOARD_DATA_PORT)),
            status_port: UnsafeCell::new(PortReadOnly::new(KEYBOARD_STATUS_PORT)),
            command_port: UnsafeCell::new(PortWriteOnly::new(KEYBOARD_COMMAND_PORT)),
            state: Mutex::new(KeyboardState {
                modifiers: KeyModifiers::default(),
                input_buffer: VecDeque::with_capacity(256),
                led_state: 0,
            }),
            initialized: AtomicBool::new(false),
            keys_pressed: AtomicU64::new(0),
            invalid_scancodes: AtomicU64::new(0),
        }
    }
    
    /// Initialize keyboard controller and device
    pub fn initialize(&self) -> Result<(), &'static str> {
        // Disable devices during setup
        self.send_controller_command(CTRL_CMD_DISABLE_FIRST_PORT)?;
        self.send_controller_command(CTRL_CMD_DISABLE_SECOND_PORT)?;
        
        // Flush output buffer
        while self.is_output_buffer_full() {
            unsafe { (*self.data_port.get()).read(); }
        }
        
        // Test controller
        self.send_controller_command(CTRL_CMD_CONTROLLER_TEST)?;
        let response = self.wait_for_data(1000)?;
        if response != RESP_TEST_PASSED {
            return Err("Controller self-test failed");
        }
        
        // Read configuration
        self.send_controller_command(CTRL_CMD_READ_CONFIG)?;
        let mut config = self.wait_for_data(1000)?;
        
        // Enable interrupts and scanning
        config |= 0x01; // Enable first port interrupt
        config &= !0x10; // Enable first port clock
        config &= !0x20; // Enable first port translation
        
        // Write configuration back
        self.send_controller_command(CTRL_CMD_WRITE_CONFIG)?;
        self.send_controller_data(config)?;
        
        // Test first port
        self.send_controller_command(CTRL_CMD_TEST_FIRST_PORT)?;
        let test_result = self.wait_for_data(1000)?;
        if test_result != 0x00 {
            return Err("First port test failed");
        }
        
        // Enable first port
        self.send_controller_command(CTRL_CMD_ENABLE_FIRST_PORT)?;
        
        // Reset keyboard
        self.send_keyboard_command(CMD_RESET)?;
        let reset_response = self.wait_for_data(5000)?; // Reset takes longer
        if reset_response != RESP_ACK {
            return Err("Keyboard reset failed");
        }
        
        // Wait for self-test result
        let self_test = self.wait_for_data(5000)?;
        if self_test != RESP_TEST_PASSED {
            return Err("Keyboard self-test failed");
        }
        
        // Set scan code set 2 (default)
        self.send_keyboard_command(CMD_GET_SET_SCANCODE)?;
        if self.wait_for_data(1000)? != RESP_ACK {
            return Err("Failed to set scancode set");
        }
        self.send_keyboard_data(2)?;
        if self.wait_for_data(1000)? != RESP_ACK {
            return Err("Failed to set scancode set");
        }
        
        // Enable scanning
        self.send_keyboard_command(CMD_ENABLE_SCANNING)?;
        if self.wait_for_data(1000)? != RESP_ACK {
            return Err("Failed to enable scanning");
        }
        
        // Initialize LED state
        self.update_leds()?;
        
        self.initialized.store(true, Ordering::Relaxed);
        Ok(())
    }
    
    /// Handle keyboard interrupt (called from interrupt handler)
    pub fn handle_interrupt(&self) {
        if !self.initialized.load(Ordering::Relaxed) {
            return;
        }
        
        if !self.is_output_buffer_full() {
            return;
        }
        
        let scancode = unsafe { (*self.data_port.get()).read() };
        self.process_scancode(scancode);
    }
    
    /// Process incoming scancode
    fn process_scancode(&self, scancode: u8) {
        let mut state = self.state.lock();
        
        // Handle extended scancodes (0xE0 prefix)
        if scancode == 0xE0 {
            // Extended scancode follows - would need state machine
            return;
        }
        
        // Determine if key was pressed or released
        let pressed = (scancode & 0x80) == 0;
        let key_code = scancode & 0x7F;
        
        // Update modifier states
        match key_code {
            0x2A | 0x36 => state.modifiers.shift = pressed,      // Left/Right Shift
            0x1D => state.modifiers.ctrl = pressed,              // Ctrl
            0x38 => state.modifiers.alt = pressed,               // Alt
            0x3A => {                                           // Caps Lock
                if pressed {
                    state.modifiers.caps_lock = !state.modifiers.caps_lock;
                    let _ = self.update_leds_from_state(&state.modifiers);
                }
            },
            0x45 => {                                           // Num Lock
                if pressed {
                    state.modifiers.num_lock = !state.modifiers.num_lock;
                    let _ = self.update_leds_from_state(&state.modifiers);
                }
            },
            0x46 => {                                           // Scroll Lock
                if pressed {
                    state.modifiers.scroll_lock = !state.modifiers.scroll_lock;
                    let _ = self.update_leds_from_state(&state.modifiers);
                }
            },
            _ => {}
        }
        
        if pressed {
            self.keys_pressed.fetch_add(1, Ordering::Relaxed);
        }
        
        // Convert scancode to ASCII
        let ascii = self.scancode_to_ascii(key_code, &state.modifiers);
        
        // Create key event
        let event = KeyEvent {
            scancode: key_code,
            ascii,
            modifiers: state.modifiers,
            pressed,
        };
        
        // Add to input buffer
        if state.input_buffer.len() < 256 {
            state.input_buffer.push_back(event);
        }
    }
    
    /// Convert scancode to ASCII character
    fn scancode_to_ascii(&self, scancode: u8, modifiers: &KeyModifiers) -> Option<char> {
        let base_char = match scancode {
            // Numbers
            0x02 => '1', 0x03 => '2', 0x04 => '3', 0x05 => '4', 0x06 => '5',
            0x07 => '6', 0x08 => '7', 0x09 => '8', 0x0A => '9', 0x0B => '0',
            
            // Letters
            0x10 => 'q', 0x11 => 'w', 0x12 => 'e', 0x13 => 'r', 0x14 => 't',
            0x15 => 'y', 0x16 => 'u', 0x17 => 'i', 0x18 => 'o', 0x19 => 'p',
            0x1E => 'a', 0x1F => 's', 0x20 => 'd', 0x21 => 'f', 0x22 => 'g',
            0x23 => 'h', 0x24 => 'j', 0x25 => 'k', 0x26 => 'l',
            0x2C => 'z', 0x2D => 'x', 0x2E => 'c', 0x2F => 'v', 0x30 => 'b',
            0x31 => 'n', 0x32 => 'm',
            
            // Symbols
            0x0C => '-', 0x0D => '=', 0x1A => '[', 0x1B => ']', 0x27 => ';',
            0x28 => '\'', 0x29 => '`', 0x2B => '\\', 0x33 => ',', 0x34 => '.',
            0x35 => '/',
            
            // Special keys
            0x39 => ' ',    // Space
            0x1C => '\n',   // Enter
            0x0E => '\x08', // Backspace
            0x0F => '\t',   // Tab
            
            _ => return None,
        };
        
        // Handle shift modifications
        if modifiers.shift {
            let shifted = match base_char {
                '1' => '!', '2' => '@', '3' => '#', '4' => '$', '5' => '%',
                '6' => '^', '7' => '&', '8' => '*', '9' => '(', '0' => ')',
                '-' => '_', '=' => '+', '[' => '{', ']' => '}', '\\' => '|',
                ';' => ':', '\'' => '"', '`' => '~', ',' => '<', '.' => '>',
                '/' => '?',
                c if c.is_ascii_lowercase() => c.to_ascii_uppercase(),
                c => c,
            };
            Some(shifted)
        } else {
            // Handle caps lock for letters
            if modifiers.caps_lock && base_char.is_ascii_lowercase() {
                Some(base_char.to_ascii_uppercase())
            } else {
                Some(base_char)
            }
        }
    }
    
    /// Read next key event from buffer
    pub fn read_key(&self) -> Option<KeyEvent> {
        let mut state = self.state.lock();
        state.input_buffer.pop_front()
    }
    
    /// Check if input is available
    pub fn has_input(&self) -> bool {
        let state = self.state.lock();
        !state.input_buffer.is_empty()
    }
    
    /// Update keyboard LEDs
    fn update_leds(&self) -> Result<(), &'static str> {
        let state = self.state.lock();
        self.update_leds_from_state(&state.modifiers)
    }
    
    /// Update LEDs from modifier state
    fn update_leds_from_state(&self, modifiers: &KeyModifiers) -> Result<(), &'static str> {
        let mut led_state = 0u8;
        if modifiers.scroll_lock { led_state |= 0x01; }
        if modifiers.num_lock { led_state |= 0x02; }
        if modifiers.caps_lock { led_state |= 0x04; }
        
        self.send_keyboard_command(CMD_SET_LEDS)?;
        if self.wait_for_data(1000)? != RESP_ACK {
            return Err("Failed to set LEDs command");
        }
        
        self.send_keyboard_data(led_state)?;
        if self.wait_for_data(1000)? != RESP_ACK {
            return Err("Failed to set LEDs data");
        }
        
        Ok(())
    }
    
    /// Send command to keyboard controller
    fn send_controller_command(&self, command: u8) -> Result<(), &'static str> {
        self.wait_input_buffer_empty(1000)?;
        unsafe { (*self.command_port.get()).write(command); }
        Ok(())
    }
    
    /// Send data to keyboard controller
    fn send_controller_data(&self, data: u8) -> Result<(), &'static str> {
        self.wait_input_buffer_empty(1000)?;
        unsafe { (*self.data_port.get()).write(data); }
        Ok(())
    }
    
    /// Send command to keyboard device
    fn send_keyboard_command(&self, command: u8) -> Result<(), &'static str> {
        self.wait_input_buffer_empty(1000)?;
        unsafe { (*self.data_port.get()).write(command); }
        Ok(())
    }
    
    /// Send data to keyboard device
    fn send_keyboard_data(&self, data: u8) -> Result<(), &'static str> {
        self.wait_input_buffer_empty(1000)?;
        unsafe { (*self.data_port.get()).write(data); }
        Ok(())
    }
    
    /// Wait for input buffer to be empty
    fn wait_input_buffer_empty(&self, timeout_ms: u32) -> Result<(), &'static str> {
        for _ in 0..(timeout_ms * 1000) {
            if !self.is_input_buffer_full() {
                return Ok(());
            }
            self.micro_delay();
        }
        Err("Input buffer timeout")
    }
    
    /// Wait for output data to be available
    fn wait_for_data(&self, timeout_ms: u32) -> Result<u8, &'static str> {
        for _ in 0..(timeout_ms * 1000) {
            if self.is_output_buffer_full() {
                return Ok(unsafe { (*self.data_port.get()).read() });
            }
            self.micro_delay();
        }
        Err("Output data timeout")
    }
    
    /// Check if output buffer has data
    fn is_output_buffer_full(&self) -> bool {
        let status = unsafe { (*self.status_port.get()).read() };
        (status & STATUS_OUTPUT_BUFFER_FULL) != 0
    }
    
    /// Check if input buffer is full
    fn is_input_buffer_full(&self) -> bool {
        let status = unsafe { (*self.status_port.get()).read() };
        (status & STATUS_INPUT_BUFFER_FULL) != 0
    }
    
    /// Microsecond delay (very rough)
    fn micro_delay(&self) {
        for _ in 0..100 {
            unsafe { core::arch::asm!("pause"); }
        }
    }
    
    /// Get keyboard statistics
    pub fn get_stats(&self) -> KeyboardStats {
        KeyboardStats {
            keys_pressed: self.keys_pressed.load(Ordering::Relaxed),
            invalid_scancodes: self.invalid_scancodes.load(Ordering::Relaxed),
            buffer_length: {
                let state = self.state.lock();
                state.input_buffer.len()
            },
        }
    }
}

/// Keyboard statistics
#[derive(Debug, Clone)]
pub struct KeyboardStats {
    pub keys_pressed: u64,
    pub invalid_scancodes: u64,
    pub buffer_length: usize,
}

/// Global keyboard driver instance
static mut KEYBOARD_DRIVER: Option<PS2Keyboard> = None;

/// Initialize keyboard driver
pub fn init_keyboard() -> Result<(), &'static str> {
    let keyboard = PS2Keyboard::new();
    keyboard.initialize()?;
    
    unsafe {
        KEYBOARD_DRIVER = Some(keyboard);
    }
    
    Ok(())
}

/// Get keyboard driver instance
pub fn get_keyboard() -> Option<&'static PS2Keyboard> {
    unsafe { KEYBOARD_DRIVER.as_ref() }
}

/// Handle keyboard interrupt (called from interrupt handler)
pub fn handle_keyboard_interrupt() {
    if let Some(keyboard) = get_keyboard() {
        keyboard.handle_interrupt();
    }
}