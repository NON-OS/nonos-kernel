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
//!
//! PS/2 controller support with:
//! **Dual port support**
//! **Full initialization**
//! **Extended scan codes**
//! **Keyboard commands**
//! **Mouse support**
//! **Device detection**
//! **Statistics**
//! **Hot-plug detection**
//!
//! ## PS/2 Controller Architecture
//!
//! The 8042 PS/2 controller has two ports:
//! - Port 1: Primary (typically keyboard)
//! - Port 2: Secondary (typically mouse, directly connected to Aux)
//!
//! ## I/O Ports
//!
//! - 0x60: Data port (read/write)
//! - 0x64: Status register (read) / Command register (write)

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use spin::{Mutex, RwLock};
use super::input::{push_event, InputEvent, InputDevice, DeviceId};

// ============================================================================
// I/O Port Addresses
// ============================================================================

/// PS/2 data port - read/write keyboard/mouse data
const PS2_DATA: u16 = 0x60;

/// PS/2 status/command port - read status, write commands
const PS2_STATUS: u16 = 0x64;
const PS2_CMD: u16 = 0x64;

// ============================================================================
// Status Register Bits
// ============================================================================

/// Output buffer full (data available to read)
const STATUS_OUTPUT_FULL: u8 = 0x01;

/// Input buffer full (controller busy)
const STATUS_INPUT_FULL: u8 = 0x02;

/// System flag (POST passed)
const STATUS_SYSTEM_FLAG: u8 = 0x04;

/// Command/data flag (0=data written to 0x60, 1=command written to 0x64)
const STATUS_COMMAND: u8 = 0x08;

/// Keyboard lock (unused on modern systems)
const STATUS_KEYBOARD_LOCK: u8 = 0x10;

/// Auxiliary output buffer full (mouse data)
const STATUS_AUX_OUTPUT: u8 = 0x20;

/// Timeout error
const STATUS_TIMEOUT: u8 = 0x40;

/// Parity error
const STATUS_PARITY: u8 = 0x80;

// ============================================================================
// Controller Commands
// ============================================================================

/// Read controller configuration byte
const CMD_READ_CONFIG: u8 = 0x20;

/// Write controller configuration byte
const CMD_WRITE_CONFIG: u8 = 0x60;

/// Disable port 2 (mouse)
const CMD_DISABLE_PORT2: u8 = 0xA7;

/// Enable port 2 (mouse)
const CMD_ENABLE_PORT2: u8 = 0xA8;

/// Test port 2
const CMD_TEST_PORT2: u8 = 0xA9;

/// Controller self-test
const CMD_SELF_TEST: u8 = 0xAA;

/// Test port 1
const CMD_TEST_PORT1: u8 = 0xAB;

/// Disable port 1 (keyboard)
const CMD_DISABLE_PORT1: u8 = 0xAD;

/// Enable port 1 (keyboard)
const CMD_ENABLE_PORT1: u8 = 0xAE;

/// Read controller output port
const CMD_READ_OUTPUT: u8 = 0xD0;

/// Write controller output port
const CMD_WRITE_OUTPUT: u8 = 0xD1;

/// Write to port 1 output (keyboard)
const CMD_WRITE_PORT1_OUTPUT: u8 = 0xD2;

/// Write to port 2 output (mouse)
const CMD_WRITE_PORT2_OUTPUT: u8 = 0xD3;

/// Write to port 2 input (send to mouse)
const CMD_WRITE_PORT2_INPUT: u8 = 0xD4;

/// Pulse output line (for reset)
const CMD_PULSE_OUTPUT: u8 = 0xF0;

// ============================================================================
// Configuration Byte Bits
// ============================================================================

/// Port 1 interrupt enabled (IRQ1)
const CONFIG_PORT1_IRQ: u8 = 0x01;

/// Port 2 interrupt enabled (IRQ12)
const CONFIG_PORT2_IRQ: u8 = 0x02;

/// System flag
const CONFIG_SYSTEM_FLAG: u8 = 0x04;

/// Zero (reserved)
const CONFIG_ZERO: u8 = 0x08;

/// Port 1 clock disabled
const CONFIG_PORT1_CLOCK_DISABLED: u8 = 0x10;

/// Port 2 clock disabled
const CONFIG_PORT2_CLOCK_DISABLED: u8 = 0x20;

/// Port 1 translation enabled (scan code set 1)
const CONFIG_TRANSLATION: u8 = 0x40;

/// Zero (reserved)
const CONFIG_ZERO2: u8 = 0x80;

// ============================================================================
// Keyboard Commands (sent to device)
// ============================================================================

/// Set LEDs (followed by LED byte)
const KBD_CMD_SET_LEDS: u8 = 0xED;

/// Echo (returns 0xEE)
const KBD_CMD_ECHO: u8 = 0xEE;

/// Get/set scan code set
const KBD_CMD_SCANCODE_SET: u8 = 0xF0;

/// Identify keyboard
const KBD_CMD_IDENTIFY: u8 = 0xF2;

/// Set typematic rate/delay
const KBD_CMD_SET_TYPEMATIC: u8 = 0xF3;

/// Enable scanning
const KBD_CMD_ENABLE: u8 = 0xF4;

/// Disable scanning
const KBD_CMD_DISABLE: u8 = 0xF5;

/// Set default parameters
const KBD_CMD_SET_DEFAULT: u8 = 0xF6;

/// Resend last byte
const KBD_CMD_RESEND: u8 = 0xFE;

/// Reset and self-test
const KBD_CMD_RESET: u8 = 0xFF;

// ============================================================================
// Keyboard Responses
// ============================================================================

/// Command acknowledged
const KBD_RESP_ACK: u8 = 0xFA;

/// Resend request
const KBD_RESP_RESEND: u8 = 0xFE;

/// Self-test passed
const KBD_RESP_SELF_TEST_PASS: u8 = 0xAA;

/// Self-test failed
const KBD_RESP_SELF_TEST_FAIL: u8 = 0xFC;

/// Echo response
const KBD_RESP_ECHO: u8 = 0xEE;

// ============================================================================
// Mouse Commands
// ============================================================================

/// Set mouse scaling 1:1
const MOUSE_CMD_SCALING_1_1: u8 = 0xE6;

/// Set mouse scaling 2:1
const MOUSE_CMD_SCALING_2_1: u8 = 0xE7;

/// Set mouse resolution
const MOUSE_CMD_SET_RESOLUTION: u8 = 0xE8;

/// Get mouse status
const MOUSE_CMD_STATUS: u8 = 0xE9;

/// Set stream mode
const MOUSE_CMD_STREAM_MODE: u8 = 0xEA;

/// Read mouse data
const MOUSE_CMD_READ_DATA: u8 = 0xEB;

/// Reset wrap mode
const MOUSE_CMD_RESET_WRAP: u8 = 0xEC;

/// Set wrap mode
const MOUSE_CMD_SET_WRAP: u8 = 0xEE;

/// Set remote mode
const MOUSE_CMD_REMOTE_MODE: u8 = 0xF0;

/// Get mouse ID
const MOUSE_CMD_GET_ID: u8 = 0xF2;

/// Set sample rate
const MOUSE_CMD_SET_SAMPLE_RATE: u8 = 0xF3;

/// Enable mouse
const MOUSE_CMD_ENABLE: u8 = 0xF4;

/// Disable mouse
const MOUSE_CMD_DISABLE: u8 = 0xF5;

/// Set defaults
const MOUSE_CMD_SET_DEFAULTS: u8 = 0xF6;

/// Resend
const MOUSE_CMD_RESEND: u8 = 0xFE;

/// Reset
const MOUSE_CMD_RESET: u8 = 0xFF;

// ============================================================================
// Error Handling
// ============================================================================

/// PS/2 controller and device errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2Error {
    /// Controller not initialized
    NotInitialized,
    /// Controller already initialized
    AlreadyInitialized,
    /// Controller self-test failed
    SelfTestFailed,
    /// Port 1 (keyboard) test failed
    Port1TestFailed,
    /// Port 2 (mouse) test failed
    Port2TestFailed,
    /// Timeout waiting for controller
    Timeout,
    /// Parity error in data
    ParityError,
    /// Device not present
    DeviceNotPresent,
    /// Device command failed
    CommandFailed,
    /// Device sent unexpected response
    UnexpectedResponse,
    /// Buffer overflow
    BufferOverflow,
    /// Invalid parameter
    InvalidParameter,
    /// No data available
    NoData,
    /// Port disabled
    PortDisabled,
}

impl Ps2Error {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "PS/2 controller not initialized",
            Self::AlreadyInitialized => "PS/2 controller already initialized",
            Self::SelfTestFailed => "PS/2 controller self-test failed",
            Self::Port1TestFailed => "PS/2 port 1 test failed",
            Self::Port2TestFailed => "PS/2 port 2 test failed",
            Self::Timeout => "PS/2 timeout waiting for controller",
            Self::ParityError => "PS/2 data parity error",
            Self::DeviceNotPresent => "PS/2 device not present",
            Self::CommandFailed => "PS/2 device command failed",
            Self::UnexpectedResponse => "PS/2 unexpected device response",
            Self::BufferOverflow => "PS/2 buffer overflow",
            Self::InvalidParameter => "PS/2 invalid parameter",
            Self::NoData => "PS/2 no data available",
            Self::PortDisabled => "PS/2 port disabled",
        }
    }

    /// Returns error code for logging
    pub const fn code(self) -> u8 {
        match self {
            Self::NotInitialized => 1,
            Self::AlreadyInitialized => 2,
            Self::SelfTestFailed => 3,
            Self::Port1TestFailed => 4,
            Self::Port2TestFailed => 5,
            Self::Timeout => 6,
            Self::ParityError => 7,
            Self::DeviceNotPresent => 8,
            Self::CommandFailed => 9,
            Self::UnexpectedResponse => 10,
            Self::BufferOverflow => 11,
            Self::InvalidParameter => 12,
            Self::NoData => 13,
            Self::PortDisabled => 14,
        }
    }
}

/// Result type for PS/2 operations
pub type Ps2Result<T> = Result<T, Ps2Error>;

// ============================================================================
// Device Types
// ============================================================================

/// PS/2 device type identification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Unknown or no device
    Unknown,
    /// Standard AT keyboard
    AtKeyboard,
    /// MF2 keyboard (most modern keyboards)
    Mf2Keyboard,
    /// MF2 keyboard with translation
    Mf2KeyboardTranslated,
    /// Standard PS/2 mouse
    StandardMouse,
    /// Mouse with scroll wheel
    ScrollMouse,
    /// 5-button mouse with scroll
    FiveButtonMouse,
}

impl DeviceType {
    /// Returns device name
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::AtKeyboard => "AT Keyboard",
            Self::Mf2Keyboard => "MF2 Keyboard",
            Self::Mf2KeyboardTranslated => "MF2 Keyboard (translated)",
            Self::StandardMouse => "Standard PS/2 Mouse",
            Self::ScrollMouse => "Scroll Wheel Mouse",
            Self::FiveButtonMouse => "5-Button Mouse",
        }
    }

    /// Returns true if this is a keyboard
    pub const fn is_keyboard(self) -> bool {
        matches!(self, Self::AtKeyboard | Self::Mf2Keyboard | Self::Mf2KeyboardTranslated)
    }

    /// Returns true if this is a mouse
    pub const fn is_mouse(self) -> bool {
        matches!(self, Self::StandardMouse | Self::ScrollMouse | Self::FiveButtonMouse)
    }

    /// Parse device ID bytes from IDENTIFY command
    pub fn from_id_bytes(bytes: &[u8]) -> Self {
        match bytes {
            [] => Self::AtKeyboard,
            [0xAB, 0x41] | [0xAB, 0xC1] => Self::Mf2KeyboardTranslated,
            [0xAB, 0x83] => Self::Mf2Keyboard,
            [0x00] => Self::StandardMouse,
            [0x03] => Self::ScrollMouse,
            [0x04] => Self::FiveButtonMouse,
            _ => Self::Unknown,
        }
    }
}

// ============================================================================
// Keyboard LED State
// ============================================================================

/// Keyboard LED indicators
#[derive(Debug, Clone, Copy, Default)]
pub struct LedState {
    /// Scroll Lock LED
    pub scroll_lock: bool,
    /// Num Lock LED
    pub num_lock: bool,
    /// Caps Lock LED
    pub caps_lock: bool,
}

impl LedState {
    /// Creates new LED state with all LEDs off
    pub const fn new() -> Self {
        Self {
            scroll_lock: false,
            num_lock: false,
            caps_lock: false,
        }
    }

    /// Converts to byte for SET_LEDS command
    pub const fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.scroll_lock { byte |= 0x01; }
        if self.num_lock { byte |= 0x02; }
        if self.caps_lock { byte |= 0x04; }
        byte
    }

    /// Creates from byte
    pub const fn from_byte(byte: u8) -> Self {
        Self {
            scroll_lock: (byte & 0x01) != 0,
            num_lock: (byte & 0x02) != 0,
            caps_lock: (byte & 0x04) != 0,
        }
    }
}

// ============================================================================
// Typematic Rate Configuration
// ============================================================================

/// Typematic (key repeat) configuration
#[derive(Debug, Clone, Copy)]
pub struct TypematicConfig {
    /// Repeat rate (0-31, where 0=30Hz, 31=2Hz)
    pub rate: u8,
    /// Delay before repeat (0-3, where 0=250ms, 3=1000ms)
    pub delay: u8,
}

impl TypematicConfig {
    /// Default: 10.9 repeats/sec, 500ms delay
    pub const DEFAULT: Self = Self { rate: 0x0B, delay: 0x01 };

    /// Fast: 30 repeats/sec, 250ms delay
    pub const FAST: Self = Self { rate: 0x00, delay: 0x00 };

    /// Slow: 2 repeats/sec, 1000ms delay
    pub const SLOW: Self = Self { rate: 0x1F, delay: 0x03 };

    /// Converts to byte for SET_TYPEMATIC command
    pub const fn to_byte(self) -> u8 {
        (self.delay << 5) | (self.rate & 0x1F)
    }

    /// Creates configuration for specific rate in Hz (approximate)
    pub const fn from_rate_hz(hz: u8) -> Self {
        let rate = match hz {
            30.. => 0x00,
            25..=29 => 0x02,
            20..=24 => 0x04,
            15..=19 => 0x08,
            10..=14 => 0x0C,
            5..=9 => 0x14,
            _ => 0x1F,
        };
        Self { rate, delay: 0x01 }
    }
}

impl Default for TypematicConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ============================================================================
// Scan Code State Machine
// ============================================================================

/// Extended scan code state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanCodeState {
    /// Normal single-byte scan code
    Normal,
    /// Waiting for E0-prefixed byte
    Extended,
    /// Waiting for E1-prefixed bytes (Pause key)
    ExtendedE1(u8),
    /// Print Screen make sequence
    PrintScreenMake(u8),
    /// Print Screen break sequence
    PrintScreenBreak(u8),
}

impl Default for ScanCodeState {
    fn default() -> Self {
        Self::Normal
    }
}

/// Extended scan code result
#[derive(Debug, Clone, Copy)]
pub struct ScanCodeResult {
    /// The scan code (0x00-0xFF)
    pub code: u8,
    /// True if this is a key release
    pub is_release: bool,
    /// True if this is an extended key (E0 prefix)
    pub is_extended: bool,
    /// True if this is the Pause key (E1 prefix)
    pub is_pause: bool,
}

// ============================================================================
// Port State
// ============================================================================

/// State for a single PS/2 port
struct PortState {
    /// Device type connected
    device_type: DeviceType,
    /// Port enabled
    enabled: bool,
    /// Scan code state machine
    scan_state: ScanCodeState,
    /// LED state (for keyboards)
    leds: LedState,
    /// Interrupt count
    interrupt_count: u32,
    /// Error count
    error_count: u32,
}

impl PortState {
    const fn new() -> Self {
        Self {
            device_type: DeviceType::Unknown,
            enabled: false,
            scan_state: ScanCodeState::Normal,
            leds: LedState::new(),
            interrupt_count: 0,
            error_count: 0,
        }
    }
}

// ============================================================================
// Mouse State
// ============================================================================

/// Mouse button state
#[derive(Debug, Clone, Copy, Default)]
pub struct MouseButtons {
    pub left: bool,
    pub right: bool,
    pub middle: bool,
    pub button4: bool,
    pub button5: bool,
}

/// Mouse packet data
#[derive(Debug, Clone, Copy)]
pub struct MousePacket {
    /// X movement (-256 to 255)
    pub dx: i16,
    /// Y movement (-256 to 255)
    pub dy: i16,
    /// Scroll wheel movement (-8 to 7)
    pub dz: i8,
    /// Button states
    pub buttons: MouseButtons,
    /// X overflow
    pub x_overflow: bool,
    /// Y overflow
    pub y_overflow: bool,
}

/// Mouse packet parser state
struct MouseParser {
    /// Expected packet size (3 for standard, 4 for scroll)
    packet_size: u8,
    /// Current byte index
    byte_index: u8,
    /// Packet buffer
    buffer: [u8; 4],
}

impl MouseParser {
    const fn new() -> Self {
        Self {
            packet_size: 3,
            byte_index: 0,
            buffer: [0; 4],
        }
    }

    /// Sets packet size based on mouse type
    fn set_mouse_type(&mut self, device_type: DeviceType) {
        self.packet_size = match device_type {
            DeviceType::ScrollMouse | DeviceType::FiveButtonMouse => 4,
            _ => 3,
        };
    }

    /// Processes a byte, returns packet if complete
    fn process_byte(&mut self, byte: u8) -> Option<MousePacket> {
        // Resync on invalid first byte
        if self.byte_index == 0 && (byte & 0x08) == 0 {
            return None;
        }

        self.buffer[self.byte_index as usize] = byte;
        self.byte_index += 1;

        if self.byte_index >= self.packet_size {
            self.byte_index = 0;
            Some(self.parse_packet())
        } else {
            None
        }
    }

    /// Parses buffered bytes into a packet
    fn parse_packet(&self) -> MousePacket {
        let b0 = self.buffer[0];
        let b1 = self.buffer[1];
        let b2 = self.buffer[2];
        let b3 = if self.packet_size >= 4 { self.buffer[3] } else { 0 };

        // Parse movement with sign extension
        let dx = if (b0 & 0x10) != 0 {
            (b1 as i16) - 256
        } else {
            b1 as i16
        };

        let dy = if (b0 & 0x20) != 0 {
            (b2 as i16) - 256
        } else {
            b2 as i16
        };

        // Parse scroll wheel (signed nibble)
        let dz = if self.packet_size >= 4 {
            let z = (b3 & 0x0F) as i8;
            if z > 7 { z - 16 } else { z }
        } else {
            0
        };

        MousePacket {
            dx,
            dy: -dy, // Invert Y for screen coordinates
            dz,
            buttons: MouseButtons {
                left: (b0 & 0x01) != 0,
                right: (b0 & 0x02) != 0,
                middle: (b0 & 0x04) != 0,
                button4: self.packet_size >= 4 && (b3 & 0x10) != 0,
                button5: self.packet_size >= 4 && (b3 & 0x20) != 0,
            },
            x_overflow: (b0 & 0x40) != 0,
            y_overflow: (b0 & 0x80) != 0,
        }
    }

    /// Resets parser state
    fn reset(&mut self) {
        self.byte_index = 0;
    }
}

// ============================================================================
// Controller State
// ============================================================================

/// Global initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Controller has dual ports
static DUAL_PORT: AtomicBool = AtomicBool::new(false);

/// Current configuration byte
static CONFIG: AtomicU8 = AtomicU8::new(0);

/// Port 1 state
static PORT1: Mutex<PortState> = Mutex::new(PortState::new());

/// Port 2 state
static PORT2: Mutex<PortState> = Mutex::new(PortState::new());

/// Mouse parser
static MOUSE_PARSER: Mutex<MouseParser> = Mutex::new(MouseParser::new());

/// Statistics
static STATS: RwLock<Ps2Stats> = RwLock::new(Ps2Stats::new());

/// PS/2 controller statistics
#[derive(Debug, Clone, Copy)]
pub struct Ps2Stats {
    /// Total keyboard interrupts
    pub keyboard_interrupts: u32,
    /// Total mouse interrupts
    pub mouse_interrupts: u32,
    /// Total parity errors
    pub parity_errors: u32,
    /// Total timeout errors
    pub timeout_errors: u32,
    /// Total buffer overflows
    pub buffer_overflows: u32,
    /// Keyboard scan codes processed
    pub scan_codes_processed: u32,
    /// Mouse packets processed
    pub mouse_packets_processed: u32,
}

impl Ps2Stats {
    const fn new() -> Self {
        Self {
            keyboard_interrupts: 0,
            mouse_interrupts: 0,
            parity_errors: 0,
            timeout_errors: 0,
            buffer_overflows: 0,
            scan_codes_processed: 0,
            mouse_packets_processed: 0,
        }
    }
}

// ============================================================================
// Low-Level I/O
// ============================================================================

/// Default timeout iterations
const TIMEOUT_ITERATIONS: u32 = 100_000;

/// Waits for input buffer to be ready (controller can accept data)
fn wait_input_ready() -> bool {
    for _ in 0..TIMEOUT_ITERATIONS {
        if unsafe { crate::arch::x86_64::port::inb(PS2_STATUS) } & STATUS_INPUT_FULL == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Waits for output buffer to have data
fn wait_output_ready() -> bool {
    for _ in 0..TIMEOUT_ITERATIONS {
        if unsafe { crate::arch::x86_64::port::inb(PS2_STATUS) } & STATUS_OUTPUT_FULL != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Sends a command to the controller
fn send_command(cmd: u8) -> Ps2Result<()> {
    if !wait_input_ready() {
        return Err(Ps2Error::Timeout);
    }
    unsafe { crate::arch::x86_64::port::outb(PS2_CMD, cmd); }
    Ok(())
}

/// Sends data to the data port
fn send_data(data: u8) -> Ps2Result<()> {
    if !wait_input_ready() {
        return Err(Ps2Error::Timeout);
    }
    unsafe { crate::arch::x86_64::port::outb(PS2_DATA, data); }
    Ok(())
}

/// Reads data from the data port
fn read_data() -> Ps2Result<u8> {
    if !wait_output_ready() {
        return Err(Ps2Error::Timeout);
    }
    Ok(unsafe { crate::arch::x86_64::port::inb(PS2_DATA) })
}

/// Reads data if available (non-blocking)
fn try_read_data() -> Option<u8> {
    let status = unsafe { crate::arch::x86_64::port::inb(PS2_STATUS) };
    if status & STATUS_OUTPUT_FULL != 0 {
        Some(unsafe { crate::arch::x86_64::port::inb(PS2_DATA) })
    } else {
        None
    }
}

/// Flushes the output buffer
fn flush_output_buffer() {
    for _ in 0..16 {
        let status = unsafe { crate::arch::x86_64::port::inb(PS2_STATUS) };
        if status & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        unsafe { crate::arch::x86_64::port::inb(PS2_DATA); }
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

/// Sends a command to a keyboard (port 1)
fn send_keyboard_command(cmd: u8) -> Ps2Result<u8> {
    for _ in 0..3 {
        send_data(cmd)?;
        match read_data() {
            Ok(KBD_RESP_ACK) => return Ok(KBD_RESP_ACK),
            Ok(KBD_RESP_RESEND) => continue,
            Ok(other) => return Ok(other),
            Err(e) => return Err(e),
        }
    }
    Err(Ps2Error::CommandFailed)
}

/// Sends a command with parameter to keyboard
fn send_keyboard_command_with_param(cmd: u8, param: u8) -> Ps2Result<()> {
    let resp = send_keyboard_command(cmd)?;
    if resp != KBD_RESP_ACK {
        return Err(Ps2Error::CommandFailed);
    }
    let resp = send_keyboard_command(param)?;
    if resp != KBD_RESP_ACK {
        return Err(Ps2Error::CommandFailed);
    }
    Ok(())
}

/// Sends a command to mouse (port 2)
fn send_mouse_command(cmd: u8) -> Ps2Result<u8> {
    for _ in 0..3 {
        send_command(CMD_WRITE_PORT2_INPUT)?;
        send_data(cmd)?;
        match read_data() {
            Ok(KBD_RESP_ACK) => return Ok(KBD_RESP_ACK),
            Ok(KBD_RESP_RESEND) => continue,
            Ok(other) => return Ok(other),
            Err(e) => return Err(e),
        }
    }
    Err(Ps2Error::CommandFailed)
}

/// Sends a command with parameter to mouse
fn send_mouse_command_with_param(cmd: u8, param: u8) -> Ps2Result<()> {
    let resp = send_mouse_command(cmd)?;
    if resp != KBD_RESP_ACK {
        return Err(Ps2Error::CommandFailed);
    }
    send_command(CMD_WRITE_PORT2_INPUT)?;
    send_data(param)?;
    let resp = read_data()?;
    if resp != KBD_RESP_ACK {
        return Err(Ps2Error::CommandFailed);
    }
    Ok(())
}

// ============================================================================
// Initialization
// ============================================================================

/// Initializes the PS/2 controller and connected devices
///
/// This performs the full initialization sequence:
/// 1. Disable devices
/// 2. Flush output buffer
/// 3. Configure controller
/// 4. Self-test
/// 5. Detect dual-port
/// 6. Port tests
/// 7. Enable ports and interrupts
/// 8. Detect and initialize devices
pub fn init() -> Ps2Result<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(Ps2Error::AlreadyInitialized);
    }

    // Disable both devices
    send_command(CMD_DISABLE_PORT1)?;
    send_command(CMD_DISABLE_PORT2)?;

    // Flush output buffer
    flush_output_buffer();

    // Read and modify configuration
    send_command(CMD_READ_CONFIG)?;
    let mut config = read_data()?;

    // Disable interrupts and translation for now
    config &= !CONFIG_PORT1_IRQ;
    config &= !CONFIG_PORT2_IRQ;
    config &= !CONFIG_TRANSLATION;

    // Check if port 2 exists (bit 5 should be set if disabled)
    let has_port2 = (config & CONFIG_PORT2_CLOCK_DISABLED) != 0;

    send_command(CMD_WRITE_CONFIG)?;
    send_data(config)?;

    // Controller self-test
    send_command(CMD_SELF_TEST)?;
    let result = read_data()?;
    if result != 0x55 {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(Ps2Error::SelfTestFailed);
    }

    // Restore configuration (self-test may reset it)
    send_command(CMD_WRITE_CONFIG)?;
    send_data(config)?;

    // Check for dual-port controller
    let is_dual_port = if has_port2 {
        send_command(CMD_ENABLE_PORT2)?;
        send_command(CMD_READ_CONFIG)?;
        let new_config = read_data()?;
        let dual = (new_config & CONFIG_PORT2_CLOCK_DISABLED) == 0;
        if dual {
            send_command(CMD_DISABLE_PORT2)?;
        }
        dual
    } else {
        false
    };
    DUAL_PORT.store(is_dual_port, Ordering::Release);

    // Test port 1
    send_command(CMD_TEST_PORT1)?;
    let result = read_data()?;
    if result != 0x00 {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(Ps2Error::Port1TestFailed);
    }
    {
        let mut port1 = PORT1.lock();
        port1.enabled = true;
    }

    // Test port 2 if present
    if is_dual_port {
        send_command(CMD_TEST_PORT2)?;
        let result = read_data()?;
        if result == 0x00 {
            let mut port2 = PORT2.lock();
            port2.enabled = true;
        }
    }

    // Enable ports
    send_command(CMD_ENABLE_PORT1)?;
    if is_dual_port && PORT2.lock().enabled {
        send_command(CMD_ENABLE_PORT2)?;
    }

    // Enable interrupts
    send_command(CMD_READ_CONFIG)?;
    config = read_data()?;
    config |= CONFIG_PORT1_IRQ;
    if is_dual_port && PORT2.lock().enabled {
        config |= CONFIG_PORT2_IRQ;
    }
    send_command(CMD_WRITE_CONFIG)?;
    send_data(config)?;
    CONFIG.store(config, Ordering::Release);

    // Detect devices
    detect_devices()?;

    // Enable keyboard IRQ1 on PIC
    unsafe {
        let mask = crate::arch::x86_64::port::inb(0x21);
        crate::arch::x86_64::port::outb(0x21, mask & !0x02);
    }

    // Enable mouse IRQ12 on PIC if present
    if is_dual_port && PORT2.lock().device_type.is_mouse() {
        unsafe {
            let mask = crate::arch::x86_64::port::inb(0xA1);
            crate::arch::x86_64::port::outb(0xA1, mask & !0x10);
        }
    }

    Ok(())
}

/// Detects and initializes connected devices
fn detect_devices() -> Ps2Result<()> {
    // Reset and identify keyboard
    flush_output_buffer();
    if let Ok(resp) = send_keyboard_command(KBD_CMD_RESET) {
        if resp == KBD_RESP_ACK {
            // Wait for self-test result
            if let Ok(st) = read_data() {
                if st == KBD_RESP_SELF_TEST_PASS {
                    // Identify device
                    if send_keyboard_command(KBD_CMD_IDENTIFY).is_ok() {
                        let mut id_bytes = [0u8; 2];
                        let mut id_len = 0;
                        for i in 0..2 {
                            if let Ok(b) = read_data() {
                                id_bytes[i] = b;
                                id_len += 1;
                            } else {
                                break;
                            }
                        }
                        let device_type = DeviceType::from_id_bytes(&id_bytes[..id_len]);
                        let mut port1 = PORT1.lock();
                        port1.device_type = device_type;
                    }
                }
            }
        }
    }

    // Reset and identify mouse if port 2 is enabled
    if DUAL_PORT.load(Ordering::Acquire) && PORT2.lock().enabled {
        flush_output_buffer();
        if let Ok(resp) = send_mouse_command(MOUSE_CMD_RESET) {
            if resp == KBD_RESP_ACK {
                // Wait for self-test
                if let Ok(st) = read_data() {
                    if st == KBD_RESP_SELF_TEST_PASS {
                        // Read device ID
                        if let Ok(id) = read_data() {
                            let device_type = DeviceType::from_id_bytes(&[id]);
                            let mut port2 = PORT2.lock();
                            port2.device_type = device_type;

                            // Try to enable scroll wheel
                            if device_type == DeviceType::StandardMouse {
                                if try_enable_scroll_wheel().is_ok() {
                                    port2.device_type = DeviceType::ScrollMouse;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Enable mouse streaming
        let port2_type = PORT2.lock().device_type;
        if port2_type.is_mouse() {
            let _ = send_mouse_command(MOUSE_CMD_ENABLE);
            MOUSE_PARSER.lock().set_mouse_type(port2_type);
        }
    }

    Ok(())
}

/// Tries to enable scroll wheel on mouse
fn try_enable_scroll_wheel() -> Ps2Result<()> {
    // Magic sequence to enable scroll wheel: set sample rate 200, 100, 80
    send_mouse_command_with_param(MOUSE_CMD_SET_SAMPLE_RATE, 200)?;
    send_mouse_command_with_param(MOUSE_CMD_SET_SAMPLE_RATE, 100)?;
    send_mouse_command_with_param(MOUSE_CMD_SET_SAMPLE_RATE, 80)?;

    // Check if ID changed
    send_mouse_command(MOUSE_CMD_GET_ID)?;
    let id = read_data()?;
    if id == 0x03 {
        Ok(())
    } else {
        Err(Ps2Error::DeviceNotPresent)
    }
}

// ============================================================================
// Public Interface
// ============================================================================

/// Returns true if controller is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Returns true if controller has dual ports
pub fn is_dual_port() -> bool {
    DUAL_PORT.load(Ordering::Acquire)
}

/// Returns port 1 (keyboard) device type
pub fn get_port1_device() -> DeviceType {
    PORT1.lock().device_type
}

/// Returns port 2 (mouse) device type
pub fn get_port2_device() -> DeviceType {
    PORT2.lock().device_type
}

/// Returns controller statistics
pub fn get_stats() -> Ps2Stats {
    *STATS.read()
}

/// Resets statistics
pub fn reset_stats() {
    *STATS.write() = Ps2Stats::new();
}

/// Sets keyboard LED state
pub fn set_leds(leds: LedState) -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    if !PORT1.lock().device_type.is_keyboard() {
        return Err(Ps2Error::DeviceNotPresent);
    }

    send_keyboard_command_with_param(KBD_CMD_SET_LEDS, leds.to_byte())?;
    PORT1.lock().leds = leds;
    Ok(())
}

/// Gets current keyboard LED state
pub fn get_leds() -> LedState {
    PORT1.lock().leds
}

/// Sets keyboard typematic rate
pub fn set_typematic(config: TypematicConfig) -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    if !PORT1.lock().device_type.is_keyboard() {
        return Err(Ps2Error::DeviceNotPresent);
    }

    send_keyboard_command_with_param(KBD_CMD_SET_TYPEMATIC, config.to_byte())
}

/// Sets keyboard scan code set (1, 2, or 3)
pub fn set_scan_code_set(set: u8) -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    if set < 1 || set > 3 {
        return Err(Ps2Error::InvalidParameter);
    }
    send_keyboard_command_with_param(KBD_CMD_SCANCODE_SET, set)
}

/// Gets current keyboard scan code set
pub fn get_scan_code_set() -> Ps2Result<u8> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    send_keyboard_command_with_param(KBD_CMD_SCANCODE_SET, 0)?;
    read_data()
}

/// Sets mouse sample rate (10, 20, 40, 60, 80, 100, 200 samples/sec)
pub fn set_mouse_sample_rate(rate: u8) -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    if !PORT2.lock().device_type.is_mouse() {
        return Err(Ps2Error::DeviceNotPresent);
    }
    send_mouse_command_with_param(MOUSE_CMD_SET_SAMPLE_RATE, rate)
}

/// Sets mouse resolution (0-3, where 0=1 count/mm, 3=8 counts/mm)
pub fn set_mouse_resolution(resolution: u8) -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    if resolution > 3 {
        return Err(Ps2Error::InvalidParameter);
    }
    if !PORT2.lock().device_type.is_mouse() {
        return Err(Ps2Error::DeviceNotPresent);
    }
    send_mouse_command_with_param(MOUSE_CMD_SET_RESOLUTION, resolution)
}

/// Reads a scan code (non-blocking)
pub fn read_scan_code() -> Option<u8> {
    if !is_initialized() {
        return None;
    }
    try_read_data()
}

// ============================================================================
// Interrupt Handling
// ============================================================================

/// Handles keyboard interrupt (IRQ1)
pub fn handle_interrupt() {
    if !is_initialized() {
        return;
    }

    let status = unsafe { crate::arch::x86_64::port::inb(PS2_STATUS) };
    if status & STATUS_OUTPUT_FULL == 0 {
        return;
    }

    // Check for errors
    if status & STATUS_PARITY != 0 {
        let _ = unsafe { crate::arch::x86_64::port::inb(PS2_DATA) };
        STATS.write().parity_errors += 1;
        PORT1.lock().error_count += 1;
        return;
    }

    // Check if this is mouse data
    if status & STATUS_AUX_OUTPUT != 0 {
        handle_mouse_data();
        return;
    }

    // Read keyboard scan code
    let scan_code = unsafe { crate::arch::x86_64::port::inb(PS2_DATA) };

    // Update statistics
    {
        let mut stats = STATS.write();
        stats.keyboard_interrupts += 1;
        stats.scan_codes_processed += 1;
    }
    PORT1.lock().interrupt_count += 1;

    // Process scan code through state machine
    let mut port1 = PORT1.lock();
    if let Some(result) = process_scan_code(&mut port1.scan_state, scan_code) {
        drop(port1); // Release lock before pushing event

        if result.is_release {
            let _ = push_event(InputEvent::key_release(result.code));
        } else {
            let _ = push_event(InputEvent::key_press(result.code));
        }
    }
}

/// Handles mouse interrupt (IRQ12)
pub fn handle_mouse_interrupt() {
    if !is_initialized() || !DUAL_PORT.load(Ordering::Acquire) {
        return;
    }

    let status = unsafe { crate::arch::x86_64::port::inb(PS2_STATUS) };
    if status & STATUS_OUTPUT_FULL == 0 || status & STATUS_AUX_OUTPUT == 0 {
        return;
    }

    handle_mouse_data();
}

/// Processes mouse data byte
fn handle_mouse_data() {
    let byte = unsafe { crate::arch::x86_64::port::inb(PS2_DATA) };

    // Update statistics
    STATS.write().mouse_interrupts += 1;
    PORT2.lock().interrupt_count += 1;

    let mut parser = MOUSE_PARSER.lock();
    if let Some(packet) = parser.process_byte(byte) {
        drop(parser);
        STATS.write().mouse_packets_processed += 1;

        // Push mouse event
        let _ = push_event(InputEvent::mouse_move(packet.dx, packet.dy));

        // Push button events
        // Note: Would need to track button state changes for press/release
        // For now, just push move events
    }
}

/// Processes a scan code through the state machine
fn process_scan_code(state: &mut ScanCodeState, scan_code: u8) -> Option<ScanCodeResult> {
    match *state {
        ScanCodeState::Normal => {
            match scan_code {
                0xE0 => {
                    *state = ScanCodeState::Extended;
                    None
                }
                0xE1 => {
                    *state = ScanCodeState::ExtendedE1(0);
                    None
                }
                _ => {
                    let is_release = (scan_code & 0x80) != 0;
                    let code = scan_code & 0x7F;
                    Some(ScanCodeResult {
                        code,
                        is_release,
                        is_extended: false,
                        is_pause: false,
                    })
                }
            }
        }
        ScanCodeState::Extended => {
            *state = ScanCodeState::Normal;

            // Handle Print Screen make/break
            if scan_code == 0x2A {
                *state = ScanCodeState::PrintScreenMake(0);
                return None;
            }
            if scan_code == 0xB7 {
                *state = ScanCodeState::PrintScreenBreak(0);
                return None;
            }

            let is_release = (scan_code & 0x80) != 0;
            let code = scan_code & 0x7F;
            Some(ScanCodeResult {
                code,
                is_release,
                is_extended: true,
                is_pause: false,
            })
        }
        ScanCodeState::ExtendedE1(count) => {
            // Pause key: E1 1D 45 E1 9D C5
            if count < 5 {
                *state = ScanCodeState::ExtendedE1(count + 1);
                None
            } else {
                *state = ScanCodeState::Normal;
                Some(ScanCodeResult {
                    code: 0x45, // Pause key code
                    is_release: false,
                    is_extended: false,
                    is_pause: true,
                })
            }
        }
        ScanCodeState::PrintScreenMake(count) => {
            if count == 0 && scan_code == 0xE0 {
                *state = ScanCodeState::PrintScreenMake(1);
                None
            } else if count == 1 && scan_code == 0x37 {
                *state = ScanCodeState::Normal;
                Some(ScanCodeResult {
                    code: 0x37, // Print Screen
                    is_release: false,
                    is_extended: true,
                    is_pause: false,
                })
            } else {
                *state = ScanCodeState::Normal;
                None
            }
        }
        ScanCodeState::PrintScreenBreak(count) => {
            if count == 0 && scan_code == 0xE0 {
                *state = ScanCodeState::PrintScreenBreak(1);
                None
            } else if count == 1 && scan_code == 0xAA {
                *state = ScanCodeState::Normal;
                Some(ScanCodeResult {
                    code: 0x37, // Print Screen
                    is_release: true,
                    is_extended: true,
                    is_pause: false,
                })
            } else {
                *state = ScanCodeState::Normal;
                None
            }
        }
    }
}

// ============================================================================
// InputDevice Implementation for PS/2 Keyboard
// ============================================================================

/// PS/2 Keyboard as an InputDevice
pub struct Ps2Keyboard;

impl Ps2Keyboard {
    /// Device ID for PS/2 keyboard
    pub const DEVICE_ID: DeviceId = DeviceId(1);

    /// Creates a new PS/2 keyboard device
    pub const fn new() -> Self {
        Self
    }
}

impl InputDevice for Ps2Keyboard {
    fn device_id(&self) -> DeviceId {
        Self::DEVICE_ID
    }

    fn name(&self) -> &'static str {
        "PS/2 Keyboard"
    }

    fn device_type(&self) -> &'static str {
        let dt = get_port1_device();
        dt.name()
    }

    fn is_connected(&self) -> bool {
        is_initialized() && get_port1_device().is_keyboard()
    }

    fn poll(&self) -> Option<InputEvent> {
        if !is_initialized() {
            return None;
        }

        let status = unsafe { crate::arch::x86_64::port::inb(PS2_STATUS) };
        if status & STATUS_OUTPUT_FULL == 0 || status & STATUS_AUX_OUTPUT != 0 {
            return None;
        }

        let scan_code = unsafe { crate::arch::x86_64::port::inb(PS2_DATA) };
        let is_release = (scan_code & 0x80) != 0;
        let code = scan_code & 0x7F;

        if is_release {
            Some(InputEvent::key_release(code))
        } else {
            Some(InputEvent::key_press(code))
        }
    }
}

/// PS/2 Mouse as an InputDevice
pub struct Ps2Mouse;

impl Ps2Mouse {
    /// Device ID for PS/2 mouse
    pub const DEVICE_ID: DeviceId = DeviceId(2);

    /// Creates a new PS/2 mouse device
    pub const fn new() -> Self {
        Self
    }
}

impl InputDevice for Ps2Mouse {
    fn device_id(&self) -> DeviceId {
        Self::DEVICE_ID
    }

    fn name(&self) -> &'static str {
        "PS/2 Mouse"
    }

    fn device_type(&self) -> &'static str {
        let dt = get_port2_device();
        dt.name()
    }

    fn is_connected(&self) -> bool {
        is_initialized() && is_dual_port() && get_port2_device().is_mouse()
    }

    fn poll(&self) -> Option<InputEvent> {
        // Mouse data comes through interrupts, not polling
        None
    }
}

// ============================================================================
// Shutdown / Reset
// ============================================================================

/// Disables the PS/2 controller
pub fn shutdown() -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }

    // Disable interrupts
    send_command(CMD_READ_CONFIG)?;
    let mut config = read_data()?;
    config &= !CONFIG_PORT1_IRQ;
    config &= !CONFIG_PORT2_IRQ;
    send_command(CMD_WRITE_CONFIG)?;
    send_data(config)?;

    // Disable ports
    send_command(CMD_DISABLE_PORT1)?;
    send_command(CMD_DISABLE_PORT2)?;

    // Mask IRQs
    unsafe {
        let mask = crate::arch::x86_64::port::inb(0x21);
        crate::arch::x86_64::port::outb(0x21, mask | 0x02);
        let mask = crate::arch::x86_64::port::inb(0xA1);
        crate::arch::x86_64::port::outb(0xA1, mask | 0x10);
    }

    INITIALIZED.store(false, Ordering::SeqCst);
    Ok(())
}

/// Resets the PS/2 controller and reinitializes
pub fn reset() -> Ps2Result<()> {
    if is_initialized() {
        shutdown()?;
    }
    // Reset port state
    *PORT1.lock() = PortState::new();
    *PORT2.lock() = PortState::new();
    MOUSE_PARSER.lock().reset();
    init()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(Ps2Error::Timeout.as_str(), "PS/2 timeout waiting for controller");
        assert_eq!(Ps2Error::SelfTestFailed.as_str(), "PS/2 controller self-test failed");
        assert_eq!(Ps2Error::Port1TestFailed.as_str(), "PS/2 port 1 test failed");
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(Ps2Error::NotInitialized.code(), 1);
        assert_eq!(Ps2Error::Timeout.code(), 6);
        assert_eq!(Ps2Error::PortDisabled.code(), 14);
    }

    #[test]
    fn test_device_type_names() {
        assert_eq!(DeviceType::AtKeyboard.name(), "AT Keyboard");
        assert_eq!(DeviceType::Mf2Keyboard.name(), "MF2 Keyboard");
        assert_eq!(DeviceType::StandardMouse.name(), "Standard PS/2 Mouse");
    }

    #[test]
    fn test_device_type_classification() {
        assert!(DeviceType::AtKeyboard.is_keyboard());
        assert!(DeviceType::Mf2Keyboard.is_keyboard());
        assert!(!DeviceType::StandardMouse.is_keyboard());

        assert!(!DeviceType::AtKeyboard.is_mouse());
        assert!(DeviceType::StandardMouse.is_mouse());
        assert!(DeviceType::ScrollMouse.is_mouse());
    }

    #[test]
    fn test_device_type_from_id() {
        assert_eq!(DeviceType::from_id_bytes(&[]), DeviceType::AtKeyboard);
        assert_eq!(DeviceType::from_id_bytes(&[0xAB, 0x83]), DeviceType::Mf2Keyboard);
        assert_eq!(DeviceType::from_id_bytes(&[0x00]), DeviceType::StandardMouse);
        assert_eq!(DeviceType::from_id_bytes(&[0x03]), DeviceType::ScrollMouse);
        assert_eq!(DeviceType::from_id_bytes(&[0x04]), DeviceType::FiveButtonMouse);
    }

    #[test]
    fn test_led_state() {
        let leds = LedState {
            scroll_lock: true,
            num_lock: false,
            caps_lock: true,
        };
        assert_eq!(leds.to_byte(), 0x05);

        let leds2 = LedState::from_byte(0x05);
        assert!(leds2.scroll_lock);
        assert!(!leds2.num_lock);
        assert!(leds2.caps_lock);
    }

    #[test]
    fn test_typematic_config() {
        let config = TypematicConfig::DEFAULT;
        assert_eq!(config.to_byte(), 0x2B);

        let fast = TypematicConfig::FAST;
        assert_eq!(fast.to_byte(), 0x00);

        let slow = TypematicConfig::SLOW;
        assert_eq!(slow.to_byte(), 0x7F);
    }

    #[test]
    fn test_typematic_from_hz() {
        let config = TypematicConfig::from_rate_hz(30);
        assert_eq!(config.rate, 0x00);

        let config = TypematicConfig::from_rate_hz(10);
        assert_eq!(config.rate, 0x0C);
    }

    #[test]
    fn test_scan_code_state_machine() {
        let mut state = ScanCodeState::Normal;

        // Normal key press
        let result = process_scan_code(&mut state, 0x1E);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.code, 0x1E);
        assert!(!r.is_release);
        assert!(!r.is_extended);

        // Normal key release
        let result = process_scan_code(&mut state, 0x9E);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.code, 0x1E);
        assert!(r.is_release);

        // Extended key
        let result = process_scan_code(&mut state, 0xE0);
        assert!(result.is_none());
        assert_eq!(state, ScanCodeState::Extended);

        let result = process_scan_code(&mut state, 0x48); // Up arrow
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.code, 0x48);
        assert!(r.is_extended);
    }

    #[test]
    fn test_mouse_packet_parsing() {
        let mut parser = MouseParser::new();

        // First byte must have bit 3 set
        let result = parser.process_byte(0x00);
        assert!(result.is_none());

        // Valid 3-byte packet
        let result = parser.process_byte(0x08); // Bit 3 set, no buttons
        assert!(result.is_none());
        let result = parser.process_byte(10); // dx = 10
        assert!(result.is_none());
        let result = parser.process_byte(5); // dy = 5
        assert!(result.is_some());

        let packet = result.unwrap();
        assert_eq!(packet.dx, 10);
        assert_eq!(packet.dy, -5); // Inverted
        assert!(!packet.buttons.left);
    }

    #[test]
    fn test_mouse_buttons() {
        let mut parser = MouseParser::new();

        // Packet with left and right buttons
        let _ = parser.process_byte(0x0B); // Bit 3 set, left+right
        let _ = parser.process_byte(0);
        let result = parser.process_byte(0);

        let packet = result.unwrap();
        assert!(packet.buttons.left);
        assert!(packet.buttons.right);
        assert!(!packet.buttons.middle);
    }

    #[test]
    fn test_stats() {
        let stats = Ps2Stats::new();
        assert_eq!(stats.keyboard_interrupts, 0);
        assert_eq!(stats.mouse_interrupts, 0);
        assert_eq!(stats.parity_errors, 0);
    }

    #[test]
    fn test_ps2_keyboard_device() {
        let kbd = Ps2Keyboard::new();
        assert_eq!(kbd.device_id(), DeviceId(1));
        assert_eq!(kbd.name(), "PS/2 Keyboard");
    }

    #[test]
    fn test_ps2_mouse_device() {
        let mouse = Ps2Mouse::new();
        assert_eq!(mouse.device_id(), DeviceId(2));
        assert_eq!(mouse.name(), "PS/2 Mouse");
    }
}
