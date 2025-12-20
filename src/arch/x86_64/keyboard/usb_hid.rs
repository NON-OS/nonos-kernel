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
//! USB HID (Human Interface Device) support with:
//! **Keyboard support**
//! **Mouse support**
//! **Key state tracking**
//! **Modifier tracking**
//! **LED control**
//! **Multiple devices**
//! **HID usage tables**
//! **Statistics**
//! **Hot-plug support**
//!
//! ## USB HID Protocol
//!
//! HID devices communicate via interrupt endpoints with periodic reports:
//! - Keyboard boot report: 8 bytes (modifiers, reserved, 6 keycodes)
//! - Mouse boot report: 3+ bytes (buttons, X, Y, optional wheel)
//!
//! ## HID Class Codes
//!
//! - Class: 0x03 (HID)
//! - Subclass: 0x01 (Boot Interface)
//! - Protocol: 0x01 (Keyboard) or 0x02 (Mouse)

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use spin::{Mutex, RwLock};
use super::input::{push_event, InputEvent, InputDevice, DeviceId};

// ============================================================================
// Constants
// ============================================================================

/// HID class code
const HID_CLASS: u8 = 0x03;

/// HID boot interface subclass
const HID_SUBCLASS_BOOT: u8 = 0x01;

/// HID keyboard protocol
const HID_PROTOCOL_KEYBOARD: u8 = 0x01;

/// HID mouse protocol
const HID_PROTOCOL_MOUSE: u8 = 0x02;

/// Maximum number of tracked HID devices
const MAX_HID_DEVICES: usize = 8;

/// Maximum keys that can be pressed simultaneously (6-key rollover)
const MAX_KEYS_PRESSED: usize = 6;

/// Keyboard boot report size
const KEYBOARD_REPORT_SIZE: usize = 8;

/// Mouse boot report size (minimum)
const MOUSE_REPORT_MIN_SIZE: usize = 3;

/// Mouse report with scroll wheel
const MOUSE_REPORT_SCROLL_SIZE: usize = 4;

/// Mouse report with scroll and extra buttons
const MOUSE_REPORT_EXTENDED_SIZE: usize = 5;

// ============================================================================
// Error Handling
// ============================================================================

/// USB HID driver errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbHidError {
    /// Driver not initialized
    NotInitialized,
    /// Driver already initialized
    AlreadyInitialized,
    /// xHCI controller initialization failed
    XhciInitFailed,
    /// USB stack initialization failed
    UsbInitFailed,
    /// No HID devices found
    NoDevices,
    /// Device enumeration failed
    EnumerationFailed,
    /// Polling failed
    PollFailed,
    /// Invalid report received
    InvalidReport,
    /// Device not found
    DeviceNotFound,
    /// Endpoint not found
    EndpointNotFound,
    /// Transfer failed
    TransferFailed,
    /// Device registry full
    RegistryFull,
    /// Invalid device ID
    InvalidDeviceId,
    /// Set protocol failed
    SetProtocolFailed,
    /// Set LED failed
    SetLedFailed,
    /// Timeout
    Timeout,
}

impl UsbHidError {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "USB HID driver not initialized",
            Self::AlreadyInitialized => "USB HID driver already initialized",
            Self::XhciInitFailed => "xHCI controller initialization failed",
            Self::UsbInitFailed => "USB stack initialization failed",
            Self::NoDevices => "no USB HID devices found",
            Self::EnumerationFailed => "HID device enumeration failed",
            Self::PollFailed => "USB HID polling failed",
            Self::InvalidReport => "invalid HID report received",
            Self::DeviceNotFound => "USB HID device not found",
            Self::EndpointNotFound => "USB HID endpoint not found",
            Self::TransferFailed => "USB transfer failed",
            Self::RegistryFull => "USB HID device registry full",
            Self::InvalidDeviceId => "invalid USB HID device ID",
            Self::SetProtocolFailed => "failed to set HID protocol",
            Self::SetLedFailed => "failed to set keyboard LEDs",
            Self::Timeout => "USB HID operation timeout",
        }
    }

    /// Returns error code for logging
    pub const fn code(self) -> u8 {
        match self {
            Self::NotInitialized => 1,
            Self::AlreadyInitialized => 2,
            Self::XhciInitFailed => 3,
            Self::UsbInitFailed => 4,
            Self::NoDevices => 5,
            Self::EnumerationFailed => 6,
            Self::PollFailed => 7,
            Self::InvalidReport => 8,
            Self::DeviceNotFound => 9,
            Self::EndpointNotFound => 10,
            Self::TransferFailed => 11,
            Self::RegistryFull => 12,
            Self::InvalidDeviceId => 13,
            Self::SetProtocolFailed => 14,
            Self::SetLedFailed => 15,
            Self::Timeout => 16,
        }
    }
}

/// Result type for USB HID operations
pub type UsbHidResult<T> = Result<T, UsbHidError>;

// ============================================================================
// HID Device Types
// ============================================================================

/// USB HID device type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidDeviceType {
    /// Unknown HID device
    Unknown,
    /// Boot protocol keyboard
    BootKeyboard,
    /// Report protocol keyboard
    ReportKeyboard,
    /// Boot protocol mouse
    BootMouse,
    /// Report protocol mouse (with scroll)
    ScrollMouse,
    /// Extended mouse (5+ buttons)
    ExtendedMouse,
    /// Composite device (keyboard + mouse)
    Composite,
}

impl HidDeviceType {
    /// Returns device type name
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown HID Device",
            Self::BootKeyboard => "USB Boot Keyboard",
            Self::ReportKeyboard => "USB Keyboard",
            Self::BootMouse => "USB Boot Mouse",
            Self::ScrollMouse => "USB Scroll Mouse",
            Self::ExtendedMouse => "USB Extended Mouse",
            Self::Composite => "USB Composite Device",
        }
    }

    /// Returns true if this is a keyboard
    pub const fn is_keyboard(self) -> bool {
        matches!(self, Self::BootKeyboard | Self::ReportKeyboard)
    }

    /// Returns true if this is a mouse
    pub const fn is_mouse(self) -> bool {
        matches!(self, Self::BootMouse | Self::ScrollMouse | Self::ExtendedMouse)
    }

    /// Returns true if this device has a scroll wheel
    pub const fn has_scroll(self) -> bool {
        matches!(self, Self::ScrollMouse | Self::ExtendedMouse)
    }
}

// ============================================================================
// Keyboard Modifier Tracking
// ============================================================================

/// Keyboard modifier key states (from HID boot report byte 0)
#[derive(Debug, Clone, Copy, Default)]
pub struct ModifierState {
    /// Left Control
    pub left_ctrl: bool,
    /// Left Shift
    pub left_shift: bool,
    /// Left Alt
    pub left_alt: bool,
    /// Left GUI (Windows/Command)
    pub left_gui: bool,
    /// Right Control
    pub right_ctrl: bool,
    /// Right Shift
    pub right_shift: bool,
    /// Right Alt (AltGr)
    pub right_alt: bool,
    /// Right GUI
    pub right_gui: bool,
}

impl ModifierState {
    /// Creates modifier state from HID boot report byte
    pub const fn from_byte(byte: u8) -> Self {
        Self {
            left_ctrl: (byte & 0x01) != 0,
            left_shift: (byte & 0x02) != 0,
            left_alt: (byte & 0x04) != 0,
            left_gui: (byte & 0x08) != 0,
            right_ctrl: (byte & 0x10) != 0,
            right_shift: (byte & 0x20) != 0,
            right_alt: (byte & 0x40) != 0,
            right_gui: (byte & 0x80) != 0,
        }
    }

    /// Converts to byte
    pub const fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.left_ctrl { byte |= 0x01; }
        if self.left_shift { byte |= 0x02; }
        if self.left_alt { byte |= 0x04; }
        if self.left_gui { byte |= 0x08; }
        if self.right_ctrl { byte |= 0x10; }
        if self.right_shift { byte |= 0x20; }
        if self.right_alt { byte |= 0x40; }
        if self.right_gui { byte |= 0x80; }
        byte
    }

    /// Returns true if any shift is pressed
    pub const fn shift(self) -> bool {
        self.left_shift || self.right_shift
    }

    /// Returns true if any control is pressed
    pub const fn ctrl(self) -> bool {
        self.left_ctrl || self.right_ctrl
    }

    /// Returns true if any alt is pressed
    pub const fn alt(self) -> bool {
        self.left_alt || self.right_alt
    }

    /// Returns true if any GUI is pressed
    pub const fn gui(self) -> bool {
        self.left_gui || self.right_gui
    }

    /// Returns true if AltGr (right alt) is pressed
    pub const fn altgr(self) -> bool {
        self.right_alt
    }
}

// ============================================================================
// Keyboard LED State
// ============================================================================

/// Keyboard LED indicators
#[derive(Debug, Clone, Copy, Default)]
pub struct LedState {
    /// Num Lock LED
    pub num_lock: bool,
    /// Caps Lock LED
    pub caps_lock: bool,
    /// Scroll Lock LED
    pub scroll_lock: bool,
    /// Compose LED (not common)
    pub compose: bool,
    /// Kana LED (not common)
    pub kana: bool,
}

impl LedState {
    /// Creates new LED state with all off
    pub const fn new() -> Self {
        Self {
            num_lock: false,
            caps_lock: false,
            scroll_lock: false,
            compose: false,
            kana: false,
        }
    }

    /// Converts to HID output report byte
    pub const fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.num_lock { byte |= 0x01; }
        if self.caps_lock { byte |= 0x02; }
        if self.scroll_lock { byte |= 0x04; }
        if self.compose { byte |= 0x08; }
        if self.kana { byte |= 0x10; }
        byte
    }

    /// Creates from byte
    pub const fn from_byte(byte: u8) -> Self {
        Self {
            num_lock: (byte & 0x01) != 0,
            caps_lock: (byte & 0x02) != 0,
            scroll_lock: (byte & 0x04) != 0,
            compose: (byte & 0x08) != 0,
            kana: (byte & 0x10) != 0,
        }
    }
}

// ============================================================================
// Mouse Button State
// ============================================================================

/// Mouse button states
#[derive(Debug, Clone, Copy, Default)]
pub struct MouseButtonState {
    /// Left button
    pub left: bool,
    /// Right button
    pub right: bool,
    /// Middle button
    pub middle: bool,
    /// Button 4 (back)
    pub button4: bool,
    /// Button 5 (forward)
    pub button5: bool,
}

impl MouseButtonState {
    /// Creates from HID report byte
    pub const fn from_byte(byte: u8) -> Self {
        Self {
            left: (byte & 0x01) != 0,
            right: (byte & 0x02) != 0,
            middle: (byte & 0x04) != 0,
            button4: (byte & 0x08) != 0,
            button5: (byte & 0x10) != 0,
        }
    }

    /// Converts to byte
    pub const fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.left { byte |= 0x01; }
        if self.right { byte |= 0x02; }
        if self.middle { byte |= 0x04; }
        if self.button4 { byte |= 0x08; }
        if self.button5 { byte |= 0x10; }
        byte
    }

    /// Returns button state by index (0-4)
    pub const fn get(self, index: u8) -> bool {
        match index {
            0 => self.left,
            1 => self.right,
            2 => self.middle,
            3 => self.button4,
            4 => self.button5,
            _ => false,
        }
    }
}

// ============================================================================
// HID Device State
// ============================================================================

/// State for a tracked HID device
#[derive(Clone)]
struct HidDeviceState {
    /// USB slot ID
    slot_id: u8,
    /// Endpoint address
    endpoint: u8,
    /// Device type
    device_type: HidDeviceType,
    /// Interface number
    interface: u8,
    /// Is device active
    active: bool,
    /// Last keyboard report (for detecting changes)
    last_keyboard_report: [u8; KEYBOARD_REPORT_SIZE],
    /// Current modifier state
    modifiers: ModifierState,
    /// Current LED state
    leds: LedState,
    /// Last mouse buttons
    last_mouse_buttons: MouseButtonState,
    /// Report count (for statistics)
    report_count: u32,
    /// Error count
    error_count: u32,
}

impl HidDeviceState {
    const fn new() -> Self {
        Self {
            slot_id: 0,
            endpoint: 0,
            device_type: HidDeviceType::Unknown,
            interface: 0,
            active: false,
            last_keyboard_report: [0; KEYBOARD_REPORT_SIZE],
            modifiers: ModifierState {
                left_ctrl: false,
                left_shift: false,
                left_alt: false,
                left_gui: false,
                right_ctrl: false,
                right_shift: false,
                right_alt: false,
                right_gui: false,
            },
            leds: LedState::new(),
            last_mouse_buttons: MouseButtonState {
                left: false,
                right: false,
                middle: false,
                button4: false,
                button5: false,
            },
            report_count: 0,
            error_count: 0,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

/// Driver initialized flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Number of active HID devices
static DEVICE_COUNT: AtomicU8 = AtomicU8::new(0);

/// HID device registry
static DEVICES: Mutex<[HidDeviceState; MAX_HID_DEVICES]> = Mutex::new([
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
    HidDeviceState::new(),
]);

/// Statistics
static STATS: RwLock<UsbHidStats> = RwLock::new(UsbHidStats::new());

/// USB HID statistics
#[derive(Debug, Clone, Copy)]
pub struct UsbHidStats {
    /// Total keyboard reports processed
    pub keyboard_reports: u32,
    /// Total mouse reports processed
    pub mouse_reports: u32,
    /// Total key press events
    pub key_presses: u32,
    /// Total key release events
    pub key_releases: u32,
    /// Total mouse move events
    pub mouse_moves: u32,
    /// Total mouse button events
    pub mouse_buttons: u32,
    /// Total poll cycles
    pub poll_cycles: u32,
    /// Total errors
    pub errors: u32,
    /// Devices connected
    pub devices_connected: u8,
    /// Devices disconnected
    pub devices_disconnected: u8,
}

impl UsbHidStats {
    const fn new() -> Self {
        Self {
            keyboard_reports: 0,
            mouse_reports: 0,
            key_presses: 0,
            key_releases: 0,
            mouse_moves: 0,
            mouse_buttons: 0,
            poll_cycles: 0,
            errors: 0,
            devices_connected: 0,
            devices_disconnected: 0,
        }
    }
}

// ============================================================================
// HID Usage Table - Keyboard
// ============================================================================

/// USB HID usage codes for keyboard (Usage Page 0x07)
pub mod usage {
    // Letters
    pub const KEY_A: u8 = 0x04;
    pub const KEY_B: u8 = 0x05;
    pub const KEY_C: u8 = 0x06;
    pub const KEY_D: u8 = 0x07;
    pub const KEY_E: u8 = 0x08;
    pub const KEY_F: u8 = 0x09;
    pub const KEY_G: u8 = 0x0A;
    pub const KEY_H: u8 = 0x0B;
    pub const KEY_I: u8 = 0x0C;
    pub const KEY_J: u8 = 0x0D;
    pub const KEY_K: u8 = 0x0E;
    pub const KEY_L: u8 = 0x0F;
    pub const KEY_M: u8 = 0x10;
    pub const KEY_N: u8 = 0x11;
    pub const KEY_O: u8 = 0x12;
    pub const KEY_P: u8 = 0x13;
    pub const KEY_Q: u8 = 0x14;
    pub const KEY_R: u8 = 0x15;
    pub const KEY_S: u8 = 0x16;
    pub const KEY_T: u8 = 0x17;
    pub const KEY_U: u8 = 0x18;
    pub const KEY_V: u8 = 0x19;
    pub const KEY_W: u8 = 0x1A;
    pub const KEY_X: u8 = 0x1B;
    pub const KEY_Y: u8 = 0x1C;
    pub const KEY_Z: u8 = 0x1D;

    // Numbers
    pub const KEY_1: u8 = 0x1E;
    pub const KEY_2: u8 = 0x1F;
    pub const KEY_3: u8 = 0x20;
    pub const KEY_4: u8 = 0x21;
    pub const KEY_5: u8 = 0x22;
    pub const KEY_6: u8 = 0x23;
    pub const KEY_7: u8 = 0x24;
    pub const KEY_8: u8 = 0x25;
    pub const KEY_9: u8 = 0x26;
    pub const KEY_0: u8 = 0x27;

    // Special keys
    pub const KEY_ENTER: u8 = 0x28;
    pub const KEY_ESCAPE: u8 = 0x29;
    pub const KEY_BACKSPACE: u8 = 0x2A;
    pub const KEY_TAB: u8 = 0x2B;
    pub const KEY_SPACE: u8 = 0x2C;
    pub const KEY_MINUS: u8 = 0x2D;
    pub const KEY_EQUALS: u8 = 0x2E;
    pub const KEY_LEFT_BRACKET: u8 = 0x2F;
    pub const KEY_RIGHT_BRACKET: u8 = 0x30;
    pub const KEY_BACKSLASH: u8 = 0x31;
    pub const KEY_HASH: u8 = 0x32; // Non-US #
    pub const KEY_SEMICOLON: u8 = 0x33;
    pub const KEY_APOSTROPHE: u8 = 0x34;
    pub const KEY_GRAVE: u8 = 0x35;
    pub const KEY_COMMA: u8 = 0x36;
    pub const KEY_PERIOD: u8 = 0x37;
    pub const KEY_SLASH: u8 = 0x38;
    pub const KEY_CAPS_LOCK: u8 = 0x39;

    // Function keys
    pub const KEY_F1: u8 = 0x3A;
    pub const KEY_F2: u8 = 0x3B;
    pub const KEY_F3: u8 = 0x3C;
    pub const KEY_F4: u8 = 0x3D;
    pub const KEY_F5: u8 = 0x3E;
    pub const KEY_F6: u8 = 0x3F;
    pub const KEY_F7: u8 = 0x40;
    pub const KEY_F8: u8 = 0x41;
    pub const KEY_F9: u8 = 0x42;
    pub const KEY_F10: u8 = 0x43;
    pub const KEY_F11: u8 = 0x44;
    pub const KEY_F12: u8 = 0x45;

    // Navigation
    pub const KEY_PRINT_SCREEN: u8 = 0x46;
    pub const KEY_SCROLL_LOCK: u8 = 0x47;
    pub const KEY_PAUSE: u8 = 0x48;
    pub const KEY_INSERT: u8 = 0x49;
    pub const KEY_HOME: u8 = 0x4A;
    pub const KEY_PAGE_UP: u8 = 0x4B;
    pub const KEY_DELETE: u8 = 0x4C;
    pub const KEY_END: u8 = 0x4D;
    pub const KEY_PAGE_DOWN: u8 = 0x4E;
    pub const KEY_RIGHT_ARROW: u8 = 0x4F;
    pub const KEY_LEFT_ARROW: u8 = 0x50;
    pub const KEY_DOWN_ARROW: u8 = 0x51;
    pub const KEY_UP_ARROW: u8 = 0x52;

    // Numpad
    pub const KEY_NUM_LOCK: u8 = 0x53;
    pub const KEY_KP_DIVIDE: u8 = 0x54;
    pub const KEY_KP_MULTIPLY: u8 = 0x55;
    pub const KEY_KP_MINUS: u8 = 0x56;
    pub const KEY_KP_PLUS: u8 = 0x57;
    pub const KEY_KP_ENTER: u8 = 0x58;
    pub const KEY_KP_1: u8 = 0x59;
    pub const KEY_KP_2: u8 = 0x5A;
    pub const KEY_KP_3: u8 = 0x5B;
    pub const KEY_KP_4: u8 = 0x5C;
    pub const KEY_KP_5: u8 = 0x5D;
    pub const KEY_KP_6: u8 = 0x5E;
    pub const KEY_KP_7: u8 = 0x5F;
    pub const KEY_KP_8: u8 = 0x60;
    pub const KEY_KP_9: u8 = 0x61;
    pub const KEY_KP_0: u8 = 0x62;
    pub const KEY_KP_DECIMAL: u8 = 0x63;

    // Modifiers (reported in modifier byte, not keycode array)
    pub const KEY_LEFT_CTRL: u8 = 0xE0;
    pub const KEY_LEFT_SHIFT: u8 = 0xE1;
    pub const KEY_LEFT_ALT: u8 = 0xE2;
    pub const KEY_LEFT_GUI: u8 = 0xE3;
    pub const KEY_RIGHT_CTRL: u8 = 0xE4;
    pub const KEY_RIGHT_SHIFT: u8 = 0xE5;
    pub const KEY_RIGHT_ALT: u8 = 0xE6;
    pub const KEY_RIGHT_GUI: u8 = 0xE7;

    // Error codes
    pub const ERR_ROLLOVER: u8 = 0x01;
    pub const ERR_POST_FAIL: u8 = 0x02;
    pub const ERR_UNDEFINED: u8 = 0x03;
}

// ============================================================================
// HID to PS/2 Scan Code Conversion
// ============================================================================

/// Converts HID usage code to PS/2 Set 1 scan code
pub fn hid_to_scancode(hid_usage: u8) -> u8 {
    // This maps USB HID keyboard usage codes to PS/2 Set 1 scan codes
    // for compatibility with the existing input system
    match hid_usage {
        // Letters (A-Z)
        0x04..=0x1D => {
            const MAP: [u8; 26] = [
                0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24,
                0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14,
                0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
            ];
            MAP[(hid_usage - 0x04) as usize]
        }
        // Numbers (1-9, 0)
        0x1E..=0x27 => {
            const MAP: [u8; 10] = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B];
            MAP[(hid_usage - 0x1E) as usize]
        }
        // Special keys
        0x28 => 0x1C, // Enter
        0x29 => 0x01, // Escape
        0x2A => 0x0E, // Backspace
        0x2B => 0x0F, // Tab
        0x2C => 0x39, // Space
        0x2D => 0x0C, // Minus
        0x2E => 0x0D, // Equals
        0x2F => 0x1A, // Left bracket
        0x30 => 0x1B, // Right bracket
        0x31 => 0x2B, // Backslash
        0x33 => 0x27, // Semicolon
        0x34 => 0x28, // Apostrophe
        0x35 => 0x29, // Grave
        0x36 => 0x33, // Comma
        0x37 => 0x34, // Period
        0x38 => 0x35, // Slash
        0x39 => 0x3A, // Caps Lock
        // Function keys
        0x3A..=0x45 => 0x3B + (hid_usage - 0x3A), // F1-F12
        // Navigation (extended codes, we add 0x80 to indicate E0 prefix)
        0x49 => 0x52, // Insert
        0x4A => 0x47, // Home
        0x4B => 0x49, // Page Up
        0x4C => 0x53, // Delete
        0x4D => 0x4F, // End
        0x4E => 0x51, // Page Down
        0x4F => 0x4D, // Right Arrow
        0x50 => 0x4B, // Left Arrow
        0x51 => 0x50, // Down Arrow
        0x52 => 0x48, // Up Arrow
        // Numpad
        0x53 => 0x45, // Num Lock
        0x54 => 0x35, // KP Divide (E0 35)
        0x55 => 0x37, // KP Multiply
        0x56 => 0x4A, // KP Minus
        0x57 => 0x4E, // KP Plus
        0x58 => 0x1C, // KP Enter (E0 1C)
        0x59..=0x62 => {
            const MAP: [u8; 10] = [0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49, 0x52];
            MAP[(hid_usage - 0x59) as usize]
        }
        0x63 => 0x53, // KP Decimal
        // Modifiers
        0xE0 => 0x1D, // Left Ctrl
        0xE1 => 0x2A, // Left Shift
        0xE2 => 0x38, // Left Alt
        0xE3 => 0x5B, // Left GUI
        0xE4 => 0x1D, // Right Ctrl (E0 1D)
        0xE5 => 0x36, // Right Shift
        0xE6 => 0x38, // Right Alt (E0 38)
        0xE7 => 0x5C, // Right GUI
        // Unknown
        _ => 0,
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initializes the USB HID driver
///
/// This initializes the xHCI controller and USB stack, then enumerates
/// all connected HID devices.
pub fn init() -> UsbHidResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(UsbHidError::AlreadyInitialized);
    }

    // Initialize xHCI controller
    if crate::drivers::nonos_xhci::init_xhci().is_err() {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(UsbHidError::XhciInitFailed);
    }

    // Initialize USB stack
    if crate::drivers::nonos_usb::init_usb().is_err() {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(UsbHidError::UsbInitFailed);
    }

    // Enumerate HID devices
    enumerate_devices()?;

    Ok(())
}

/// Re-enumerates USB HID devices (for hot-plug support)
pub fn enumerate_devices() -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    let usb_mgr = match crate::drivers::nonos_usb::get_manager() {
        Some(mgr) => mgr,
        None => return Err(UsbHidError::UsbInitFailed),
    };

    let mut devices = DEVICES.lock();
    let mut device_count = 0u8;

    // Mark all devices as inactive (will be reactivated if still present)
    for dev in devices.iter_mut() {
        dev.active = false;
    }

    // Scan for HID devices
    for usb_dev in usb_mgr.devices() {
        if let Some(cfg) = &usb_dev.active_config {
            for iface in &cfg.interfaces {
                let class = iface.iface.b_interface_class;
                let subclass = iface.iface.b_interface_sub_class;
                let protocol = iface.iface.b_interface_protocol;

                // Check for HID class
                if class != HID_CLASS {
                    continue;
                }

                // Find interrupt IN endpoint
                let endpoint = iface.endpoints.iter()
                    .find(|ep| (ep.b_endpoint_address & 0x80) != 0)
                    .map(|ep| ep.b_endpoint_address);

                let endpoint = match endpoint {
                    Some(ep) => ep,
                    None => continue,
                };

                // Determine device type
                let device_type = if subclass == HID_SUBCLASS_BOOT {
                    match protocol {
                        HID_PROTOCOL_KEYBOARD => HidDeviceType::BootKeyboard,
                        HID_PROTOCOL_MOUSE => HidDeviceType::BootMouse,
                        _ => HidDeviceType::Unknown,
                    }
                } else {
                    // Non-boot protocol - need to parse HID descriptor
                    match protocol {
                        HID_PROTOCOL_KEYBOARD => HidDeviceType::ReportKeyboard,
                        HID_PROTOCOL_MOUSE => HidDeviceType::ScrollMouse,
                        _ => HidDeviceType::Unknown,
                    }
                };

                // Find or allocate slot
                let slot = devices.iter_mut()
                    .enumerate()
                    .find(|(_, d)| !d.active)
                    .map(|(i, _)| i);

                if let Some(idx) = slot {
                    devices[idx] = HidDeviceState {
                        slot_id: usb_dev.slot_id,
                        endpoint,
                        device_type,
                        interface: iface.iface.b_interface_number,
                        active: true,
                        last_keyboard_report: [0; KEYBOARD_REPORT_SIZE],
                        modifiers: ModifierState::from_byte(0),
                        leds: LedState::new(),
                        last_mouse_buttons: MouseButtonState::from_byte(0),
                        report_count: 0,
                        error_count: 0,
                    };
                    device_count += 1;

                    // Set boot protocol for boot devices
                    if subclass == HID_SUBCLASS_BOOT {
                        let _ = set_protocol(usb_dev.slot_id, iface.iface.b_interface_number, 0);
                    }

                    STATS.write().devices_connected += 1;
                }
            }
        }
    }

    DEVICE_COUNT.store(device_count, Ordering::Release);

    if device_count == 0 {
        return Err(UsbHidError::NoDevices);
    }

    Ok(())
}

/// Sets HID protocol (0 = boot, 1 = report)
fn set_protocol(slot_id: u8, interface: u8, protocol: u8) -> UsbHidResult<()> {
    // Send SET_PROTOCOL request
    // bmRequestType: 0x21 (host to device, class, interface)
    // bRequest: 0x0B (SET_PROTOCOL)
    // wValue: protocol (0 = boot, 1 = report)
    // wIndex: interface number
    // wLength: 0

    let result = crate::drivers::nonos_usb::control_transfer(
        slot_id,
        0x21, // bmRequestType
        0x0B, // SET_PROTOCOL
        protocol as u16,
        interface as u16,
        &mut [],
    );

    match result {
        Ok(_) => Ok(()),
        Err(_) => Err(UsbHidError::SetProtocolFailed),
    }
}

// ============================================================================
// Public Interface
// ============================================================================

/// Returns true if the USB HID driver is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Returns the number of active HID devices
pub fn device_count() -> u8 {
    DEVICE_COUNT.load(Ordering::Acquire)
}

/// Returns statistics
pub fn get_stats() -> UsbHidStats {
    *STATS.read()
}

/// Resets statistics
pub fn reset_stats() {
    *STATS.write() = UsbHidStats::new();
}

/// Gets device info by index
pub fn get_device_info(index: usize) -> Option<HidDeviceInfo> {
    if index >= MAX_HID_DEVICES {
        return None;
    }

    let devices = DEVICES.lock();
    let dev = &devices[index];

    if !dev.active {
        return None;
    }

    Some(HidDeviceInfo {
        slot_id: dev.slot_id,
        device_type: dev.device_type,
        report_count: dev.report_count,
        error_count: dev.error_count,
    })
}

/// Device info returned to callers
#[derive(Debug, Clone, Copy)]
pub struct HidDeviceInfo {
    /// USB slot ID
    pub slot_id: u8,
    /// Device type
    pub device_type: HidDeviceType,
    /// Number of reports processed
    pub report_count: u32,
    /// Number of errors
    pub error_count: u32,
}

// ============================================================================
// Polling
// ============================================================================

/// This should be called periodically (typically from a timer interrupt
/// or dedicated polling thread) to read HID reports and generate input events.
pub fn poll() -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    STATS.write().poll_cycles += 1;

    let mut devices = DEVICES.lock();

    for idx in 0..MAX_HID_DEVICES {
        let dev = &mut devices[idx];
        if !dev.active {
            continue;
        }

        match dev.device_type {
            HidDeviceType::BootKeyboard | HidDeviceType::ReportKeyboard => {
                poll_keyboard(dev);
            }
            HidDeviceType::BootMouse | HidDeviceType::ScrollMouse | HidDeviceType::ExtendedMouse => {
                poll_mouse(dev);
            }
            _ => {}
        }
    }

    Ok(())
}

/// Polls a keyboard device
fn poll_keyboard(dev: &mut HidDeviceState) {
    let mut report = [0u8; KEYBOARD_REPORT_SIZE];

    let result = crate::drivers::nonos_usb::poll_endpoint(
        dev.slot_id,
        dev.endpoint,
        &mut report,
    );

    if result.is_err() {
        dev.error_count += 1;
        STATS.write().errors += 1;
        return;
    }

    // Check if report changed
    if report == dev.last_keyboard_report {
        return;
    }

    dev.report_count += 1;
    STATS.write().keyboard_reports += 1;

    // Process modifier changes
    let new_mods = ModifierState::from_byte(report[0]);
    process_modifier_changes(&dev.modifiers, &new_mods);
    dev.modifiers = new_mods;

    // Process key changes (bytes 2-7)
    let old_keys = &dev.last_keyboard_report[2..8];
    let new_keys = &report[2..8];

    // Find released keys (in old but not in new)
    for &old_key in old_keys {
        if old_key != 0 && !new_keys.contains(&old_key) {
            let scancode = hid_to_scancode(old_key);
            if scancode != 0 {
                let _ = push_event(InputEvent::key_release(scancode));
                STATS.write().key_releases += 1;
            }
        }
    }

    // Find pressed keys (in new but not in old)
    for &new_key in new_keys {
        if new_key != 0 && !old_keys.contains(&new_key) {
            // Check for error codes
            if new_key == usage::ERR_ROLLOVER {
                // Phantom key - too many keys pressed
                continue;
            }

            let scancode = hid_to_scancode(new_key);
            if scancode != 0 {
                let _ = push_event(InputEvent::key_press(scancode));
                STATS.write().key_presses += 1;
            }
        }
    }

    dev.last_keyboard_report = report;
}

/// Processes modifier key changes
fn process_modifier_changes(old: &ModifierState, new: &ModifierState) {
    // Left Ctrl
    if old.left_ctrl != new.left_ctrl {
        let scancode = hid_to_scancode(usage::KEY_LEFT_CTRL);
        if new.left_ctrl {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }

    // Left Shift
    if old.left_shift != new.left_shift {
        let scancode = hid_to_scancode(usage::KEY_LEFT_SHIFT);
        if new.left_shift {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }

    // Left Alt
    if old.left_alt != new.left_alt {
        let scancode = hid_to_scancode(usage::KEY_LEFT_ALT);
        if new.left_alt {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }

    // Left GUI
    if old.left_gui != new.left_gui {
        let scancode = hid_to_scancode(usage::KEY_LEFT_GUI);
        if new.left_gui {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }

    // Right Ctrl
    if old.right_ctrl != new.right_ctrl {
        let scancode = hid_to_scancode(usage::KEY_RIGHT_CTRL);
        if new.right_ctrl {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }

    // Right Shift
    if old.right_shift != new.right_shift {
        let scancode = hid_to_scancode(usage::KEY_RIGHT_SHIFT);
        if new.right_shift {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }

    // Right Alt
    if old.right_alt != new.right_alt {
        let scancode = hid_to_scancode(usage::KEY_RIGHT_ALT);
        if new.right_alt {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }

    // Right GUI
    if old.right_gui != new.right_gui {
        let scancode = hid_to_scancode(usage::KEY_RIGHT_GUI);
        if new.right_gui {
            let _ = push_event(InputEvent::key_press(scancode));
            STATS.write().key_presses += 1;
        } else {
            let _ = push_event(InputEvent::key_release(scancode));
            STATS.write().key_releases += 1;
        }
    }
}

/// Polls a mouse device
fn poll_mouse(dev: &mut HidDeviceState) {
    let mut report = [0u8; 8];

    let result = crate::drivers::nonos_usb::poll_endpoint(
        dev.slot_id,
        dev.endpoint,
        &mut report,
    );

    if result.is_err() {
        dev.error_count += 1;
        STATS.write().errors += 1;
        return;
    }

    dev.report_count += 1;
    STATS.write().mouse_reports += 1;

    // Parse mouse report
    let buttons = MouseButtonState::from_byte(report[0]);
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;
    let dz = if dev.device_type.has_scroll() && report.len() > 3 {
        report[3] as i8
    } else {
        0
    };

    // Generate movement event
    if dx != 0 || dy != 0 {
        let _ = push_event(InputEvent::mouse_move(dx, dy));
        STATS.write().mouse_moves += 1;
    }

    // Generate scroll event
    if dz != 0 {
        let _ = push_event(InputEvent::mouse_scroll(dz as i16));
    }

    // Generate button events for state changes
    let old_buttons = dev.last_mouse_buttons;

    if old_buttons.left != buttons.left {
        let _ = push_event(InputEvent::mouse_button(0, buttons.left));
        STATS.write().mouse_buttons += 1;
    }
    if old_buttons.right != buttons.right {
        let _ = push_event(InputEvent::mouse_button(1, buttons.right));
        STATS.write().mouse_buttons += 1;
    }
    if old_buttons.middle != buttons.middle {
        let _ = push_event(InputEvent::mouse_button(2, buttons.middle));
        STATS.write().mouse_buttons += 1;
    }
    if old_buttons.button4 != buttons.button4 {
        let _ = push_event(InputEvent::mouse_button(3, buttons.button4));
        STATS.write().mouse_buttons += 1;
    }
    if old_buttons.button5 != buttons.button5 {
        let _ = push_event(InputEvent::mouse_button(4, buttons.button5));
        STATS.write().mouse_buttons += 1;
    }

    dev.last_mouse_buttons = buttons;
}

// ============================================================================
// LED Control
// ============================================================================

/// Sets keyboard LED state for all connected USB keyboards
pub fn set_leds(leds: LedState) -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    let mut devices = DEVICES.lock();
    let mut found_keyboard = false;

    for dev in devices.iter_mut() {
        if !dev.active || !dev.device_type.is_keyboard() {
            continue;
        }

        found_keyboard = true;

        // Send SET_REPORT request
        // bmRequestType: 0x21 (host to device, class, interface)
        // bRequest: 0x09 (SET_REPORT)
        // wValue: 0x0200 (output report, report ID 0)
        // wIndex: interface number
        // wLength: 1

        let mut report = [leds.to_byte()];
        let result = crate::drivers::nonos_usb::control_transfer(
            dev.slot_id,
            0x21,
            0x09,
            0x0200,
            dev.interface as u16,
            &mut report,
        );

        if result.is_ok() {
            dev.leds = leds;
        }
    }

    if !found_keyboard {
        return Err(UsbHidError::DeviceNotFound);
    }

    Ok(())
}

/// Gets LED state from the first keyboard
pub fn get_leds() -> LedState {
    let devices = DEVICES.lock();
    for dev in devices.iter() {
        if dev.active && dev.device_type.is_keyboard() {
            return dev.leds;
        }
    }
    LedState::new()
}

// ============================================================================
// Report Parsing (Public API)
// ============================================================================

/// Parses a keyboard boot protocol report
///
/// Returns the first non-zero keycode, or None if no keys pressed.
pub fn parse_keyboard_report(report: &[u8; 8]) -> Option<u8> {
    for &keycode in &report[2..8] {
        if keycode != 0 && keycode != usage::ERR_ROLLOVER {
            return Some(keycode);
        }
    }
    None
}

/// Parses all keycodes from a keyboard boot protocol report
pub fn parse_keyboard_report_all(report: &[u8; 8]) -> [u8; MAX_KEYS_PRESSED] {
    let mut keys = [0u8; MAX_KEYS_PRESSED];
    let mut idx = 0;

    for &keycode in &report[2..8] {
        if keycode != 0 && keycode != usage::ERR_ROLLOVER && idx < MAX_KEYS_PRESSED {
            keys[idx] = keycode;
            idx += 1;
        }
    }

    keys
}

/// Parses modifiers from a keyboard boot protocol report
pub fn parse_keyboard_modifiers(report: &[u8; 8]) -> ModifierState {
    ModifierState::from_byte(report[0])
}

/// Parses a mouse boot protocol report
///
/// Returns (dx, dy, buttons) or None if report too short.
pub fn parse_mouse_report(report: &[u8]) -> Option<(i16, i16, [bool; 3])> {
    if report.len() < MOUSE_REPORT_MIN_SIZE {
        return None;
    }

    let buttons = [
        (report[0] & 0x01) != 0,
        (report[0] & 0x02) != 0,
        (report[0] & 0x04) != 0,
    ];
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;

    Some((dx, dy, buttons))
}

/// Parses a mouse report with scroll wheel
pub fn parse_mouse_report_scroll(report: &[u8]) -> Option<(i16, i16, i8, [bool; 5])> {
    if report.len() < MOUSE_REPORT_SCROLL_SIZE {
        return None;
    }

    let buttons = [
        (report[0] & 0x01) != 0,
        (report[0] & 0x02) != 0,
        (report[0] & 0x04) != 0,
        (report[0] & 0x08) != 0,
        (report[0] & 0x10) != 0,
    ];
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;
    let dz = report[3] as i8;

    Some((dx, dy, dz, buttons))
}

// ============================================================================
// InputDevice Implementation
// ============================================================================

/// USB HID Keyboard as an InputDevice
pub struct UsbHidKeyboard {
    device_index: usize,
}

impl UsbHidKeyboard {
    /// Base device ID for USB HID keyboards
    pub const BASE_DEVICE_ID: u32 = 100;

    /// Creates a new USB HID keyboard device
    pub const fn new(device_index: usize) -> Self {
        Self { device_index }
    }

    /// Gets the first connected USB keyboard
    pub fn first() -> Option<Self> {
        let devices = DEVICES.lock();
        for (idx, dev) in devices.iter().enumerate() {
            if dev.active && dev.device_type.is_keyboard() {
                return Some(Self::new(idx));
            }
        }
        None
    }
}

impl InputDevice for UsbHidKeyboard {
    fn device_id(&self) -> DeviceId {
        DeviceId(Self::BASE_DEVICE_ID + self.device_index as u32)
    }

    fn name(&self) -> &'static str {
        "USB HID Keyboard"
    }

    fn device_type(&self) -> &'static str {
        let devices = DEVICES.lock();
        if self.device_index < MAX_HID_DEVICES && devices[self.device_index].active {
            devices[self.device_index].device_type.name()
        } else {
            "Disconnected"
        }
    }

    fn is_connected(&self) -> bool {
        if !is_initialized() || self.device_index >= MAX_HID_DEVICES {
            return false;
        }
        let devices = DEVICES.lock();
        devices[self.device_index].active && devices[self.device_index].device_type.is_keyboard()
    }

    fn poll(&self) -> Option<InputEvent> {
        // Polling is done globally, individual device polling not supported
        None
    }
}

/// USB HID Mouse as an InputDevice
pub struct UsbHidMouse {
    device_index: usize,
}

impl UsbHidMouse {
    /// Base device ID for USB HID mice
    pub const BASE_DEVICE_ID: u32 = 200;

    /// Creates a new USB HID mouse device
    pub const fn new(device_index: usize) -> Self {
        Self { device_index }
    }

    /// Gets the first connected USB mouse
    pub fn first() -> Option<Self> {
        let devices = DEVICES.lock();
        for (idx, dev) in devices.iter().enumerate() {
            if dev.active && dev.device_type.is_mouse() {
                return Some(Self::new(idx));
            }
        }
        None
    }
}

impl InputDevice for UsbHidMouse {
    fn device_id(&self) -> DeviceId {
        DeviceId(Self::BASE_DEVICE_ID + self.device_index as u32)
    }

    fn name(&self) -> &'static str {
        "USB HID Mouse"
    }

    fn device_type(&self) -> &'static str {
        let devices = DEVICES.lock();
        if self.device_index < MAX_HID_DEVICES && devices[self.device_index].active {
            devices[self.device_index].device_type.name()
        } else {
            "Disconnected"
        }
    }

    fn is_connected(&self) -> bool {
        if !is_initialized() || self.device_index >= MAX_HID_DEVICES {
            return false;
        }
        let devices = DEVICES.lock();
        devices[self.device_index].active && devices[self.device_index].device_type.is_mouse()
    }

    fn poll(&self) -> Option<InputEvent> {
        // Polling is done globally, individual device polling not supported
        None
    }
}

// ============================================================================
// Shutdown
// ============================================================================

/// Shuts down the USB HID driver
pub fn shutdown() -> UsbHidResult<()> {
    if !is_initialized() {
        return Err(UsbHidError::NotInitialized);
    }

    // Clear device registry
    let mut devices = DEVICES.lock();
    for dev in devices.iter_mut() {
        if dev.active {
            STATS.write().devices_disconnected += 1;
        }
        *dev = HidDeviceState::new();
    }

    DEVICE_COUNT.store(0, Ordering::Release);
    INITIALIZED.store(false, Ordering::SeqCst);

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(UsbHidError::NotInitialized.as_str(), "USB HID driver not initialized");
        assert_eq!(UsbHidError::XhciInitFailed.as_str(), "xHCI controller initialization failed");
        assert_eq!(UsbHidError::NoDevices.as_str(), "no USB HID devices found");
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(UsbHidError::NotInitialized.code(), 1);
        assert_eq!(UsbHidError::Timeout.code(), 16);
    }

    #[test]
    fn test_device_type() {
        assert!(HidDeviceType::BootKeyboard.is_keyboard());
        assert!(HidDeviceType::ReportKeyboard.is_keyboard());
        assert!(!HidDeviceType::BootMouse.is_keyboard());

        assert!(HidDeviceType::BootMouse.is_mouse());
        assert!(HidDeviceType::ScrollMouse.is_mouse());
        assert!(!HidDeviceType::BootKeyboard.is_mouse());

        assert!(!HidDeviceType::BootMouse.has_scroll());
        assert!(HidDeviceType::ScrollMouse.has_scroll());
    }

    #[test]
    fn test_modifier_state() {
        let mods = ModifierState::from_byte(0b00100011);
        assert!(mods.left_ctrl);
        assert!(mods.left_shift);
        assert!(!mods.left_alt);
        assert!(!mods.left_gui);
        assert!(!mods.right_ctrl);
        assert!(mods.right_shift);
        assert!(!mods.right_alt);
        assert!(!mods.right_gui);

        assert!(mods.shift());
        assert!(mods.ctrl());
        assert!(!mods.alt());
        assert!(!mods.gui());

        assert_eq!(mods.to_byte(), 0b00100011);
    }

    #[test]
    fn test_led_state() {
        let leds = LedState {
            num_lock: true,
            caps_lock: false,
            scroll_lock: true,
            compose: false,
            kana: false,
        };
        assert_eq!(leds.to_byte(), 0b00000101);

        let leds2 = LedState::from_byte(0b00000101);
        assert!(leds2.num_lock);
        assert!(!leds2.caps_lock);
        assert!(leds2.scroll_lock);
    }

    #[test]
    fn test_mouse_buttons() {
        let buttons = MouseButtonState::from_byte(0b00010101);
        assert!(buttons.left);
        assert!(!buttons.right);
        assert!(buttons.middle);
        assert!(!buttons.button4);
        assert!(buttons.button5);

        assert_eq!(buttons.to_byte(), 0b00010101);

        assert!(buttons.get(0));
        assert!(!buttons.get(1));
        assert!(buttons.get(2));
        assert!(!buttons.get(3));
        assert!(buttons.get(4));
    }

    #[test]
    fn test_parse_keyboard_report_key() {
        let report = [0, 0, 0x04, 0, 0, 0, 0, 0];
        assert_eq!(parse_keyboard_report(&report), Some(0x04));
    }

    #[test]
    fn test_parse_keyboard_report_empty() {
        let report = [0; 8];
        assert_eq!(parse_keyboard_report(&report), None);
    }

    #[test]
    fn test_parse_keyboard_report_multiple() {
        let report = [0, 0, 0x04, 0x05, 0x06, 0, 0, 0];
        assert_eq!(parse_keyboard_report(&report), Some(0x04));

        let all = parse_keyboard_report_all(&report);
        assert_eq!(all[0], 0x04);
        assert_eq!(all[1], 0x05);
        assert_eq!(all[2], 0x06);
        assert_eq!(all[3], 0);
    }

    #[test]
    fn test_parse_keyboard_report_rollover() {
        let report = [0, 0, usage::ERR_ROLLOVER, 0, 0, 0, 0, 0];
        assert_eq!(parse_keyboard_report(&report), None);
    }

    #[test]
    fn test_parse_keyboard_modifiers() {
        let report = [0b11001010, 0, 0, 0, 0, 0, 0, 0];
        let mods = parse_keyboard_modifiers(&report);
        assert!(!mods.left_ctrl);
        assert!(mods.left_shift);
        assert!(!mods.left_alt);
        assert!(mods.left_gui);
        assert!(!mods.right_ctrl);
        assert!(!mods.right_shift);
        assert!(mods.right_alt);
        assert!(mods.right_gui);
    }

    #[test]
    fn test_parse_mouse_report() {
        let report = [0b101, 10, 246];
        let (dx, dy, buttons) = parse_mouse_report(&report).unwrap();
        assert_eq!(dx, 10);
        assert_eq!(dy, -10);
        assert_eq!(buttons, [true, false, true]);
    }

    #[test]
    fn test_parse_mouse_report_short() {
        let report = [0, 0];
        assert!(parse_mouse_report(&report).is_none());
    }

    #[test]
    fn test_parse_mouse_report_scroll() {
        let report = [0b00111, 5, 250, 253];
        let (dx, dy, dz, buttons) = parse_mouse_report_scroll(&report).unwrap();
        assert_eq!(dx, 5);
        assert_eq!(dy, -6);
        assert_eq!(dz, -3);
        assert_eq!(buttons, [true, true, true, false, false]);
    }

    #[test]
    fn test_hid_to_scancode() {
        // Letters
        assert_eq!(hid_to_scancode(usage::KEY_A), 0x1E);
        assert_eq!(hid_to_scancode(usage::KEY_Z), 0x2C);

        // Numbers
        assert_eq!(hid_to_scancode(usage::KEY_1), 0x02);
        assert_eq!(hid_to_scancode(usage::KEY_0), 0x0B);

        // Special
        assert_eq!(hid_to_scancode(usage::KEY_ENTER), 0x1C);
        assert_eq!(hid_to_scancode(usage::KEY_ESCAPE), 0x01);
        assert_eq!(hid_to_scancode(usage::KEY_SPACE), 0x39);

        // Function keys
        assert_eq!(hid_to_scancode(usage::KEY_F1), 0x3B);
        assert_eq!(hid_to_scancode(usage::KEY_F12), 0x46);

        // Modifiers
        assert_eq!(hid_to_scancode(usage::KEY_LEFT_SHIFT), 0x2A);
        assert_eq!(hid_to_scancode(usage::KEY_RIGHT_SHIFT), 0x36);
    }

    #[test]
    fn test_stats() {
        let stats = UsbHidStats::new();
        assert_eq!(stats.keyboard_reports, 0);
        assert_eq!(stats.mouse_reports, 0);
        assert_eq!(stats.poll_cycles, 0);
    }

    #[test]
    fn test_usb_hid_keyboard_device() {
        let kbd = UsbHidKeyboard::new(0);
        assert_eq!(kbd.device_id(), DeviceId(100));
        assert_eq!(kbd.name(), "USB HID Keyboard");
    }

    #[test]
    fn test_usb_hid_mouse_device() {
        let mouse = UsbHidMouse::new(0);
        assert_eq!(mouse.device_id(), DeviceId(200));
        assert_eq!(mouse.name(), "USB HID Mouse");
    }
}
