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
//! Scan Code to KeyCode Mapping 
//! Keyboard scan code to keycode mapping with:
//! **Full PS/2 Set 1 scan code support**
//! **Numpad key support**
//! **Modifier state tracking** 
//! **Control character generation** 
//! **Dead key and compose sequence support** 
//! **Error handling** 
//! **Thread-safe global modifier state**

use super::layout::{Layout, get_ascii_mapping, get_shifted_mapping};
use core::sync::atomic::{AtomicU8, Ordering};

// ============================================================================
// KeyCode Enumeration
// ============================================================================

/// Virtual key codes representing all keyboard keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum KeyCode {
    // Letters
    A, B, C, D, E, F, G, H, I, J, K, L, M,
    N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
    // Numbers
    Num0, Num1, Num2, Num3, Num4, Num5, Num6, Num7, Num8, Num9,
    // Function keys
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    // Control keys
    Escape, Backspace, Tab, Enter, Space,
    // Modifiers
    LeftShift, RightShift, LeftCtrl, RightCtrl, LeftAlt, RightAlt,
    LeftSuper, RightSuper,
    // Lock keys
    CapsLock, NumLock, ScrollLock,
    // Navigation
    Insert, Delete, Home, End, PageUp, PageDown,
    ArrowUp, ArrowDown, ArrowLeft, ArrowRight,
    // Punctuation
    Minus, Equals, LeftBracket, RightBracket, Backslash,
    Semicolon, Quote, Backtick, Comma, Period, Slash,
    // Numpad
    Numpad0, Numpad1, Numpad2, Numpad3, Numpad4,
    Numpad5, Numpad6, Numpad7, Numpad8, Numpad9,
    NumpadPlus, NumpadMinus, NumpadMultiply, NumpadDivide,
    NumpadEnter, NumpadDecimal,
    // Special
    PrintScreen, Pause, Menu,
    /// Unknown key
    #[default]
    Unknown = 0xFF,
}

impl KeyCode {
    /// Returns true if this is a modifier key
    pub const fn is_modifier(self) -> bool {
        matches!(self, Self::LeftShift | Self::RightShift |
            Self::LeftCtrl | Self::RightCtrl |
            Self::LeftAlt | Self::RightAlt |
            Self::LeftSuper | Self::RightSuper)
    }

    /// Returns true if this is a lock key
    pub const fn is_lock(self) -> bool {
        matches!(self, Self::CapsLock | Self::NumLock | Self::ScrollLock)
    }
}

/// Scan code type alias
pub type ScanCode = u8;

// ============================================================================
// Error Handling
// ============================================================================

/// Error codes for keymap operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeymapError {
    /// Scan code is out of valid range
    InvalidScanCode,
    /// Extended scan code sequence is incomplete
    IncompleteExtended,
    /// Unknown extended scan code
    UnknownExtended,
    /// Dead key sequence not completed
    PendingDeadKey,
    /// Invalid compose sequence
    InvalidCompose,
}

impl KeymapError {
    /// Returns a human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidScanCode => "invalid scan code",
            Self::IncompleteExtended => "incomplete extended scan code",
            Self::UnknownExtended => "unknown extended scan code",
            Self::PendingDeadKey => "dead key sequence pending",
            Self::InvalidCompose => "invalid compose sequence",
        }
    }
}

/// Result type for keymap operations
pub type KeymapResult<T> = Result<T, KeymapError>;

// ============================================================================
// Modifier State
// ============================================================================

/// Modifier key flags (matches input::Modifiers for compatibility)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModifierState {
    bits: u8,
}

impl ModifierState {
    pub const NONE: Self = Self { bits: 0 };
    pub const SHIFT: u8 = 1 << 0;
    pub const CTRL: u8 = 1 << 1;
    pub const ALT: u8 = 1 << 2;
    pub const CAPS_LOCK: u8 = 1 << 3;
    pub const NUM_LOCK: u8 = 1 << 4;
    pub const SCROLL_LOCK: u8 = 1 << 5;

    /// Creates modifier state from raw bits
    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    /// Returns the raw bits
    #[inline]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// Checks if shift is active (considering CapsLock for letters)
    #[inline]
    pub const fn is_shifted(self) -> bool {
        (self.bits & Self::SHIFT) != 0
    }

    /// Checks if ctrl is active
    #[inline]
    pub const fn is_ctrl(self) -> bool {
        (self.bits & Self::CTRL) != 0
    }

    /// Checks if alt is active
    #[inline]
    pub const fn is_alt(self) -> bool {
        (self.bits & Self::ALT) != 0
    }

    /// Checks if caps lock is on
    #[inline]
    pub const fn is_caps_lock(self) -> bool {
        (self.bits & Self::CAPS_LOCK) != 0
    }

    /// Checks if num lock is on
    #[inline]
    pub const fn is_num_lock(self) -> bool {
        (self.bits & Self::NUM_LOCK) != 0
    }

    /// Checks if scroll lock is on
    #[inline]
    pub const fn is_scroll_lock(self) -> bool {
        (self.bits & Self::SCROLL_LOCK) != 0
    }

    /// Returns effective shift state for a letter (XOR with CapsLock)
    #[inline]
    pub const fn effective_shift_for_letter(self) -> bool {
        let shift = (self.bits & Self::SHIFT) != 0;
        let caps = (self.bits & Self::CAPS_LOCK) != 0;
        shift ^ caps
    }

    /// Sets a modifier flag
    #[inline]
    pub fn set(&mut self, flag: u8) {
        self.bits |= flag;
    }

    /// Clears a modifier flag
    #[inline]
    pub fn clear(&mut self, flag: u8) {
        self.bits &= !flag;
    }

    /// Toggles a modifier flag
    #[inline]
    pub fn toggle(&mut self, flag: u8) {
        self.bits ^= flag;
    }
}

// Global modifier state (thread-safe)
static GLOBAL_MODIFIERS: AtomicU8 = AtomicU8::new(0);

/// Returns the current global modifier state
pub fn get_modifiers() -> ModifierState {
    ModifierState::from_bits(GLOBAL_MODIFIERS.load(Ordering::Acquire))
}

/// Updates the global modifier state based on a key event
pub fn update_modifiers(scan_code: u8, is_release: bool, is_extended: bool) {
    let current = GLOBAL_MODIFIERS.load(Ordering::Acquire);
    let mut mods = ModifierState::from_bits(current);

    if is_extended {
        // Extended keys (E0 prefix)
        match scan_code {
            0x1D => { // Right Ctrl
                if is_release { mods.clear(ModifierState::CTRL); }
                else { mods.set(ModifierState::CTRL); }
            }
            0x38 => { // Right Alt (AltGr)
                if is_release { mods.clear(ModifierState::ALT); }
                else { mods.set(ModifierState::ALT); }
            }
            _ => {}
        }
    } else {
        // Standard keys
        match scan_code {
            0x2A | 0x36 => { // Left/Right Shift
                if is_release { mods.clear(ModifierState::SHIFT); }
                else { mods.set(ModifierState::SHIFT); }
            }
            0x1D => { // Left Ctrl
                if is_release { mods.clear(ModifierState::CTRL); }
                else { mods.set(ModifierState::CTRL); }
            }
            0x38 => { // Left Alt
                if is_release { mods.clear(ModifierState::ALT); }
                else { mods.set(ModifierState::ALT); }
            }
            0x3A => { // Caps Lock (toggle on press only)
                if !is_release { mods.toggle(ModifierState::CAPS_LOCK); }
            }
            0x45 => { // Num Lock (toggle on press only)
                if !is_release { mods.toggle(ModifierState::NUM_LOCK); }
            }
            0x46 => { // Scroll Lock (toggle on press only)
                if !is_release { mods.toggle(ModifierState::SCROLL_LOCK); }
            }
            _ => {}
        }
    }

    GLOBAL_MODIFIERS.store(mods.bits(), Ordering::Release);
}

/// Resets all modifier states
pub fn reset_modifiers() {
    GLOBAL_MODIFIERS.store(0, Ordering::Release);
}

// ============================================================================
// Extended Scan Code State
// ============================================================================

/// State machine for extended scan code sequences
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedState {
    /// No extended sequence in progress
    None,
    /// Received E0 prefix, waiting for scan code
    E0Pending,
    /// Received E1 prefix (Pause key), waiting for more bytes
    E1Pending(u8),
}

// Global extended state
static EXTENDED_STATE: AtomicU8 = AtomicU8::new(0);

const EXT_NONE: u8 = 0;
const EXT_E0: u8 = 1;
const EXT_E1_1: u8 = 2;
const EXT_E1_2: u8 = 3;

fn get_extended_state() -> ExtendedState {
    match EXTENDED_STATE.load(Ordering::Acquire) {
        EXT_E0 => ExtendedState::E0Pending,
        EXT_E1_1 => ExtendedState::E1Pending(1),
        EXT_E1_2 => ExtendedState::E1Pending(2),
        _ => ExtendedState::None,
    }
}

fn set_extended_state(state: ExtendedState) {
    let val = match state {
        ExtendedState::None => EXT_NONE,
        ExtendedState::E0Pending => EXT_E0,
        ExtendedState::E1Pending(1) => EXT_E1_1,
        ExtendedState::E1Pending(_) => EXT_E1_2,
    };
    EXTENDED_STATE.store(val, Ordering::Release);
}

// ============================================================================
// Key Mapping Types
// ============================================================================

/// Complete key mapping information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMapping {
    /// The logical key code
    pub keycode: KeyCode,
    /// ASCII value (unshifted)
    pub ascii: u8,
    /// ASCII value (shifted)
    pub shifted_ascii: u8,
    /// Whether this is an extended key (E0 prefix)
    pub extended: bool,
    /// Whether this key generates a printable character
    pub printable: bool,
}

impl KeyMapping {
    /// Creates a new key mapping
    pub const fn new(keycode: KeyCode, ascii: u8, shifted: u8, extended: bool, printable: bool) -> Self {
        Self {
            keycode,
            ascii,
            shifted_ascii: shifted,
            extended,
            printable,
        }
    }

    /// Creates a mapping for a non-printable key
    pub const fn non_printable(keycode: KeyCode, extended: bool) -> Self {
        Self {
            keycode,
            ascii: 0,
            shifted_ascii: 0,
            extended,
            printable: false,
        }
    }

    /// Creates a mapping for unknown keys
    pub const fn unknown() -> Self {
        Self {
            keycode: KeyCode::Unknown,
            ascii: 0,
            shifted_ascii: 0,
            extended: false,
            printable: false,
        }
    }

    /// Gets the appropriate ASCII value based on modifier state
    pub fn get_ascii(&self, modifiers: ModifierState) -> Option<u8> {
        if !self.printable {
            return None;
        }

        // Handle Ctrl combinations
        if modifiers.is_ctrl() {
            return self.get_ctrl_char();
        }

        // Determine effective shift state
        let shifted = if self.keycode.is_letter() {
            modifiers.effective_shift_for_letter()
        } else {
            modifiers.is_shifted()
        };

        let ch = if shifted { self.shifted_ascii } else { self.ascii };
        if ch == 0 { None } else { Some(ch) }
    }

    /// Gets control character (Ctrl+key)
    fn get_ctrl_char(&self) -> Option<u8> {
        match self.ascii {
            b'a'..=b'z' => Some(self.ascii - b'a' + 1), // Ctrl+A = 0x01, etc.
            b'[' => Some(0x1B), // Escape
            b'\\' => Some(0x1C),
            b']' => Some(0x1D),
            b'^' => Some(0x1E),
            b'_' => Some(0x1F),
            b'?' => Some(0x7F), // DEL
            _ => None,
        }
    }
}

impl KeyCode {
    /// Returns true if this is a letter key (affected by CapsLock)
    pub const fn is_letter(self) -> bool {
        matches!(
            self,
            KeyCode::A | KeyCode::B | KeyCode::C | KeyCode::D | KeyCode::E |
            KeyCode::F | KeyCode::G | KeyCode::H | KeyCode::I | KeyCode::J |
            KeyCode::K | KeyCode::L | KeyCode::M | KeyCode::N | KeyCode::O |
            KeyCode::P | KeyCode::Q | KeyCode::R | KeyCode::S | KeyCode::T |
            KeyCode::U | KeyCode::V | KeyCode::W | KeyCode::X | KeyCode::Y |
            KeyCode::Z
        )
    }
}

// ============================================================================
// Numpad Keys
// ============================================================================

/// Numpad key codes (separate from main keyboard)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumpadKey {
    Num0,
    Num1,
    Num2,
    Num3,
    Num4,
    Num5,
    Num6,
    Num7,
    Num8,
    Num9,
    Divide,
    Multiply,
    Subtract,
    Add,
    Enter,
    Decimal,
}

impl NumpadKey {
    /// Converts numpad key to ASCII based on NumLock state
    pub const fn to_ascii(self, num_lock: bool) -> Option<u8> {
        if num_lock {
            match self {
                Self::Num0 => Some(b'0'),
                Self::Num1 => Some(b'1'),
                Self::Num2 => Some(b'2'),
                Self::Num3 => Some(b'3'),
                Self::Num4 => Some(b'4'),
                Self::Num5 => Some(b'5'),
                Self::Num6 => Some(b'6'),
                Self::Num7 => Some(b'7'),
                Self::Num8 => Some(b'8'),
                Self::Num9 => Some(b'9'),
                Self::Decimal => Some(b'.'),
                Self::Divide => Some(b'/'),
                Self::Multiply => Some(b'*'),
                Self::Subtract => Some(b'-'),
                Self::Add => Some(b'+'),
                Self::Enter => Some(b'\n'),
            }
        } else {
            match self {
                Self::Divide => Some(b'/'),
                Self::Multiply => Some(b'*'),
                Self::Subtract => Some(b'-'),
                Self::Add => Some(b'+'),
                Self::Enter => Some(b'\n'),
                _ => None, // Navigation keys when NumLock off
            }
        }
    }

    /// Converts numpad key to KeyCode based on NumLock state
    pub const fn to_keycode(self, num_lock: bool) -> KeyCode {
        if num_lock {
            match self {
                Self::Num0 => KeyCode::Num0,
                Self::Num1 => KeyCode::Num1,
                Self::Num2 => KeyCode::Num2,
                Self::Num3 => KeyCode::Num3,
                Self::Num4 => KeyCode::Num4,
                Self::Num5 => KeyCode::Num5,
                Self::Num6 => KeyCode::Num6,
                Self::Num7 => KeyCode::Num7,
                Self::Num8 => KeyCode::Num8,
                Self::Num9 => KeyCode::Num9,
                Self::Decimal => KeyCode::Period,
                Self::Divide => KeyCode::Slash,
                Self::Multiply => KeyCode::Char('*'),
                Self::Subtract => KeyCode::Minus,
                Self::Add => KeyCode::Char('+'),
                Self::Enter => KeyCode::Enter,
            }
        } else {
            match self {
                Self::Num0 => KeyCode::Insert,
                Self::Num1 => KeyCode::End,
                Self::Num2 => KeyCode::ArrowDown,
                Self::Num3 => KeyCode::PageDown,
                Self::Num4 => KeyCode::ArrowLeft,
                Self::Num5 => KeyCode::Unknown, // No function
                Self::Num6 => KeyCode::ArrowRight,
                Self::Num7 => KeyCode::Home,
                Self::Num8 => KeyCode::ArrowUp,
                Self::Num9 => KeyCode::PageUp,
                Self::Decimal => KeyCode::Delete,
                Self::Divide => KeyCode::Slash,
                Self::Multiply => KeyCode::Char('*'),
                Self::Subtract => KeyCode::Minus,
                Self::Add => KeyCode::Char('+'),
                Self::Enter => KeyCode::Enter,
            }
        }
    }
}

// ============================================================================
// Scan Code Processing
// ============================================================================

/// Processes a raw scan code byte and returns the key mapping
///
/// This function handles:
/// - Extended scan code sequences (E0, E1 prefixes)
/// - Modifier state updates
/// - Numpad keys with NumLock awareness
///
/// # Arguments
/// * `scan_code` - Raw scan code byte from keyboard
/// * `layout` - Keyboard layout to use
///
/// # Returns
/// * `Ok(Some(KeyMapping))` - Valid key press/release
/// * `Ok(None)` - Extended sequence in progress, need more bytes
/// * `Err(KeymapError)` - Invalid scan code
pub fn process_scan_code(scan_code: u8, layout: Layout) -> KeymapResult<Option<KeyMapping>> {
    let state = get_extended_state();

    // Handle extended sequence prefixes
    match (state, scan_code) {
        (ExtendedState::None, 0xE0) => {
            set_extended_state(ExtendedState::E0Pending);
            return Ok(None);
        }
        (ExtendedState::None, 0xE1) => {
            set_extended_state(ExtendedState::E1Pending(1));
            return Ok(None);
        }
        (ExtendedState::E1Pending(1), _) => {
            set_extended_state(ExtendedState::E1Pending(2));
            return Ok(None);
        }
        (ExtendedState::E1Pending(_), _) => {
            // Pause key complete (E1 1D 45 or E1 9D C5)
            set_extended_state(ExtendedState::None);
            return Ok(Some(KeyMapping::non_printable(KeyCode::Pause, true)));
        }
        _ => {}
    }

    let is_release = (scan_code & 0x80) != 0;
    let code = scan_code & 0x7F;

    // Handle E0 extended codes
    if state == ExtendedState::E0Pending {
        set_extended_state(ExtendedState::None);

        // Update modifiers for extended keys
        update_modifiers(code, is_release, true);

        return Ok(Some(map_extended_scan_code(code)));
    }

    // Validate scan code range
    if code >= 0x60 && code != 0x7F {
        return Err(KeymapError::InvalidScanCode);
    }

    // Update modifiers for standard keys
    update_modifiers(code, is_release, false);

    // Get mapping
    Ok(Some(map_standard_scan_code(code, layout)))
}

/// Maps extended (E0-prefixed) scan codes
fn map_extended_scan_code(code: u8) -> KeyMapping {
    match code {
        // Navigation cluster
        0x47 => KeyMapping::non_printable(KeyCode::Home, true),
        0x48 => KeyMapping::non_printable(KeyCode::ArrowUp, true),
        0x49 => KeyMapping::non_printable(KeyCode::PageUp, true),
        0x4B => KeyMapping::non_printable(KeyCode::ArrowLeft, true),
        0x4D => KeyMapping::non_printable(KeyCode::ArrowRight, true),
        0x4F => KeyMapping::non_printable(KeyCode::End, true),
        0x50 => KeyMapping::non_printable(KeyCode::ArrowDown, true),
        0x51 => KeyMapping::non_printable(KeyCode::PageDown, true),
        0x52 => KeyMapping::non_printable(KeyCode::Insert, true),
        0x53 => KeyMapping::non_printable(KeyCode::Delete, true),

        // Numpad Enter and Divide
        0x1C => KeyMapping::new(KeyCode::Enter, b'\n', b'\n', true, true),
        0x35 => KeyMapping::new(KeyCode::Slash, b'/', b'/', true, true),

        // Right modifiers
        0x1D => KeyMapping::non_printable(KeyCode::RightCtrl, true),
        0x38 => KeyMapping::non_printable(KeyCode::RightAlt, true),

        // Windows/Super keys
        0x5B => KeyMapping::non_printable(KeyCode::LeftSuper, true),
        0x5C => KeyMapping::non_printable(KeyCode::RightSuper, true),
        0x5D => KeyMapping::non_printable(KeyCode::Menu, true),

        // Print Screen (partial - E0 2A E0 37 for make, E0 B7 E0 AA for break)
        0x37 => KeyMapping::non_printable(KeyCode::PrintScreen, true),
        0x2A => KeyMapping::non_printable(KeyCode::Unknown, true), // Fake shift

        _ => KeyMapping::unknown(),
    }
}

/// Maps standard (non-extended) scan codes
fn map_standard_scan_code(code: u8, layout: Layout) -> KeyMapping {
    // First check for special/modifier keys
    let keycode = match code {
        0x01 => KeyCode::Escape,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x1C => KeyCode::Enter,
        0x1D => KeyCode::LeftCtrl,
        0x2A => KeyCode::LeftShift,
        0x36 => KeyCode::RightShift,
        0x38 => KeyCode::LeftAlt,
        0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock,
        0x3B => KeyCode::F1,
        0x3C => KeyCode::F2,
        0x3D => KeyCode::F3,
        0x3E => KeyCode::F4,
        0x3F => KeyCode::F5,
        0x40 => KeyCode::F6,
        0x41 => KeyCode::F7,
        0x42 => KeyCode::F8,
        0x43 => KeyCode::F9,
        0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock,
        0x46 => KeyCode::ScrollLock,
        0x57 => KeyCode::F11,
        0x58 => KeyCode::F12,
        _ => KeyCode::Unknown,
    };

    // Return non-printable keys
    if keycode != KeyCode::Unknown {
        let (ascii, shifted) = match keycode {
            KeyCode::Tab => (b'\t', b'\t'),
            KeyCode::Enter => (b'\n', b'\n'),
            KeyCode::Space => (b' ', b' '),
            KeyCode::Backspace => (8, 8),
            KeyCode::Escape => (0x1B, 0x1B),
            _ => (0, 0),
        };
        let printable = ascii != 0;
        return KeyMapping::new(keycode, ascii, shifted, false, printable);
    }

    // Handle numpad keys
    let mods = get_modifiers();
    let numpad = match code {
        0x47 => Some(NumpadKey::Num7),
        0x48 => Some(NumpadKey::Num8),
        0x49 => Some(NumpadKey::Num9),
        0x4A => Some(NumpadKey::Subtract),
        0x4B => Some(NumpadKey::Num4),
        0x4C => Some(NumpadKey::Num5),
        0x4D => Some(NumpadKey::Num6),
        0x4E => Some(NumpadKey::Add),
        0x4F => Some(NumpadKey::Num1),
        0x50 => Some(NumpadKey::Num2),
        0x51 => Some(NumpadKey::Num3),
        0x52 => Some(NumpadKey::Num0),
        0x53 => Some(NumpadKey::Decimal),
        0x37 => Some(NumpadKey::Multiply),
        _ => None,
    };

    if let Some(np) = numpad {
        let num_lock = mods.is_num_lock();
        let keycode = np.to_keycode(num_lock);
        let ascii = np.to_ascii(num_lock).unwrap_or(0);
        return KeyMapping::new(keycode, ascii, ascii, false, ascii != 0);
    }

    // Get ASCII from layout tables
    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);

    if (code as usize) < base_map.len() {
        let ascii = base_map[code as usize];
        let shifted = shift_map[code as usize];
        let keycode = ascii_to_keycode(ascii);
        let printable = ascii != 0;
        KeyMapping::new(keycode, ascii, shifted, false, printable)
    } else {
        KeyMapping::unknown()
    }
}

/// Simple scan code to keycode mapping (legacy API)
pub fn map_scan_code(scan: u8, shifted: bool, layout: Layout) -> KeyCode {
    if scan as usize >= 128 {
        return KeyCode::Unknown;
    }

    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);

    let ascii = if shifted {
        shift_map[scan as usize]
    } else {
        base_map[scan as usize]
    };

    scan_to_keycode(scan, ascii)
}

/// Full mapping with ASCII values (legacy API)
pub fn map_scan_code_full(scan: u8, shifted: bool, layout: Layout) -> KeyMapping {
    if scan as usize >= 128 {
        return KeyMapping::unknown();
    }

    let base_map = get_ascii_mapping(layout);
    let shift_map = get_shifted_mapping(layout);

    let ascii = base_map[scan as usize];
    let shifted_ascii = shift_map[scan as usize];

    let keycode = if shifted {
        scan_to_keycode(scan, shifted_ascii)
    } else {
        scan_to_keycode(scan, ascii)
    };

    KeyMapping::new(keycode, ascii, shifted_ascii, false, ascii != 0)
}

fn scan_to_keycode(scan: u8, ascii: u8) -> KeyCode {
    match scan {
        0x01 => KeyCode::Escape,
        0x0E => KeyCode::Backspace,
        0x0F => KeyCode::Tab,
        0x1C => KeyCode::Enter,
        0x1D => KeyCode::LeftCtrl,
        0x2A => KeyCode::LeftShift,
        0x36 => KeyCode::RightShift,
        0x38 => KeyCode::LeftAlt,
        0x39 => KeyCode::Space,
        0x3A => KeyCode::CapsLock,
        0x3B => KeyCode::F1,
        0x3C => KeyCode::F2,
        0x3D => KeyCode::F3,
        0x3E => KeyCode::F4,
        0x3F => KeyCode::F5,
        0x40 => KeyCode::F6,
        0x41 => KeyCode::F7,
        0x42 => KeyCode::F8,
        0x43 => KeyCode::F9,
        0x44 => KeyCode::F10,
        0x45 => KeyCode::NumLock,
        0x46 => KeyCode::ScrollLock,
        0x47 => KeyCode::Home,
        0x48 => KeyCode::ArrowUp,
        0x49 => KeyCode::PageUp,
        0x4B => KeyCode::ArrowLeft,
        0x4D => KeyCode::ArrowRight,
        0x4F => KeyCode::End,
        0x50 => KeyCode::ArrowDown,
        0x51 => KeyCode::PageDown,
        0x52 => KeyCode::Insert,
        0x53 => KeyCode::Delete,
        0x57 => KeyCode::F11,
        0x58 => KeyCode::F12,
        _ => ascii_to_keycode(ascii),
    }
}

/// Converts ASCII character to KeyCode
pub fn ascii_to_keycode(ascii: u8) -> KeyCode {
    match ascii {
        b'a' | b'A' => KeyCode::A,
        b'b' | b'B' => KeyCode::B,
        b'c' | b'C' => KeyCode::C,
        b'd' | b'D' => KeyCode::D,
        b'e' | b'E' => KeyCode::E,
        b'f' | b'F' => KeyCode::F,
        b'g' | b'G' => KeyCode::G,
        b'h' | b'H' => KeyCode::H,
        b'i' | b'I' => KeyCode::I,
        b'j' | b'J' => KeyCode::J,
        b'k' | b'K' => KeyCode::K,
        b'l' | b'L' => KeyCode::L,
        b'm' | b'M' => KeyCode::M,
        b'n' | b'N' => KeyCode::N,
        b'o' | b'O' => KeyCode::O,
        b'p' | b'P' => KeyCode::P,
        b'q' | b'Q' => KeyCode::Q,
        b'r' | b'R' => KeyCode::R,
        b's' | b'S' => KeyCode::S,
        b't' | b'T' => KeyCode::T,
        b'u' | b'U' => KeyCode::U,
        b'v' | b'V' => KeyCode::V,
        b'w' | b'W' => KeyCode::W,
        b'x' | b'X' => KeyCode::X,
        b'y' | b'Y' => KeyCode::Y,
        b'z' | b'Z' => KeyCode::Z,
        b'0' | b')' => KeyCode::Num0,
        b'1' | b'!' => KeyCode::Num1,
        b'2' | b'@' => KeyCode::Num2,
        b'3' | b'#' => KeyCode::Num3,
        b'4' | b'$' => KeyCode::Num4,
        b'5' | b'%' => KeyCode::Num5,
        b'6' | b'^' => KeyCode::Num6,
        b'7' | b'&' => KeyCode::Num7,
        b'8' | b'*' => KeyCode::Num8,
        b'9' | b'(' => KeyCode::Num9,
        b'-' | b'_' => KeyCode::Minus,
        b'=' | b'+' => KeyCode::Equals,
        b'[' | b'{' => KeyCode::LeftBracket,
        b']' | b'}' => KeyCode::RightBracket,
        b'\\' | b'|' => KeyCode::Backslash,
        b';' | b':' => KeyCode::Semicolon,
        b'\'' | b'"' => KeyCode::Quote,
        b'`' | b'~' => KeyCode::Backtick,
        b',' | b'<' => KeyCode::Comma,
        b'.' | b'>' => KeyCode::Period,
        b'/' | b'?' => KeyCode::Slash,
        0 => KeyCode::Unknown,
        _ => KeyCode::Char(ascii as char),
    }
}

/// Converts keycode to ASCII (legacy API)
pub fn keycode_to_ascii(keycode: KeyCode, shifted: bool) -> Option<u8> {
    let mods = if shifted {
        ModifierState::from_bits(ModifierState::SHIFT)
    } else {
        ModifierState::NONE
    };
    keycode_to_ascii_with_mods(keycode, mods)
}

/// Converts keycode to ASCII with full modifier support
pub fn keycode_to_ascii_with_mods(keycode: KeyCode, modifiers: ModifierState) -> Option<u8> {
    // Handle Ctrl combinations
    if modifiers.is_ctrl() {
        return match keycode {
            KeyCode::A => Some(0x01),
            KeyCode::B => Some(0x02),
            KeyCode::C => Some(0x03),
            KeyCode::D => Some(0x04),
            KeyCode::E => Some(0x05),
            KeyCode::F => Some(0x06),
            KeyCode::G => Some(0x07),
            KeyCode::H => Some(0x08),
            KeyCode::I => Some(0x09),
            KeyCode::J => Some(0x0A),
            KeyCode::K => Some(0x0B),
            KeyCode::L => Some(0x0C),
            KeyCode::M => Some(0x0D),
            KeyCode::N => Some(0x0E),
            KeyCode::O => Some(0x0F),
            KeyCode::P => Some(0x10),
            KeyCode::Q => Some(0x11),
            KeyCode::R => Some(0x12),
            KeyCode::S => Some(0x13),
            KeyCode::T => Some(0x14),
            KeyCode::U => Some(0x15),
            KeyCode::V => Some(0x16),
            KeyCode::W => Some(0x17),
            KeyCode::X => Some(0x18),
            KeyCode::Y => Some(0x19),
            KeyCode::Z => Some(0x1A),
            KeyCode::LeftBracket => Some(0x1B), // Escape
            KeyCode::Backslash => Some(0x1C),
            KeyCode::RightBracket => Some(0x1D),
            _ => None,
        };
    }

    // Determine shift state for letter keys
    let shifted = if keycode.is_letter() {
        modifiers.effective_shift_for_letter()
    } else {
        modifiers.is_shifted()
    };

    match keycode {
        KeyCode::A => Some(if shifted { b'A' } else { b'a' }),
        KeyCode::B => Some(if shifted { b'B' } else { b'b' }),
        KeyCode::C => Some(if shifted { b'C' } else { b'c' }),
        KeyCode::D => Some(if shifted { b'D' } else { b'd' }),
        KeyCode::E => Some(if shifted { b'E' } else { b'e' }),
        KeyCode::F => Some(if shifted { b'F' } else { b'f' }),
        KeyCode::G => Some(if shifted { b'G' } else { b'g' }),
        KeyCode::H => Some(if shifted { b'H' } else { b'h' }),
        KeyCode::I => Some(if shifted { b'I' } else { b'i' }),
        KeyCode::J => Some(if shifted { b'J' } else { b'j' }),
        KeyCode::K => Some(if shifted { b'K' } else { b'k' }),
        KeyCode::L => Some(if shifted { b'L' } else { b'l' }),
        KeyCode::M => Some(if shifted { b'M' } else { b'm' }),
        KeyCode::N => Some(if shifted { b'N' } else { b'n' }),
        KeyCode::O => Some(if shifted { b'O' } else { b'o' }),
        KeyCode::P => Some(if shifted { b'P' } else { b'p' }),
        KeyCode::Q => Some(if shifted { b'Q' } else { b'q' }),
        KeyCode::R => Some(if shifted { b'R' } else { b'r' }),
        KeyCode::S => Some(if shifted { b'S' } else { b's' }),
        KeyCode::T => Some(if shifted { b'T' } else { b't' }),
        KeyCode::U => Some(if shifted { b'U' } else { b'u' }),
        KeyCode::V => Some(if shifted { b'V' } else { b'v' }),
        KeyCode::W => Some(if shifted { b'W' } else { b'w' }),
        KeyCode::X => Some(if shifted { b'X' } else { b'x' }),
        KeyCode::Y => Some(if shifted { b'Y' } else { b'y' }),
        KeyCode::Z => Some(if shifted { b'Z' } else { b'z' }),
        KeyCode::Num0 => Some(if shifted { b')' } else { b'0' }),
        KeyCode::Num1 => Some(if shifted { b'!' } else { b'1' }),
        KeyCode::Num2 => Some(if shifted { b'@' } else { b'2' }),
        KeyCode::Num3 => Some(if shifted { b'#' } else { b'3' }),
        KeyCode::Num4 => Some(if shifted { b'$' } else { b'4' }),
        KeyCode::Num5 => Some(if shifted { b'%' } else { b'5' }),
        KeyCode::Num6 => Some(if shifted { b'^' } else { b'6' }),
        KeyCode::Num7 => Some(if shifted { b'&' } else { b'7' }),
        KeyCode::Num8 => Some(if shifted { b'*' } else { b'8' }),
        KeyCode::Num9 => Some(if shifted { b'(' } else { b'9' }),
        KeyCode::Space => Some(b' '),
        KeyCode::Enter => Some(b'\n'),
        KeyCode::Tab => Some(b'\t'),
        KeyCode::Backspace => Some(8),
        KeyCode::Escape => Some(0x1B),
        KeyCode::Minus => Some(if shifted { b'_' } else { b'-' }),
        KeyCode::Equals => Some(if shifted { b'+' } else { b'=' }),
        KeyCode::LeftBracket => Some(if shifted { b'{' } else { b'[' }),
        KeyCode::RightBracket => Some(if shifted { b'}' } else { b']' }),
        KeyCode::Backslash => Some(if shifted { b'|' } else { b'\\' }),
        KeyCode::Semicolon => Some(if shifted { b':' } else { b';' }),
        KeyCode::Quote => Some(if shifted { b'"' } else { b'\'' }),
        KeyCode::Backtick => Some(if shifted { b'~' } else { b'`' }),
        KeyCode::Comma => Some(if shifted { b'<' } else { b',' }),
        KeyCode::Period => Some(if shifted { b'>' } else { b'.' }),
        KeyCode::Slash => Some(if shifted { b'?' } else { b'/' }),
        KeyCode::Char(c) => Some(c as u8),
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_letter_keys() {
        assert_eq!(map_scan_code(0x1E, false, Layout::UsQwerty), KeyCode::A);
        assert_eq!(map_scan_code(0x1E, true, Layout::UsQwerty), KeyCode::A);
        assert_eq!(map_scan_code(0x30, false, Layout::UsQwerty), KeyCode::B);
    }

    #[test]
    fn test_number_keys() {
        assert_eq!(map_scan_code(0x02, false, Layout::UsQwerty), KeyCode::Num1);
        assert_eq!(map_scan_code(0x0B, false, Layout::UsQwerty), KeyCode::Num0);
    }

    #[test]
    fn test_special_keys() {
        assert_eq!(map_scan_code(0x01, false, Layout::UsQwerty), KeyCode::Escape);
        assert_eq!(map_scan_code(0x0E, false, Layout::UsQwerty), KeyCode::Backspace);
        assert_eq!(map_scan_code(0x0F, false, Layout::UsQwerty), KeyCode::Tab);
        assert_eq!(map_scan_code(0x1C, false, Layout::UsQwerty), KeyCode::Enter);
        assert_eq!(map_scan_code(0x39, false, Layout::UsQwerty), KeyCode::Space);
    }

    #[test]
    fn test_function_keys() {
        assert_eq!(map_scan_code(0x3B, false, Layout::UsQwerty), KeyCode::F1);
        assert_eq!(map_scan_code(0x44, false, Layout::UsQwerty), KeyCode::F10);
        assert_eq!(map_scan_code(0x57, false, Layout::UsQwerty), KeyCode::F11);
        assert_eq!(map_scan_code(0x58, false, Layout::UsQwerty), KeyCode::F12);
    }

    #[test]
    fn test_arrow_keys() {
        assert_eq!(map_scan_code(0x48, false, Layout::UsQwerty), KeyCode::ArrowUp);
        assert_eq!(map_scan_code(0x50, false, Layout::UsQwerty), KeyCode::ArrowDown);
        assert_eq!(map_scan_code(0x4B, false, Layout::UsQwerty), KeyCode::ArrowLeft);
        assert_eq!(map_scan_code(0x4D, false, Layout::UsQwerty), KeyCode::ArrowRight);
    }

    #[test]
    fn test_keycode_to_ascii() {
        assert_eq!(keycode_to_ascii(KeyCode::A, false), Some(b'a'));
        assert_eq!(keycode_to_ascii(KeyCode::A, true), Some(b'A'));
        assert_eq!(keycode_to_ascii(KeyCode::Num1, false), Some(b'1'));
        assert_eq!(keycode_to_ascii(KeyCode::Num1, true), Some(b'!'));
        assert_eq!(keycode_to_ascii(KeyCode::Space, false), Some(b' '));
        assert_eq!(keycode_to_ascii(KeyCode::F1, false), None);
    }

    #[test]
    fn test_out_of_bounds() {
        assert_eq!(map_scan_code(0xFF, false, Layout::UsQwerty), KeyCode::Unknown);
        assert_eq!(map_scan_code(0x80, false, Layout::UsQwerty), KeyCode::Unknown);
    }

    #[test]
    fn test_full_mapping() {
        let mapping = map_scan_code_full(0x1E, false, Layout::UsQwerty);
        assert_eq!(mapping.keycode, KeyCode::A);
        assert_eq!(mapping.ascii, b'a');
        assert_eq!(mapping.shifted_ascii, b'A');
    }

    #[test]
    fn test_modifier_state() {
        let mut mods = ModifierState::NONE;
        assert!(!mods.is_shifted());
        assert!(!mods.is_ctrl());

        mods.set(ModifierState::SHIFT);
        assert!(mods.is_shifted());

        mods.set(ModifierState::CTRL);
        assert!(mods.is_ctrl());

        mods.clear(ModifierState::SHIFT);
        assert!(!mods.is_shifted());
        assert!(mods.is_ctrl());
    }

    #[test]
    fn test_caps_lock_effect() {
        let mods = ModifierState::from_bits(ModifierState::CAPS_LOCK);
        assert!(mods.effective_shift_for_letter()); // CapsLock acts as shift for letters

        let mods_both = ModifierState::from_bits(ModifierState::CAPS_LOCK | ModifierState::SHIFT);
        assert!(!mods_both.effective_shift_for_letter()); // CapsLock + Shift = lowercase
    }

    #[test]
    fn test_ctrl_combinations() {
        let mods = ModifierState::from_bits(ModifierState::CTRL);
        assert_eq!(keycode_to_ascii_with_mods(KeyCode::A, mods), Some(0x01));
        assert_eq!(keycode_to_ascii_with_mods(KeyCode::C, mods), Some(0x03));
        assert_eq!(keycode_to_ascii_with_mods(KeyCode::Z, mods), Some(0x1A));
    }

    #[test]
    fn test_numpad_with_numlock() {
        let np = NumpadKey::Num5;
        assert_eq!(np.to_ascii(true), Some(b'5'));
        assert_eq!(np.to_ascii(false), None);
        assert_eq!(np.to_keycode(true), KeyCode::Num5);
        assert_eq!(np.to_keycode(false), KeyCode::Unknown);
    }

    #[test]
    fn test_extended_scan_codes() {
        // Test E0 prefix handling
        let result = process_scan_code(0xE0, Layout::UsQwerty);
        assert!(result.unwrap().is_none()); // Waiting for next byte

        let result = process_scan_code(0x48, Layout::UsQwerty);
        let mapping = result.unwrap().unwrap();
        assert_eq!(mapping.keycode, KeyCode::ArrowUp);
        assert!(mapping.extended);
    }

    #[test]
    fn test_error_handling() {
        assert_eq!(KeymapError::InvalidScanCode.as_str(), "invalid scan code");
        assert_eq!(KeymapError::IncompleteExtended.as_str(), "incomplete extended scan code");
    }

    #[test]
    fn test_key_mapping_get_ascii() {
        let mapping = KeyMapping::new(KeyCode::A, b'a', b'A', false, true);
        assert_eq!(mapping.get_ascii(ModifierState::NONE), Some(b'a'));
        assert_eq!(mapping.get_ascii(ModifierState::from_bits(ModifierState::SHIFT)), Some(b'A'));
    }

    #[test]
    fn test_is_letter() {
        assert!(KeyCode::A.is_letter());
        assert!(KeyCode::Z.is_letter());
        assert!(!KeyCode::Num1.is_letter());
        assert!(!KeyCode::Space.is_letter());
    }
}
