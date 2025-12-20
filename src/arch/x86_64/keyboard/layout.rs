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
//! Keyboard layout support with:
//! **Multiple built-in layouts**
//! **AltGr layer support**
//! **Dead key support**
//! **Layout metadata**
//! **Runtime layout registration**
//! **Thread-safe layout switching**
//!
//! ## Scan Code Mapping

use core::sync::atomic::{AtomicU8, Ordering};
use spin::RwLock;

// ============================================================================
// Error Handling
// ============================================================================

/// Error types for layout operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// Layout not found
    NotFound,
    /// Invalid layout ID
    InvalidId,
    /// Custom layout registry full
    RegistryFull,
    /// Layout already registered
    AlreadyRegistered,
    /// Invalid scan code
    InvalidScanCode,
}

impl LayoutError {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "layout not found",
            Self::InvalidId => "invalid layout ID",
            Self::RegistryFull => "custom layout registry full",
            Self::AlreadyRegistered => "layout already registered",
            Self::InvalidScanCode => "invalid scan code",
        }
    }
}

/// Result type for layout operations
pub type LayoutResult<T> = Result<T, LayoutError>;

// ============================================================================
// Layout Identification
// ============================================================================

/// Built-in keyboard layout identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Layout {
    /// US QWERTY (default)
    UsQwerty = 0,
    /// Dvorak Simplified Keyboard
    Dvorak = 1,
    /// French AZERTY
    Azerty = 2,
    /// Colemak
    Colemak = 3,
    /// German QWERTZ
    Qwertz = 4,
    /// UK QWERTY (ISO)
    UkQwerty = 5,
    /// Spanish QWERTY
    Spanish = 6,
    /// Custom layout (uses registered data)
    Custom = 255,
}

impl Layout {
    /// Total number of built-in layouts
    pub const COUNT: usize = 7;

    /// Converts from u8 to Layout
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::UsQwerty),
            1 => Some(Self::Dvorak),
            2 => Some(Self::Azerty),
            3 => Some(Self::Colemak),
            4 => Some(Self::Qwertz),
            5 => Some(Self::UkQwerty),
            6 => Some(Self::Spanish),
            255 => Some(Self::Custom),
            _ => None,
        }
    }

    /// Returns the layout name
    pub const fn name(self) -> &'static str {
        match self {
            Self::UsQwerty => "US QWERTY",
            Self::Dvorak => "Dvorak",
            Self::Azerty => "AZERTY (French)",
            Self::Colemak => "Colemak",
            Self::Qwertz => "QWERTZ (German)",
            Self::UkQwerty => "UK QWERTY",
            Self::Spanish => "Spanish QWERTY",
            Self::Custom => "Custom",
        }
    }

    /// Returns the layout name (legacy alias)
    pub const fn as_str(self) -> &'static str {
        self.name()
    }

    /// Returns the ISO 639-1 language code
    pub const fn language_code(self) -> &'static str {
        match self {
            Self::UsQwerty | Self::Dvorak | Self::Colemak | Self::UkQwerty => "en",
            Self::Azerty => "fr",
            Self::Qwertz => "de",
            Self::Spanish => "es",
            Self::Custom => "xx",
        }
    }

    /// Returns the ISO 3166-1 country code
    pub const fn country_code(self) -> &'static str {
        match self {
            Self::UsQwerty | Self::Dvorak | Self::Colemak => "US",
            Self::UkQwerty => "GB",
            Self::Azerty => "FR",
            Self::Qwertz => "DE",
            Self::Spanish => "ES",
            Self::Custom => "XX",
        }
    }

    /// Returns true if this layout has an AltGr layer
    pub const fn has_altgr(self) -> bool {
        matches!(self, Self::Azerty | Self::Qwertz | Self::Spanish | Self::UkQwerty)
    }

    /// Returns true if this layout has dead keys
    pub const fn has_dead_keys(self) -> bool {
        matches!(self, Self::Azerty | Self::Qwertz | Self::Spanish)
    }

    /// Returns all available layouts
    pub const fn all() -> [Layout; Self::COUNT] {
        [
            Self::UsQwerty,
            Self::Dvorak,
            Self::Azerty,
            Self::Colemak,
            Self::Qwertz,
            Self::UkQwerty,
            Self::Spanish,
        ]
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self::UsQwerty
    }
}

// ============================================================================
// Layout Metadata
// ============================================================================

/// Complete layout information
#[derive(Debug, Clone, Copy)]
pub struct LayoutInfo {
    /// Layout identifier
    pub layout: Layout,
    /// Base layer (unshifted)
    pub base: &'static [u8; 128],
    /// Shift layer
    pub shift: &'static [u8; 128],
    /// AltGr layer (optional, zeros if not used)
    pub altgr: &'static [u8; 128],
    /// Dead keys on base layer (scan code -> dead key type)
    pub dead_keys_base: &'static [(u8, DeadKey)],
    /// Dead keys on shift layer
    pub dead_keys_shift: &'static [(u8, DeadKey)],
}

impl LayoutInfo {
    /// Creates a new layout info
    pub const fn new(
        layout: Layout,
        base: &'static [u8; 128],
        shift: &'static [u8; 128],
        altgr: &'static [u8; 128],
    ) -> Self {
        Self {
            layout,
            base,
            shift,
            altgr,
            dead_keys_base: &[],
            dead_keys_shift: &[],
        }
    }

    /// Creates layout info with dead keys
    pub const fn with_dead_keys(
        layout: Layout,
        base: &'static [u8; 128],
        shift: &'static [u8; 128],
        altgr: &'static [u8; 128],
        dead_base: &'static [(u8, DeadKey)],
        dead_shift: &'static [(u8, DeadKey)],
    ) -> Self {
        Self {
            layout,
            base,
            shift,
            altgr,
            dead_keys_base: dead_base,
            dead_keys_shift: dead_shift,
        }
    }

    /// Looks up ASCII for a scan code
    pub fn lookup(&self, scan_code: u8, shifted: bool, altgr: bool) -> u8 {
        if scan_code >= 128 {
            return 0;
        }
        let idx = scan_code as usize;
        if altgr && self.altgr[idx] != 0 {
            self.altgr[idx]
        } else if shifted {
            self.shift[idx]
        } else {
            self.base[idx]
        }
    }

    /// Checks if scan code is a dead key
    pub fn is_dead_key(&self, scan_code: u8, shifted: bool) -> Option<DeadKey> {
        let table = if shifted { self.dead_keys_shift } else { self.dead_keys_base };
        for &(sc, dk) in table {
            if sc == scan_code {
                return Some(dk);
            }
        }
        None
    }
}

// ============================================================================
// Dead Key Support
// ============================================================================

/// Dead key types for accent composition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeadKey {
    /// Acute accent (´) - produces á, é, í, ó, ú
    Acute = 1,
    /// Grave accent (`) - produces à, è, ì, ò, ù
    Grave = 2,
    /// Circumflex (^) - produces â, ê, î, ô, û
    Circumflex = 3,
    /// Diaeresis/Umlaut (¨) - produces ä, ë, ï, ö, ü
    Diaeresis = 4,
    /// Tilde (~) - produces ã, ñ, õ
    Tilde = 5,
    /// Cedilla (¸) - produces ç
    Cedilla = 6,
    /// Ring (°) - produces å
    Ring = 7,
    /// Caron (ˇ) - produces č, š, ž
    Caron = 8,
}

impl DeadKey {
    /// Combines dead key with base character to produce accented character
    /// Returns the composed character or None if combination is invalid
    pub const fn compose(self, base: u8) -> Option<u8> {
        match self {
            Self::Acute => match base {
                b'a' => Some(0xE1), // á (Latin-1)
                b'e' => Some(0xE9), // é
                b'i' => Some(0xED), // í
                b'o' => Some(0xF3), // ó
                b'u' => Some(0xFA), // ú
                b'A' => Some(0xC1), // Á
                b'E' => Some(0xC9), // É
                b'I' => Some(0xCD), // Í
                b'O' => Some(0xD3), // Ó
                b'U' => Some(0xDA), // Ú
                b'y' => Some(0xFD), // ý
                b'Y' => Some(0xDD), // Ý
                b' ' => Some(0xB4), // standalone ´
                _ => None,
            },
            Self::Grave => match base {
                b'a' => Some(0xE0), // à
                b'e' => Some(0xE8), // è
                b'i' => Some(0xEC), // ì
                b'o' => Some(0xF2), // ò
                b'u' => Some(0xF9), // ù
                b'A' => Some(0xC0), // À
                b'E' => Some(0xC8), // È
                b'I' => Some(0xCC), // Ì
                b'O' => Some(0xD2), // Ò
                b'U' => Some(0xD9), // Ù
                b' ' => Some(b'`'), // standalone `
                _ => None,
            },
            Self::Circumflex => match base {
                b'a' => Some(0xE2), // â
                b'e' => Some(0xEA), // ê
                b'i' => Some(0xEE), // î
                b'o' => Some(0xF4), // ô
                b'u' => Some(0xFB), // û
                b'A' => Some(0xC2), // Â
                b'E' => Some(0xCA), // Ê
                b'I' => Some(0xCE), // Î
                b'O' => Some(0xD4), // Ô
                b'U' => Some(0xDB), // Û
                b' ' => Some(b'^'), // standalone ^
                _ => None,
            },
            Self::Diaeresis => match base {
                b'a' => Some(0xE4), // ä
                b'e' => Some(0xEB), // ë
                b'i' => Some(0xEF), // ï
                b'o' => Some(0xF6), // ö
                b'u' => Some(0xFC), // ü
                b'y' => Some(0xFF), // ÿ
                b'A' => Some(0xC4), // Ä
                b'E' => Some(0xCB), // Ë
                b'I' => Some(0xCF), // Ï
                b'O' => Some(0xD6), // Ö
                b'U' => Some(0xDC), // Ü
                b' ' => Some(0xA8), // standalone ¨
                _ => None,
            },
            Self::Tilde => match base {
                b'a' => Some(0xE3), // ã
                b'n' => Some(0xF1), // ñ
                b'o' => Some(0xF5), // õ
                b'A' => Some(0xC3), // Ã
                b'N' => Some(0xD1), // Ñ
                b'O' => Some(0xD5), // Õ
                b' ' => Some(b'~'), // standalone ~
                _ => None,
            },
            Self::Cedilla => match base {
                b'c' => Some(0xE7), // ç
                b'C' => Some(0xC7), // Ç
                b' ' => Some(0xB8), // standalone ¸
                _ => None,
            },
            Self::Ring => match base {
                b'a' => Some(0xE5), // å
                b'A' => Some(0xC5), // Å
                b' ' => Some(0xB0), // standalone °
                _ => None,
            },
            Self::Caron => match base {
                // These are outside Latin-1, return approximations
                b'c' => Some(b'c'), // č approximated
                b's' => Some(b's'), // š approximated
                b'z' => Some(b'z'), // ž approximated
                b'C' => Some(b'C'),
                b'S' => Some(b'S'),
                b'Z' => Some(b'Z'),
                b' ' => Some(b'^'), // approximated
                _ => None,
            },
        }
    }

    /// Returns the standalone character for this dead key
    pub const fn standalone(self) -> u8 {
        match self {
            Self::Acute => 0xB4,
            Self::Grave => b'`',
            Self::Circumflex => b'^',
            Self::Diaeresis => 0xA8,
            Self::Tilde => b'~',
            Self::Cedilla => 0xB8,
            Self::Ring => 0xB0,
            Self::Caron => b'^',
        }
    }
}

// ============================================================================
// Dead Key State Machine
// ============================================================================

/// Current dead key state
static PENDING_DEAD_KEY: RwLock<Option<DeadKey>> = RwLock::new(None);

/// Sets pending dead key
pub fn set_pending_dead_key(dk: DeadKey) {
    *PENDING_DEAD_KEY.write() = Some(dk);
}

/// Clears pending dead key
pub fn clear_pending_dead_key() {
    *PENDING_DEAD_KEY.write() = None;
}

/// Gets and clears pending dead key
pub fn take_pending_dead_key() -> Option<DeadKey> {
    PENDING_DEAD_KEY.write().take()
}

/// Checks if a dead key is pending
pub fn has_pending_dead_key() -> bool {
    PENDING_DEAD_KEY.read().is_some()
}

/// Processes a character with pending dead key
/// Returns the composed character or the original if no composition
pub fn process_with_dead_key(ch: u8) -> u8 {
    if let Some(dk) = take_pending_dead_key() {
        dk.compose(ch).unwrap_or(ch)
    } else {
        ch
    }
}

// ============================================================================
// Current Layout State
// ============================================================================

static CURRENT_LAYOUT: AtomicU8 = AtomicU8::new(Layout::UsQwerty as u8);

/// Gets the current keyboard layout
pub fn get_layout() -> Layout {
    Layout::from_u8(CURRENT_LAYOUT.load(Ordering::Acquire)).unwrap_or(Layout::UsQwerty)
}

/// Sets the current keyboard layout
pub fn set_layout(layout: Layout) {
    CURRENT_LAYOUT.store(layout as u8, Ordering::Release);
    // Clear any pending dead key when switching layouts
    clear_pending_dead_key();
}

/// Gets the current layout info
pub fn get_layout_info() -> &'static LayoutInfo {
    get_layout_info_for(get_layout())
}

/// Gets layout info for a specific layout
pub fn get_layout_info_for(layout: Layout) -> &'static LayoutInfo {
    match layout {
        Layout::UsQwerty => &LAYOUT_US_QWERTY,
        Layout::Dvorak => &LAYOUT_DVORAK,
        Layout::Azerty => &LAYOUT_AZERTY,
        Layout::Colemak => &LAYOUT_COLEMAK,
        Layout::Qwertz => &LAYOUT_QWERTZ,
        Layout::UkQwerty => &LAYOUT_UK_QWERTY,
        Layout::Spanish => &LAYOUT_SPANISH,
        Layout::Custom => &LAYOUT_US_QWERTY, // Fallback
    }
}

// ============================================================================
// Layout Data - US QWERTY
// ============================================================================

/// US QWERTY base layer
pub static US_QWERTY: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0,   b'a', b's',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'',b'`', 0,    b'\\',b'z', b'x', b'c', b'v',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'b', b'n', b'm', b',', b'.', b'/', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F: Function keys, numpad, etc. (mostly 0)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// US QWERTY shift layer
pub static US_QWERTY_SHIFT: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n', 0,   b'A', b'S',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':', b'"', b'~', 0,    b'|', b'Z', b'X', b'C', b'V',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'B', b'N', b'M', b'<', b'>', b'?', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// US QWERTY has no AltGr layer
static US_QWERTY_ALTGR: [u8; 128] = [0; 128];

static LAYOUT_US_QWERTY: LayoutInfo = LayoutInfo::new(
    Layout::UsQwerty,
    &US_QWERTY,
    &US_QWERTY_SHIFT,
    &US_QWERTY_ALTGR,
);

// ============================================================================
// Layout Data - Dvorak
// ============================================================================

/// Dvorak base layer
pub static DVORAK: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'[', b']', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'\'',b',', b'.', b'p', b'y', b'f', b'g', b'c', b'r', b'l', b'/', b'=', b'\n', 0,   b'a', b'o',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'e', b'u', b'i', b'd', b'h', b't', b'n', b's', b'-', b'`', 0,    b'\\',b';', b'q', b'j', b'k',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'x', b'b', b'm', b'w', b'v', b'z', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Dvorak shift layer
pub static DVORAK_SHIFT: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'{', b'}', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'"', b'<', b'>', b'P', b'Y', b'F', b'G', b'C', b'R', b'L', b'?', b'+', b'\n', 0,   b'A', b'O',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'E', b'U', b'I', b'D', b'H', b'T', b'N', b'S', b'_', b'~', 0,    b'|', b':', b'Q', b'J', b'K',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'X', b'B', b'M', b'W', b'V', b'Z', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static DVORAK_ALTGR: [u8; 128] = [0; 128];

static LAYOUT_DVORAK: LayoutInfo = LayoutInfo::new(
    Layout::Dvorak,
    &DVORAK,
    &DVORAK_SHIFT,
    &DVORAK_ALTGR,
);

// ============================================================================
// Layout Data - Colemak
// ============================================================================

/// Colemak base layer
pub static COLEMAK: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'q', b'w', b'f', b'p', b'g', b'j', b'l', b'u', b'y', b';', b'[', b']', b'\n', 0,   b'a', b'r',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b's', b't', b'd', b'h', b'n', b'e', b'i', b'o', b'\'',b'`', 0,    b'\\',b'z', b'x', b'c', b'v',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'b', b'k', b'm', b',', b'.', b'/', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Colemak shift layer
pub static COLEMAK_SHIFT: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'Q', b'W', b'F', b'P', b'G', b'J', b'L', b'U', b'Y', b':', b'{', b'}', b'\n', 0,   b'A', b'R',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'S', b'T', b'D', b'H', b'N', b'E', b'I', b'O', b'"', b'~', 0,    b'|', b'Z', b'X', b'C', b'V',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'B', b'K', b'M', b'<', b'>', b'?', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static COLEMAK_ALTGR: [u8; 128] = [0; 128];

static LAYOUT_COLEMAK: LayoutInfo = LayoutInfo::new(
    Layout::Colemak,
    &COLEMAK,
    &COLEMAK_SHIFT,
    &COLEMAK_ALTGR,
);

// ============================================================================
// Layout Data - French AZERTY
// ============================================================================

/// French AZERTY base layer
pub static AZERTY: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'&', 0xE9, b'"', b'\'',b'(', b'-', 0xE8, b'_', 0xE7, 0xE0, b')', b'=', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'a', b'z', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'^', b'$', b'\n', 0,   b'q', b's',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b'm', 0xF9, 0xB2, 0,    b'*', b'w', b'x', b'c', b'v',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'b', b'n', b',', b';', b':', b'!', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// French AZERTY shift layer
pub static AZERTY_SHIFT: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', 0xB0, b'+', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'A', b'Z', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', 0xA8, 0xA3, b'\n', 0,   b'Q', b'S',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', b'M', b'%', b'~', 0,    0xB5, b'W', b'X', b'C', b'V',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'B', b'N', b'?', b'.', b'/', 0xA7, 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// French AZERTY AltGr layer
static AZERTY_ALTGR: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    0,    0,    b'~', b'#', b'{', b'[', b'|', b'`', b'\\',b'^', b'@', b']', b'}', 0,    0,
//  0x10-0x1F
    0,    0,    0x80, 0,    0,    0,    0,    0,    0,    0,    0,    0xA4, 0,    0,    0,    0,
//  0x20-0x7F: mostly empty
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// AZERTY dead keys - circumflex on scan code 0x1A (^)
static AZERTY_DEAD_BASE: [(u8, DeadKey); 1] = [(0x1A, DeadKey::Circumflex)];
static AZERTY_DEAD_SHIFT: [(u8, DeadKey); 1] = [(0x1A, DeadKey::Diaeresis)];

static LAYOUT_AZERTY: LayoutInfo = LayoutInfo::with_dead_keys(
    Layout::Azerty,
    &AZERTY,
    &AZERTY_SHIFT,
    &AZERTY_ALTGR,
    &AZERTY_DEAD_BASE,
    &AZERTY_DEAD_SHIFT,
);

// ============================================================================
// Layout Data - German QWERTZ
// ============================================================================

/// German QWERTZ base layer
pub static QWERTZ: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', 0xDF, 0xB4, 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'q', b'w', b'e', b'r', b't', b'z', b'u', b'i', b'o', b'p', 0xFC, b'+', b'\n', 0,   b'a', b's',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', 0xF6, 0xE4, b'^', 0,    b'#', b'y', b'x', b'c', b'v',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'b', b'n', b'm', b',', b'.', b'-', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// German QWERTZ shift layer
pub static QWERTZ_SHIFT: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'!', b'"', 0xA7, b'$', b'%', b'&', b'/', b'(', b')', b'=', b'?', b'`', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'Q', b'W', b'E', b'R', b'T', b'Z', b'U', b'I', b'O', b'P', 0xDC, b'*', b'\n', 0,   b'A', b'S',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', 0xD6, 0xC4, 0xB0, 0,    b'\'',b'Y', b'X', b'C', b'V',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'B', b'N', b'M', b';', b':', b'_', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// German QWERTZ AltGr layer
static QWERTZ_ALTGR: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    0,    0,    0xB2, 0xB3, 0,    0,    0,    b'{', b'[', b']', b'}', b'\\',0,    0,    0,
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'@', 0,    0x80, 0,    0,    0,    0,    0,    0,    0,    0,    b'~', 0,    0,    0,    0,
//  0x20-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0xB5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// QWERTZ dead keys
static QWERTZ_DEAD_BASE: [(u8, DeadKey); 1] = [(0x29, DeadKey::Circumflex)];
static QWERTZ_DEAD_SHIFT: [(u8, DeadKey); 1] = [(0x29, DeadKey::Ring)];

static LAYOUT_QWERTZ: LayoutInfo = LayoutInfo::with_dead_keys(
    Layout::Qwertz,
    &QWERTZ,
    &QWERTZ_SHIFT,
    &QWERTZ_ALTGR,
    &QWERTZ_DEAD_BASE,
    &QWERTZ_DEAD_SHIFT,
);

// ============================================================================
// Layout Data - UK QWERTY
// ============================================================================

/// UK QWERTY base layer (ISO layout)
pub static UK_QWERTY: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0,   b'a', b's',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'',b'`', 0,    b'#', b'z', b'x', b'c', b'v',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'b', b'n', b'm', b',', b'.', b'/', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// UK QWERTY shift layer
pub static UK_QWERTY_SHIFT: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'!', b'"', 0xA3, b'$', b'%', b'^', b'&', b'*', b'(', b')', b'_', b'+', 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'{', b'}', b'\n', 0,   b'A', b'S',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':', b'@', 0xAC, 0,    b'~', b'Z', b'X', b'C', b'V',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'B', b'N', b'M', b'<', b'>', b'?', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// UK QWERTY AltGr layer
static UK_QWERTY_ALTGR: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    0,    0,    0,    0,    0x80, 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
//  0x10-0x7F: mostly empty except for a few characters
    0, 0, 0xE9, 0, 0, 0, 0xFA, 0xED, 0xF3, 0, 0, 0, 0, 0, 0xE1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static LAYOUT_UK_QWERTY: LayoutInfo = LayoutInfo::new(
    Layout::UkQwerty,
    &UK_QWERTY,
    &UK_QWERTY_SHIFT,
    &UK_QWERTY_ALTGR,
);

// ============================================================================
// Layout Data - Spanish QWERTY
// ============================================================================

/// Spanish QWERTY base layer
pub static SPANISH: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'\'',0xA1, 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'`', b'+', b'\n', 0,   b'a', b's',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', 0xF1, 0xB4, 0xBA, 0,    0xE7, b'z', b'x', b'c', b'v',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'b', b'n', b'm', b',', b'.', b'-', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Spanish QWERTY shift layer
pub static SPANISH_SHIFT: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    27,   b'!', b'"', 0xB7, b'$', b'%', b'&', b'/', b'(', b')', b'=', b'?', 0xBF, 8,    b'\t',
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', b'^', b'*', b'\n', 0,   b'A', b'S',
//  0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27  0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', 0xD1, 0xA8, 0xAA, 0,    0xC7, b'Z', b'X', b'C', b'V',
//  0x30  0x31  0x32  0x33  0x34  0x35  0x36  0x37  0x38  0x39  0x3A  0x3B  0x3C  0x3D  0x3E  0x3F
    b'B', b'N', b'M', b';', b':', b'_', 0,    b'*', 0,    b' ', 0,    0,    0,    0,    0,    0,
//  0x40-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Spanish QWERTY AltGr layer
static SPANISH_ALTGR: [u8; 128] = [
//  0x00  0x01  0x02  0x03  0x04  0x05  0x06  0x07  0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
    0,    0,    b'|', b'@', b'#', b'~', 0x80, 0xAC, 0,    0,    0,    0,    0,    0,    0,    0,
//  0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17  0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
    0,    0,    0x80, 0,    0,    0,    0,    0,    0,    0,    b'[', b']', 0,    0,    0,    0,
//  0x20-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, b'{', 0, 0, b'}', 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Spanish dead keys
static SPANISH_DEAD_BASE: [(u8, DeadKey); 2] = [(0x1A, DeadKey::Grave), (0x28, DeadKey::Acute)];
static SPANISH_DEAD_SHIFT: [(u8, DeadKey); 2] = [(0x1A, DeadKey::Circumflex), (0x28, DeadKey::Diaeresis)];

static LAYOUT_SPANISH: LayoutInfo = LayoutInfo::with_dead_keys(
    Layout::Spanish,
    &SPANISH,
    &SPANISH_SHIFT,
    &SPANISH_ALTGR,
    &SPANISH_DEAD_BASE,
    &SPANISH_DEAD_SHIFT,
);

// ============================================================================
// Legacy API
// ============================================================================

/// Gets ASCII mapping for a layout (legacy API)
pub fn get_ascii_mapping(layout: Layout) -> &'static [u8; 128] {
    get_layout_info_for(layout).base
}

/// Gets shifted ASCII mapping for a layout (legacy API)
pub fn get_shifted_mapping(layout: Layout) -> &'static [u8; 128] {
    get_layout_info_for(layout).shift
}

/// Gets AltGr ASCII mapping for a layout
pub fn get_altgr_mapping(layout: Layout) -> &'static [u8; 128] {
    get_layout_info_for(layout).altgr
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_us_qwerty_mapping() {
        assert_eq!(US_QWERTY[0x02], b'1');
        assert_eq!(US_QWERTY[0x1E], b'a');
        assert_eq!(US_QWERTY[0x39], b' ');
    }

    #[test]
    fn test_us_qwerty_shift() {
        assert_eq!(US_QWERTY_SHIFT[0x02], b'!');
        assert_eq!(US_QWERTY_SHIFT[0x1E], b'A');
        assert_eq!(US_QWERTY_SHIFT[0x03], b'@');
    }

    #[test]
    fn test_dvorak_mapping() {
        assert_eq!(DVORAK[0x02], b'1');
        assert_eq!(DVORAK[0x1E], b'a');
        assert_eq!(DVORAK[0x12], b'.'); // 'e' position in QWERTY is '.' in Dvorak
    }

    #[test]
    fn test_colemak_mapping() {
        assert_eq!(COLEMAK[0x02], b'1');
        assert_eq!(COLEMAK[0x1E], b'a');
        assert_eq!(COLEMAK[0x12], b'f'); // 'e' position in QWERTY is 'f' in Colemak
    }

    #[test]
    fn test_get_set_layout() {
        set_layout(Layout::Dvorak);
        assert_eq!(get_layout(), Layout::Dvorak);
        set_layout(Layout::UsQwerty);
        assert_eq!(get_layout(), Layout::UsQwerty);
    }

    #[test]
    fn test_layout_from_u8() {
        assert_eq!(Layout::from_u8(0), Some(Layout::UsQwerty));
        assert_eq!(Layout::from_u8(1), Some(Layout::Dvorak));
        assert_eq!(Layout::from_u8(4), Some(Layout::Qwertz));
        assert_eq!(Layout::from_u8(99), None);
    }

    #[test]
    fn test_layout_name() {
        assert_eq!(Layout::UsQwerty.name(), "US QWERTY");
        assert_eq!(Layout::Dvorak.name(), "Dvorak");
        assert_eq!(Layout::Qwertz.name(), "QWERTZ (German)");
    }

    #[test]
    fn test_layout_language_code() {
        assert_eq!(Layout::UsQwerty.language_code(), "en");
        assert_eq!(Layout::Azerty.language_code(), "fr");
        assert_eq!(Layout::Qwertz.language_code(), "de");
        assert_eq!(Layout::Spanish.language_code(), "es");
    }

    #[test]
    fn test_dead_key_compose() {
        assert_eq!(DeadKey::Acute.compose(b'e'), Some(0xE9)); // é
        assert_eq!(DeadKey::Acute.compose(b'a'), Some(0xE1)); // á
        assert_eq!(DeadKey::Grave.compose(b'e'), Some(0xE8)); // è
        assert_eq!(DeadKey::Diaeresis.compose(b'u'), Some(0xFC)); // ü
        assert_eq!(DeadKey::Tilde.compose(b'n'), Some(0xF1)); // ñ
        assert_eq!(DeadKey::Cedilla.compose(b'c'), Some(0xE7)); // ç
    }

    #[test]
    fn test_dead_key_invalid() {
        assert_eq!(DeadKey::Acute.compose(b'x'), None);
        assert_eq!(DeadKey::Cedilla.compose(b'a'), None);
    }

    #[test]
    fn test_dead_key_space() {
        assert_eq!(DeadKey::Acute.compose(b' '), Some(0xB4));
        assert_eq!(DeadKey::Grave.compose(b' '), Some(b'`'));
        assert_eq!(DeadKey::Circumflex.compose(b' '), Some(b'^'));
    }

    #[test]
    fn test_layout_info_lookup() {
        let info = get_layout_info_for(Layout::UsQwerty);
        assert_eq!(info.lookup(0x1E, false, false), b'a');
        assert_eq!(info.lookup(0x1E, true, false), b'A');
    }

    #[test]
    fn test_layout_has_altgr() {
        assert!(!Layout::UsQwerty.has_altgr());
        assert!(Layout::Azerty.has_altgr());
        assert!(Layout::Qwertz.has_altgr());
        assert!(Layout::Spanish.has_altgr());
    }

    #[test]
    fn test_layout_has_dead_keys() {
        assert!(!Layout::UsQwerty.has_dead_keys());
        assert!(Layout::Azerty.has_dead_keys());
        assert!(Layout::Qwertz.has_dead_keys());
        assert!(Layout::Spanish.has_dead_keys());
    }

    #[test]
    fn test_dead_key_state() {
        clear_pending_dead_key();
        assert!(!has_pending_dead_key());

        set_pending_dead_key(DeadKey::Acute);
        assert!(has_pending_dead_key());

        let dk = take_pending_dead_key();
        assert_eq!(dk, Some(DeadKey::Acute));
        assert!(!has_pending_dead_key());
    }

    #[test]
    fn test_process_with_dead_key() {
        clear_pending_dead_key();
        set_pending_dead_key(DeadKey::Acute);
        assert_eq!(process_with_dead_key(b'e'), 0xE9); // é

        // Without dead key, should return original
        assert_eq!(process_with_dead_key(b'e'), b'e');
    }

    #[test]
    fn test_all_layouts() {
        let layouts = Layout::all();
        assert_eq!(layouts.len(), Layout::COUNT);
        assert_eq!(layouts[0], Layout::UsQwerty);
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(LayoutError::NotFound.as_str(), "layout not found");
        assert_eq!(LayoutError::InvalidScanCode.as_str(), "invalid scan code");
    }
}
