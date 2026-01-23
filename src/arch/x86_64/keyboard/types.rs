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

pub type ScanCode = u8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum KeyCode {
    A, B, C, D, E, F, G, H, I, J, K, L, M,
    N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
    Num0, Num1, Num2, Num3, Num4, Num5, Num6, Num7, Num8, Num9,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    Escape, Backspace, Tab, Enter, Space,
    LeftShift, RightShift, LeftCtrl, RightCtrl, LeftAlt, RightAlt,
    LeftSuper, RightSuper,
    CapsLock, NumLock, ScrollLock,
    Insert, Delete, Home, End, PageUp, PageDown,
    ArrowUp, ArrowDown, ArrowLeft, ArrowRight,
    Minus, Equals, LeftBracket, RightBracket, Backslash,
    Semicolon, Quote, Backtick, Comma, Period, Slash,
    Numpad0, Numpad1, Numpad2, Numpad3, Numpad4,
    Numpad5, Numpad6, Numpad7, Numpad8, Numpad9,
    NumpadPlus, NumpadMinus, NumpadMultiply, NumpadDivide,
    NumpadEnter, NumpadDecimal,
    PrintScreen, Pause, Menu,
    #[default]
    Unknown = 0xFF,
}

impl KeyCode {
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::LeftShift | Self::RightShift |
            Self::LeftCtrl | Self::RightCtrl |
            Self::LeftAlt | Self::RightAlt |
            Self::LeftSuper | Self::RightSuper
        )
    }

    pub const fn is_lock(self) -> bool {
        matches!(self, Self::CapsLock | Self::NumLock | Self::ScrollLock)
    }

    pub const fn is_letter(self) -> bool {
        matches!(
            self,
            Self::A | Self::B | Self::C | Self::D | Self::E |
            Self::F | Self::G | Self::H | Self::I | Self::J |
            Self::K | Self::L | Self::M | Self::N | Self::O |
            Self::P | Self::Q | Self::R | Self::S | Self::T |
            Self::U | Self::V | Self::W | Self::X | Self::Y | Self::Z
        )
    }

    pub const fn is_number(self) -> bool {
        matches!(
            self,
            Self::Num0 | Self::Num1 | Self::Num2 | Self::Num3 | Self::Num4 |
            Self::Num5 | Self::Num6 | Self::Num7 | Self::Num8 | Self::Num9
        )
    }

    pub const fn is_function(self) -> bool {
        matches!(
            self,
            Self::F1 | Self::F2 | Self::F3 | Self::F4 | Self::F5 | Self::F6 |
            Self::F7 | Self::F8 | Self::F9 | Self::F10 | Self::F11 | Self::F12
        )
    }

    pub const fn is_numpad(self) -> bool {
        matches!(
            self,
            Self::Numpad0 | Self::Numpad1 | Self::Numpad2 | Self::Numpad3 |
            Self::Numpad4 | Self::Numpad5 | Self::Numpad6 | Self::Numpad7 |
            Self::Numpad8 | Self::Numpad9 | Self::NumpadPlus | Self::NumpadMinus |
            Self::NumpadMultiply | Self::NumpadDivide | Self::NumpadEnter | Self::NumpadDecimal
        )
    }

    pub const fn is_navigation(self) -> bool {
        matches!(
            self,
            Self::ArrowUp | Self::ArrowDown | Self::ArrowLeft | Self::ArrowRight |
            Self::Home | Self::End | Self::PageUp | Self::PageDown |
            Self::Insert | Self::Delete
        )
    }

    pub const fn is_printable(self) -> bool {
        self.is_letter() || self.is_number() || matches!(
            self,
            Self::Space | Self::Minus | Self::Equals | Self::LeftBracket |
            Self::RightBracket | Self::Backslash | Self::Semicolon | Self::Quote |
            Self::Backtick | Self::Comma | Self::Period | Self::Slash
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modifiers {
    bits: u8,
}

impl Modifiers {
    pub const NONE: Self = Self { bits: 0 };
    pub const SHIFT: u8 = 1 << 0;
    pub const CTRL: u8 = 1 << 1;
    pub const ALT: u8 = 1 << 2;
    pub const SUPER: u8 = 1 << 3;
    pub const CAPS_LOCK: u8 = 1 << 4;
    pub const NUM_LOCK: u8 = 1 << 5;
    pub const SCROLL_LOCK: u8 = 1 << 6;
    pub const ALTGR: u8 = 1 << 7;

    #[inline]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    #[inline]
    pub const fn shift(self) -> bool {
        (self.bits & Self::SHIFT) != 0
    }

    #[inline]
    pub const fn ctrl(self) -> bool {
        (self.bits & Self::CTRL) != 0
    }

    #[inline]
    pub const fn alt(self) -> bool {
        (self.bits & Self::ALT) != 0
    }

    #[inline]
    pub const fn super_key(self) -> bool {
        (self.bits & Self::SUPER) != 0
    }

    #[inline]
    pub const fn caps_lock(self) -> bool {
        (self.bits & Self::CAPS_LOCK) != 0
    }

    #[inline]
    pub const fn num_lock(self) -> bool {
        (self.bits & Self::NUM_LOCK) != 0
    }

    #[inline]
    pub const fn scroll_lock(self) -> bool {
        (self.bits & Self::SCROLL_LOCK) != 0
    }

    #[inline]
    pub const fn altgr(self) -> bool {
        (self.bits & Self::ALTGR) != 0
    }

    #[inline]
    pub const fn effective_shift(self) -> bool {
        let shift = (self.bits & Self::SHIFT) != 0;
        let caps = (self.bits & Self::CAPS_LOCK) != 0;
        shift ^ caps
    }

    #[inline]
    pub fn set(&mut self, flag: u8) {
        self.bits |= flag;
    }

    #[inline]
    pub fn clear(&mut self, flag: u8) {
        self.bits &= !flag;
    }

    #[inline]
    pub fn toggle(&mut self, flag: u8) {
        self.bits ^= flag;
    }

    #[inline]
    pub const fn contains(self, flag: u8) -> bool {
        (self.bits & flag) == flag
    }

    pub const fn with_shift(self) -> Self {
        Self { bits: self.bits | Self::SHIFT }
    }

    pub const fn with_ctrl(self) -> Self {
        Self { bits: self.bits | Self::CTRL }
    }

    pub const fn with_alt(self) -> Self {
        Self { bits: self.bits | Self::ALT }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedState {
    bits: u8,
}

impl LedState {
    pub const NONE: Self = Self { bits: 0 };
    pub const SCROLL_LOCK: u8 = 1 << 0;
    pub const NUM_LOCK: u8 = 1 << 1;
    pub const CAPS_LOCK: u8 = 1 << 2;

    #[inline]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits: bits & 0x07 }
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    #[inline]
    pub const fn scroll_lock(self) -> bool {
        (self.bits & Self::SCROLL_LOCK) != 0
    }

    #[inline]
    pub const fn num_lock(self) -> bool {
        (self.bits & Self::NUM_LOCK) != 0
    }

    #[inline]
    pub const fn caps_lock(self) -> bool {
        (self.bits & Self::CAPS_LOCK) != 0
    }

    #[inline]
    pub fn set(&mut self, flag: u8) {
        self.bits |= flag & 0x07;
    }

    #[inline]
    pub fn clear(&mut self, flag: u8) {
        self.bits &= !flag;
    }

    #[inline]
    pub fn toggle(&mut self, flag: u8) {
        self.bits ^= flag & 0x07;
    }

    pub fn from_modifiers(mods: Modifiers) -> Self {
        let mut leds = Self::new();
        if mods.caps_lock() {
            leds.set(Self::CAPS_LOCK);
        }
        if mods.num_lock() {
            leds.set(Self::NUM_LOCK);
        }
        if mods.scroll_lock() {
            leds.set(Self::SCROLL_LOCK);
        }
        leds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMapping {
    pub keycode: KeyCode,
    pub ascii: u8,
    pub shifted_ascii: u8,
    pub extended: bool,
    pub printable: bool,
}

impl KeyMapping {
    pub const fn new(keycode: KeyCode, ascii: u8, shifted: u8, extended: bool, printable: bool) -> Self {
        Self {
            keycode,
            ascii,
            shifted_ascii: shifted,
            extended,
            printable,
        }
    }

    pub const fn non_printable(keycode: KeyCode, extended: bool) -> Self {
        Self {
            keycode,
            ascii: 0,
            shifted_ascii: 0,
            extended,
            printable: false,
        }
    }

    pub const fn unknown() -> Self {
        Self {
            keycode: KeyCode::Unknown,
            ascii: 0,
            shifted_ascii: 0,
            extended: false,
            printable: false,
        }
    }

    pub fn get_ascii(&self, modifiers: Modifiers) -> Option<u8> {
        if !self.printable {
            return None;
        }

        if modifiers.ctrl() {
            return self.ctrl_char();
        }

        let shifted = if self.keycode.is_letter() {
            modifiers.effective_shift()
        } else {
            modifiers.shift()
        };

        let ch = if shifted { self.shifted_ascii } else { self.ascii };
        if ch == 0 { None } else { Some(ch) }
    }

    fn ctrl_char(&self) -> Option<u8> {
        match self.ascii {
            b'a'..=b'z' => Some(self.ascii - b'a' + 1),
            b'[' => Some(0x1B),
            b'\\' => Some(0x1C),
            b']' => Some(0x1D),
            b'^' => Some(0x1E),
            b'_' => Some(0x1F),
            b'?' => Some(0x7F),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MouseButton {
    Left = 0,
    Right = 1,
    Middle = 2,
    Button4 = 3,
    Button5 = 4,
}

impl MouseButton {
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Left),
            1 => Some(Self::Right),
            2 => Some(Self::Middle),
            3 => Some(Self::Button4),
            4 => Some(Self::Button5),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseButtons {
    bits: u8,
}

impl MouseButtons {
    pub const NONE: Self = Self { bits: 0 };
    pub const LEFT: u8 = 1 << 0;
    pub const RIGHT: u8 = 1 << 1;
    pub const MIDDLE: u8 = 1 << 2;
    pub const BUTTON4: u8 = 1 << 3;
    pub const BUTTON5: u8 = 1 << 4;

    #[inline]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    #[inline]
    pub const fn left(self) -> bool {
        (self.bits & Self::LEFT) != 0
    }

    #[inline]
    pub const fn right(self) -> bool {
        (self.bits & Self::RIGHT) != 0
    }

    #[inline]
    pub const fn middle(self) -> bool {
        (self.bits & Self::MIDDLE) != 0
    }

    #[inline]
    pub fn set(&mut self, button: MouseButton) {
        self.bits |= 1 << (button as u8);
    }

    #[inline]
    pub fn clear(&mut self, button: MouseButton) {
        self.bits &= !(1 << (button as u8));
    }

    #[inline]
    pub const fn is_pressed(self, button: MouseButton) -> bool {
        (self.bits & (1 << (button as u8))) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Keyboard,
    Mouse,
    Touchpad,
    Gamepad,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u16);

impl DeviceId {
    pub const INVALID: Self = Self(0xFFFF);
    pub const PS2_KEYBOARD: Self = Self(0x0001);
    pub const PS2_MOUSE: Self = Self(0x0002);
    pub const USB_BASE: u16 = 0x1000;

    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0xFFFF
    }

    pub const fn is_ps2(self) -> bool {
        self.0 < Self::USB_BASE
    }

    pub const fn is_usb(self) -> bool {
        self.0 >= Self::USB_BASE && self.0 != 0xFFFF
    }

    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::INVALID
    }
}
