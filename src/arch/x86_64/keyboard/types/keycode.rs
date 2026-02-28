// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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
