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

//! VGA console data types.

use core::sync::atomic::{AtomicU64, Ordering};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Black = 0x0,
    Blue = 0x1,
    Green = 0x2,
    Cyan = 0x3,
    Red = 0x4,
    Magenta = 0x5,
    Brown = 0x6,
    LightGrey = 0x7,
    DarkGrey = 0x8,
    LightBlue = 0x9,
    LightGreen = 0xA,
    LightCyan = 0xB,
    LightRed = 0xC,
    Pink = 0xD,
    Yellow = 0xE,
    White = 0xF,
}

impl Color {
    pub const fn from_ansi(code: u8) -> Self {
        match code {
            0 => Color::Black,
            1 => Color::Red,
            2 => Color::Green,
            3 => Color::Brown,
            4 => Color::Blue,
            5 => Color::Magenta,
            6 => Color::Cyan,
            _ => Color::LightGrey,
        }
    }

    pub const fn from_ansi_bright(code: u8) -> Self {
        match code {
            0 => Color::DarkGrey,
            1 => Color::LightRed,
            2 => Color::LightGreen,
            3 => Color::Yellow,
            4 => Color::LightBlue,
            5 => Color::Pink,
            6 => Color::LightCyan,
            _ => Color::White,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x0 => Color::Black,
            0x1 => Color::Blue,
            0x2 => Color::Green,
            0x3 => Color::Cyan,
            0x4 => Color::Red,
            0x5 => Color::Magenta,
            0x6 => Color::Brown,
            0x7 => Color::LightGrey,
            0x8 => Color::DarkGrey,
            0x9 => Color::LightBlue,
            0xA => Color::LightGreen,
            0xB => Color::LightCyan,
            0xC => Color::LightRed,
            0xD => Color::Pink,
            0xE => Color::Yellow,
            0xF => Color::White,
            _ => Color::LightGrey,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn bright(self) -> Self {
        match self {
            Color::Black => Color::DarkGrey,
            Color::Blue => Color::LightBlue,
            Color::Green => Color::LightGreen,
            Color::Cyan => Color::LightCyan,
            Color::Red => Color::LightRed,
            Color::Magenta => Color::Pink,
            Color::Brown => Color::Yellow,
            Color::LightGrey => Color::White,
            other => other,
        }
    }

    pub const fn dim(self) -> Self {
        match self {
            Color::DarkGrey => Color::Black,
            Color::LightBlue => Color::Blue,
            Color::LightGreen => Color::Green,
            Color::LightCyan => Color::Cyan,
            Color::LightRed => Color::Red,
            Color::Pink => Color::Magenta,
            Color::Yellow => Color::Brown,
            Color::White => Color::LightGrey,
            other => other,
        }
    }

    #[inline]
    pub const fn is_bright(self) -> bool {
        (self as u8) >= 0x08
    }

    pub const fn name(self) -> &'static str {
        match self {
            Color::Black => "Black",
            Color::Blue => "Blue",
            Color::Green => "Green",
            Color::Cyan => "Cyan",
            Color::Red => "Red",
            Color::Magenta => "Magenta",
            Color::Brown => "Brown",
            Color::LightGrey => "LightGrey",
            Color::DarkGrey => "DarkGrey",
            Color::LightBlue => "LightBlue",
            Color::LightGreen => "LightGreen",
            Color::LightCyan => "LightCyan",
            Color::LightRed => "LightRed",
            Color::Pink => "Pink",
            Color::Yellow => "Yellow",
            Color::White => "White",
        }
    }
}

impl Default for Color {
    fn default() -> Self {
        Color::LightGrey
    }
}

#[inline]
pub(super) const fn make_color(fg: Color, bg: Color) -> u8 {
    ((bg as u8) << 4) | (fg as u8 & 0x0F)
}

#[inline]
pub(super) const fn fg_from_attr(attr: u8) -> u8 {
    attr & 0x0F
}

#[inline]
pub(super) const fn bg_from_attr(attr: u8) -> u8 {
    (attr >> 4) & 0x0F
}

#[inline]
pub(super) const fn set_fg(attr: u8, fg: Color) -> u8 {
    (attr & 0xF0) | (fg as u8 & 0x0F)
}

#[inline]
pub(super) const fn set_bg(attr: u8, bg: Color) -> u8 {
    ((bg as u8) << 4) | (attr & 0x0F)
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VgaCell {
    pub ascii: u8,
    pub color: u8,
}

impl VgaCell {
    #[inline]
    pub const fn new(ascii: u8, color: u8) -> Self {
        Self { ascii, color }
    }

    #[inline]
    pub const fn blank(color: u8) -> Self {
        Self { ascii: b' ', color }
    }

    #[inline]
    pub const fn with_colors(ascii: u8, fg: Color, bg: Color) -> Self {
        Self {
            ascii,
            color: make_color(fg, bg),
        }
    }

    #[inline]
    pub const fn fg(&self) -> Color {
        Color::from_u8(self.color & 0x0F)
    }

    #[inline]
    pub const fn bg(&self) -> Color {
        Color::from_u8((self.color >> 4) & 0x07)
    }

    #[inline]
    pub const fn is_blank(&self) -> bool {
        self.ascii == b' '
    }

    #[inline]
    pub const fn as_u16(&self) -> u16 {
        (self.color as u16) << 8 | (self.ascii as u16)
    }

    #[inline]
    pub const fn from_u16(value: u16) -> Self {
        Self {
            ascii: (value & 0xFF) as u8,
            color: ((value >> 8) & 0xFF) as u8,
        }
    }
}

impl Default for VgaCell {
    fn default() -> Self {
        Self::blank(make_color(Color::LightGrey, Color::Black))
    }
}

impl core::fmt::Debug for VgaCell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let ascii = { self.ascii };
        let color = { self.color };
        f.debug_struct("VgaCell")
            .field("ascii", &(ascii as char))
            .field("color", &color)
            .field("fg", &Color::from_u8(color & 0x0F).name())
            .field("bg", &Color::from_u8((color >> 4) & 0x07).name())
            .finish()
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
}

impl LogLevel {
    pub const fn color(&self) -> Color {
        match self {
            LogLevel::Trace => Color::DarkGrey,
            LogLevel::Debug => Color::LightGrey,
            LogLevel::Info => Color::White,
            LogLevel::Warning => Color::Yellow,
            LogLevel::Error => Color::LightRed,
            LogLevel::Critical => Color::Red,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRIT",
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

#[derive(Debug)]
pub struct ConsoleStats {
    pub messages_written: AtomicU64,
    pub bytes_written: AtomicU64,
    pub errors: AtomicU64,
    pub uptime_ticks: AtomicU64,
}

impl ConsoleStats {
    pub const fn new() -> Self {
        Self {
            messages_written: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            uptime_ticks: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn inc_messages(&self) {
        self.messages_written.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_bytes(&self, count: u64) {
        self.bytes_written.fetch_add(count, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ConsoleStatsSnapshot {
        ConsoleStatsSnapshot {
            messages_written: self.messages_written.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            uptime_ticks: self.uptime_ticks.load(Ordering::Relaxed),
        }
    }
}

impl Default for ConsoleStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConsoleStatsSnapshot {
    pub messages_written: u64,
    pub bytes_written: u64,
    pub errors: u64,
    pub uptime_ticks: u64,
}
