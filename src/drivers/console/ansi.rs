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
//
//! Subset of ANSI/VT100 escape sequences for terminal control

use core::sync::atomic::{AtomicU64, Ordering};
use super::types::Color;
use super::constants::*;

// =============================================================================
// Statistics
// =============================================================================

/// Number of escape sequences successfully parsed.
static SEQUENCES_PARSED: AtomicU64 = AtomicU64::new(0);

/// Number of unknown/ignored sequences.
static SEQUENCES_IGNORED: AtomicU64 = AtomicU64::new(0);

/// Returns parsing statistics (parsed, ignored).
pub fn parser_stats() -> (u64, u64) {
    (
        SEQUENCES_PARSED.load(Ordering::Relaxed),
        SEQUENCES_IGNORED.load(Ordering::Relaxed),
    )
}

/// Resets parsing statistics.
pub fn reset_parser_stats() {
    SEQUENCES_PARSED.store(0, Ordering::Relaxed);
    SEQUENCES_IGNORED.store(0, Ordering::Relaxed);
}

/// ANSI parser state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParserState {
    /// Normal character processing.
    Normal,
    /// Received ESC, waiting for next character.
    Escape,
    /// In CSI sequence (ESC [), collecting parameters.
    Csi,
    /// In DEC private mode sequence (ESC [?), collecting parameters.
    DecPrivate,
}

impl Default for ParserState {
    fn default() -> Self {
        ParserState::Normal
    }
}

/// ANSI escape sequence parser.
///
/// Parses a minimal subset of ANSI escape sequences commonly used
/// for terminal color control and cursor positioning.
#[derive(Clone, Debug)]
pub struct AnsiParser {
    /// Current parser state.
    state: ParserState,
    /// First CSI parameter.
    p1: usize,
    /// Second CSI parameter.
    p2: usize,
    /// Whether p1 has been set.
    have_p1: bool,
    /// Whether p2 has been set (after semicolon).
    have_p2: bool,
}

impl AnsiParser {
    pub const fn new() -> Self {
        Self {
            state: ParserState::Normal,
            p1: 0,
            p2: 0,
            have_p1: false,
            have_p2: false,
        }
    }

    /// Resets the parser to normal state.
    pub fn reset(&mut self) {
        self.state = ParserState::Normal;
        self.p1 = 0;
        self.p2 = 0;
        self.have_p1 = false;
        self.have_p2 = false;
    }

    /// Returns the current parser state.
    #[inline]
    pub fn state(&self) -> ParserState {
        self.state
    }

    /// Processes a single byte through the parser.
    pub fn process(&mut self, byte: u8) -> Option<AnsiAction> {
        match self.state {
            ParserState::Normal => {
                if byte == ASCII_ESC {
                    self.state = ParserState::Escape;
                    None
                } else {
                    Some(AnsiAction::Print(byte))
                }
            }

            ParserState::Escape => {
                if byte == ASCII_LBRACKET {
                    // Start CSI sequence
                    self.state = ParserState::Csi;
                    self.p1 = 0;
                    self.p2 = 0;
                    self.have_p1 = false;
                    self.have_p2 = false;
                    None
                } else {
                    // Unknown escape, treat as literal
                    self.state = ParserState::Normal;
                    Some(AnsiAction::Print(byte))
                }
            }

            ParserState::Csi => self.process_csi(byte),
            ParserState::DecPrivate => self.process_dec_private(byte),
        }
    }

    /// Processes a byte within a CSI sequence.
    fn process_csi(&mut self, byte: u8) -> Option<AnsiAction> {
        match byte {
            // Question mark: enter DEC private mode
            b'?' => {
                self.state = ParserState::DecPrivate;
                self.p1 = 0;
                self.p2 = 0;
                self.have_p1 = false;
                self.have_p2 = false;
                None
            }

            // Digit: accumulate parameter
            b'0'..=b'9' => {
                let d = (byte - b'0') as usize;
                if !self.have_p2 {
                    // Still accumulating first parameter
                    self.p1 = self.p1.saturating_mul(10).saturating_add(d);
                    self.have_p1 = true;
                } else {
                    // After semicolon, accumulating second parameter
                    self.p2 = self.p2.saturating_mul(10).saturating_add(d);
                }
                None
            }

            // Semicolon: switch to second parameter
            b';' => {
                if !self.have_p1 {
                    self.have_p1 = true;
                }
                self.have_p2 = true;
                None
            }

            // SGR: Select Graphic Rendition (colors)
            b'm' => {
                self.state = ParserState::Normal;
                let p = if self.have_p1 { self.p1 } else { 0 };
                Some(AnsiAction::Sgr(p, if self.have_p2 { Some(self.p2) } else { None }))
            }

            // CUP: Cursor Position
            b'H' => {
                self.state = ParserState::Normal;
                let row = if self.have_p1 { self.p1.max(1) } else { 1 };
                let col = if self.have_p2 { self.p2.max(1) } else { 1 };
                Some(AnsiAction::CursorPosition(row - 1, col - 1))
            }

            // ED: Erase Display
            b'J' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                Some(AnsiAction::EraseDisplay(mode))
            }

            // EL: Erase Line
            b'K' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                Some(AnsiAction::EraseLine(mode))
            }

            // CUU: Cursor Up
            b'A' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorUp(n))
            }

            // CUD: Cursor Down
            b'B' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorDown(n))
            }

            // CUF: Cursor Forward (Right)
            b'C' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorForward(n))
            }

            // CUB: Cursor Back (Left)
            b'D' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorBack(n))
            }

            // Save cursor position (ESC[s)
            b's' => {
                self.state = ParserState::Normal;
                SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                Some(AnsiAction::SaveCursor)
            }

            // Restore cursor position (ESC[u)
            b'u' => {
                self.state = ParserState::Normal;
                SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                Some(AnsiAction::RestoreCursor)
            }

            // Unknown CSI command: ignore and return to normal
            _ => {
                self.state = ParserState::Normal;
                SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Processes a byte within a DEC private mode sequence (ESC[?...).
    ///
    /// Handles DEC private mode sequences like:
    /// - `ESC[?25h` - DECTCEM: Show cursor
    /// - `ESC[?25l` - DECTCEM: Hide cursor
    /// - `ESC[?7h` - DECAWM: Enable autowrap
    /// - `ESC[?7l` - DECAWM: Disable autowrap
    fn process_dec_private(&mut self, byte: u8) -> Option<AnsiAction> {
        match byte {
            // Digit: accumulate parameter
            b'0'..=b'9' => {
                let d = (byte - b'0') as usize;
                if !self.have_p2 {
                    self.p1 = self.p1.saturating_mul(10).saturating_add(d);
                    self.have_p1 = true;
                } else {
                    self.p2 = self.p2.saturating_mul(10).saturating_add(d);
                }
                None
            }

            // Semicolon: switch to second parameter
            b';' => {
                if !self.have_p1 {
                    self.have_p1 = true;
                }
                self.have_p2 = true;
                None
            }

            // 'h' - DEC private mode set
            b'h' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                match mode {
                    // DECTCEM: Show cursor
                    25 => {
                        SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                        Some(AnsiAction::ShowCursor)
                    }
                    // Other DEC private modes not currently supported
                    _ => {
                        SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }

            // 'l' - DEC private mode reset
            b'l' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                match mode {
                    // DECTCEM: Hide cursor
                    25 => {
                        SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                        Some(AnsiAction::HideCursor)
                    }
                    // Other DEC private modes not currently supported
                    _ => {
                        SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }

            // Unknown DEC private command: ignore and return to normal
            _ => {
                self.state = ParserState::Normal;
                SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Processes an entire string through the parser.
    /// This is a convenience method that processes each byte in sequence.
    /// Actions are yielded as they are parsed.
    pub fn process_str<'a>(&'a mut self, s: &'a str) -> impl Iterator<Item = AnsiAction> + 'a {
        s.bytes().filter_map(move |b| self.process(b))
    }
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Action resulting from ANSI sequence parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnsiAction {
    /// Print a regular character.
    Print(u8),
    /// SGR: Set colors/attributes. Contains primary param and optional secondary.
    Sgr(usize, Option<usize>),
    /// Set cursor position (0-indexed row, col).
    CursorPosition(usize, usize),
    /// Erase display (mode: 0=below, 1=above, 2=all).
    EraseDisplay(usize),
    /// Erase line (mode: 0=right, 1=left, 2=all).
    EraseLine(usize),
    /// Move cursor up N lines.
    CursorUp(usize),
    /// Move cursor down N lines.
    CursorDown(usize),
    /// Move cursor forward N columns.
    CursorForward(usize),
    /// Move cursor back N columns.
    CursorBack(usize),
    /// Save cursor position.
    SaveCursor,
    /// Restore cursor position.
    RestoreCursor,
    /// Show cursor.
    ShowCursor,
    /// Hide cursor.
    HideCursor,
}

impl AnsiAction {
    /// Returns true if this action modifies the cursor position.
    pub const fn is_cursor_action(&self) -> bool {
        matches!(
            self,
            AnsiAction::CursorPosition(_, _)
                | AnsiAction::CursorUp(_)
                | AnsiAction::CursorDown(_)
                | AnsiAction::CursorForward(_)
                | AnsiAction::CursorBack(_)
                | AnsiAction::SaveCursor
                | AnsiAction::RestoreCursor
        )
    }

    /// Returns true if this action modifies colors/attributes.
    pub const fn is_sgr_action(&self) -> bool {
        matches!(self, AnsiAction::Sgr(_, _))
    }

    /// Returns true if this action erases content.
    pub const fn is_erase_action(&self) -> bool {
        matches!(self, AnsiAction::EraseDisplay(_) | AnsiAction::EraseLine(_))
    }
}

/// Applies an SGR code to update the color attribute.
pub fn apply_sgr(current: u8, sgr: usize) -> u8 {
    match sgr {
        // Reset to default
        0 => super::types::make_color(Color::LightGrey, Color::Black),

        // Foreground colors (30-37)
        30..=37 => {
            let fg = Color::from_ansi((sgr - 30) as u8);
            super::types::set_fg(current, fg)
        }

        // Background colors (40-47)
        40..=47 => {
            let bg = Color::from_ansi((sgr - 40) as u8);
            super::types::set_bg(current, bg)
        }

        // Bright foreground (90-97)
        90..=97 => {
            let fg = match sgr - 90 {
                0 => Color::DarkGrey,
                1 => Color::LightRed,
                2 => Color::LightGreen,
                3 => Color::Yellow,
                4 => Color::LightBlue,
                5 => Color::Pink,
                6 => Color::LightCyan,
                _ => Color::White,
            };
            super::types::set_fg(current, fg)
        }

        // Bright background (100-107)
        100..=107 => {
            let bg = match sgr - 100 {
                0 => Color::DarkGrey,
                1 => Color::LightRed,
                2 => Color::LightGreen,
                3 => Color::Yellow,
                4 => Color::LightBlue,
                5 => Color::Pink,
                6 => Color::LightCyan,
                _ => Color::White,
            };
            super::types::set_bg(current, bg)
        }

        // Bold (1) - use bright foreground
        1 => {
            let fg = current & 0x0F;
            let bright_fg = fg | 0x08; // Set intensity bit
            (current & 0xF0) | bright_fg
        }

        // Unsupported: return unchanged
        _ => current,
    }
}
