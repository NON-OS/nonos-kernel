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

//! ANSI escape sequence parser.

use core::sync::atomic::{AtomicU64, Ordering};

use super::types::Color;
use super::constants::*;

static SEQUENCES_PARSED: AtomicU64 = AtomicU64::new(0);

static SEQUENCES_IGNORED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParserState {
    Normal,
    Escape,
    Csi,
    DecPrivate,
}

impl Default for ParserState {
    fn default() -> Self {
        ParserState::Normal
    }
}

#[derive(Clone, Debug)]
pub struct AnsiParser {
    state: ParserState,
    p1: usize,
    p2: usize,
    have_p1: bool,
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

    pub fn reset(&mut self) {
        self.state = ParserState::Normal;
        self.p1 = 0;
        self.p2 = 0;
        self.have_p1 = false;
        self.have_p2 = false;
    }

    #[inline]
    pub fn state(&self) -> ParserState {
        self.state
    }

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
                    self.state = ParserState::Csi;
                    self.p1 = 0;
                    self.p2 = 0;
                    self.have_p1 = false;
                    self.have_p2 = false;
                    None
                } else {
                    self.state = ParserState::Normal;
                    Some(AnsiAction::Print(byte))
                }
            }

            ParserState::Csi => self.process_csi(byte),
            ParserState::DecPrivate => self.process_dec_private(byte),
        }
    }

    fn process_csi(&mut self, byte: u8) -> Option<AnsiAction> {
        match byte {
            b'?' => {
                self.state = ParserState::DecPrivate;
                self.p1 = 0;
                self.p2 = 0;
                self.have_p1 = false;
                self.have_p2 = false;
                None
            }

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

            b';' => {
                if !self.have_p1 {
                    self.have_p1 = true;
                }
                self.have_p2 = true;
                None
            }

            b'm' => {
                self.state = ParserState::Normal;
                let p = if self.have_p1 { self.p1 } else { 0 };
                Some(AnsiAction::Sgr(p, if self.have_p2 { Some(self.p2) } else { None }))
            }

            b'H' => {
                self.state = ParserState::Normal;
                let row = if self.have_p1 { self.p1.max(1) } else { 1 };
                let col = if self.have_p2 { self.p2.max(1) } else { 1 };
                Some(AnsiAction::CursorPosition(row - 1, col - 1))
            }

            b'J' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                Some(AnsiAction::EraseDisplay(mode))
            }

            b'K' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                Some(AnsiAction::EraseLine(mode))
            }

            b'A' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorUp(n))
            }

            b'B' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorDown(n))
            }

            b'C' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorForward(n))
            }

            b'D' => {
                self.state = ParserState::Normal;
                let n = if self.have_p1 { self.p1.max(1) } else { 1 };
                Some(AnsiAction::CursorBack(n))
            }

            b's' => {
                self.state = ParserState::Normal;
                SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                Some(AnsiAction::SaveCursor)
            }

            b'u' => {
                self.state = ParserState::Normal;
                SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                Some(AnsiAction::RestoreCursor)
            }

            _ => {
                self.state = ParserState::Normal;
                SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn process_dec_private(&mut self, byte: u8) -> Option<AnsiAction> {
        match byte {
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

            b';' => {
                if !self.have_p1 {
                    self.have_p1 = true;
                }
                self.have_p2 = true;
                None
            }

            b'h' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                match mode {
                    25 => {
                        SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                        Some(AnsiAction::ShowCursor)
                    }
                    _ => {
                        SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }

            b'l' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                match mode {
                    25 => {
                        SEQUENCES_PARSED.fetch_add(1, Ordering::Relaxed);
                        Some(AnsiAction::HideCursor)
                    }
                    _ => {
                        SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }

            _ => {
                self.state = ParserState::Normal;
                SEQUENCES_IGNORED.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn process_str<'a>(&'a mut self, s: &'a str) -> impl Iterator<Item = AnsiAction> + 'a {
        s.bytes().filter_map(move |b| self.process(b))
    }
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnsiAction {
    Print(u8),
    Sgr(usize, Option<usize>),
    CursorPosition(usize, usize),
    EraseDisplay(usize),
    EraseLine(usize),
    CursorUp(usize),
    CursorDown(usize),
    CursorForward(usize),
    CursorBack(usize),
    SaveCursor,
    RestoreCursor,
    ShowCursor,
    HideCursor,
}

impl AnsiAction {
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

    pub const fn is_sgr_action(&self) -> bool {
        matches!(self, AnsiAction::Sgr(_, _))
    }

    pub const fn is_erase_action(&self) -> bool {
        matches!(self, AnsiAction::EraseDisplay(_) | AnsiAction::EraseLine(_))
    }
}

pub fn apply_sgr(current: u8, sgr: usize) -> u8 {
    match sgr {
        0 => super::types::make_color(Color::LightGrey, Color::Black),

        30..=37 => {
            let fg = Color::from_ansi((sgr - 30) as u8);
            super::types::set_fg(current, fg)
        }

        40..=47 => {
            let bg = Color::from_ansi((sgr - 40) as u8);
            super::types::set_bg(current, bg)
        }

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

        1 => {
            let fg = current & 0x0F;
            let bright_fg = fg | 0x08;
            (current & 0xF0) | bright_fg
        }

        _ => current,
    }
}
