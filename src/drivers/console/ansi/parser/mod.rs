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

mod csi;
mod dec;

use super::super::constants::*;
use super::action::AnsiAction;
use super::types::ParserState;

#[derive(Clone, Debug)]
pub struct AnsiParser {
    pub(crate) state: ParserState,
    pub(crate) p1: usize,
    pub(crate) p2: usize,
    pub(crate) have_p1: bool,
    pub(crate) have_p2: bool,
}

impl AnsiParser {
    pub const fn new() -> Self {
        Self { state: ParserState::Normal, p1: 0, p2: 0, have_p1: false, have_p2: false }
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

    pub fn process_str<'a>(&'a mut self, s: &'a str) -> impl Iterator<Item = AnsiAction> + 'a {
        s.bytes().filter_map(move |b| self.process(b))
    }
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}
