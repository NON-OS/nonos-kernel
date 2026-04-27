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

use super::super::action::AnsiAction;
use super::super::types::{inc_ignored, inc_parsed, ParserState};
use super::AnsiParser;

impl AnsiParser {
    pub(super) fn process_dec_private(&mut self, byte: u8) -> Option<AnsiAction> {
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
                        inc_parsed();
                        Some(AnsiAction::ShowCursor)
                    }
                    _ => {
                        inc_ignored();
                        None
                    }
                }
            }
            b'l' => {
                self.state = ParserState::Normal;
                let mode = if self.have_p1 { self.p1 } else { 0 };
                match mode {
                    25 => {
                        inc_parsed();
                        Some(AnsiAction::HideCursor)
                    }
                    _ => {
                        inc_ignored();
                        None
                    }
                }
            }
            _ => {
                self.state = ParserState::Normal;
                inc_ignored();
                None
            }
        }
    }
}
