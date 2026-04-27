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
    pub(super) fn process_csi(&mut self, byte: u8) -> Option<AnsiAction> {
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
                Some(AnsiAction::EraseDisplay(if self.have_p1 { self.p1 } else { 0 }))
            }
            b'K' => {
                self.state = ParserState::Normal;
                Some(AnsiAction::EraseLine(if self.have_p1 { self.p1 } else { 0 }))
            }
            b'A' => {
                self.state = ParserState::Normal;
                Some(AnsiAction::CursorUp(if self.have_p1 { self.p1.max(1) } else { 1 }))
            }
            b'B' => {
                self.state = ParserState::Normal;
                Some(AnsiAction::CursorDown(if self.have_p1 { self.p1.max(1) } else { 1 }))
            }
            b'C' => {
                self.state = ParserState::Normal;
                Some(AnsiAction::CursorForward(if self.have_p1 { self.p1.max(1) } else { 1 }))
            }
            b'D' => {
                self.state = ParserState::Normal;
                Some(AnsiAction::CursorBack(if self.have_p1 { self.p1.max(1) } else { 1 }))
            }
            b's' => {
                self.state = ParserState::Normal;
                inc_parsed();
                Some(AnsiAction::SaveCursor)
            }
            b'u' => {
                self.state = ParserState::Normal;
                inc_parsed();
                Some(AnsiAction::RestoreCursor)
            }
            _ => {
                self.state = ParserState::Normal;
                inc_ignored();
                None
            }
        }
    }
}
