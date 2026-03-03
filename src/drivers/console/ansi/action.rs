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
