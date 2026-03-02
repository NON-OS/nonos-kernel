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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motion {
    Left,
    Right,
    Up,
    Down,
    WordForward,
    WordBackward,
    WordEnd,
    BigWordForward,
    BigWordBackward,
    BigWordEnd,
    LineStart,
    LineEnd,
    FirstNonWhitespace,
    FileStart,
    FileEnd,
    LineNumber(usize),
    ScreenTop,
    ScreenMiddle,
    ScreenBottom,
    ParagraphForward,
    ParagraphBackward,
    MatchingBracket,
    FindChar(char, bool),
    TillChar(char, bool),
    Column(usize),
}

#[derive(Debug, Clone, Copy)]
pub struct MotionResult {
    pub row: usize,
    pub col: usize,
    pub inclusive: bool,
    pub linewise: bool,
}

impl MotionResult {
    pub fn new(row: usize, col: usize) -> Self {
        Self {
            row,
            col,
            inclusive: false,
            linewise: false,
        }
    }

    pub fn inclusive(mut self) -> Self {
        self.inclusive = true;
        self
    }

    pub fn linewise(mut self) -> Self {
        self.linewise = true;
        self
    }
}
