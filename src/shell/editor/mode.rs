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

//! Vi editor modes.

extern crate alloc;

use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Insert,
    Visual,
    VisualLine,
    VisualBlock,
    Command,
    Replace,
    Search,
}

impl Mode {
    pub fn display_name(&self) -> &'static str {
        match self {
            Mode::Normal => "NORMAL",
            Mode::Insert => "INSERT",
            Mode::Visual => "VISUAL",
            Mode::VisualLine => "V-LINE",
            Mode::VisualBlock => "V-BLOCK",
            Mode::Command => "COMMAND",
            Mode::Replace => "REPLACE",
            Mode::Search => "SEARCH",
        }
    }

    pub fn status_indicator(&self) -> &'static str {
        match self {
            Mode::Normal => "",
            Mode::Insert => "-- INSERT --",
            Mode::Visual => "-- VISUAL --",
            Mode::VisualLine => "-- VISUAL LINE --",
            Mode::VisualBlock => "-- VISUAL BLOCK --",
            Mode::Command => ":",
            Mode::Replace => "-- REPLACE --",
            Mode::Search => "/",
        }
    }

    pub fn cursor_style(&self) -> CursorStyle {
        match self {
            Mode::Normal => CursorStyle::Block,
            Mode::Insert => CursorStyle::Line,
            Mode::Visual | Mode::VisualLine | Mode::VisualBlock => CursorStyle::Block,
            Mode::Command | Mode::Search => CursorStyle::Line,
            Mode::Replace => CursorStyle::Underline,
        }
    }

    pub fn is_insert_like(&self) -> bool {
        matches!(self, Mode::Insert | Mode::Replace)
    }

    pub fn is_visual(&self) -> bool {
        matches!(self, Mode::Visual | Mode::VisualLine | Mode::VisualBlock)
    }

    pub fn allows_motion(&self) -> bool {
        matches!(
            self,
            Mode::Normal | Mode::Visual | Mode::VisualLine | Mode::VisualBlock
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorStyle {
    Block,
    Line,
    Underline,
}

#[derive(Debug, Clone)]
pub struct ModeState {
    pub mode: Mode,
    pub pending_operator: Option<Operator>,
    pub count: Option<u32>,
    pub register: char,
    pub command_buffer: String,
    pub search_buffer: String,
    pub last_search: String,
    pub search_direction: SearchDirection,
}

impl ModeState {
    pub fn new() -> Self {
        Self {
            mode: Mode::Normal,
            pending_operator: None,
            count: None,
            register: '"',
            command_buffer: String::new(),
            search_buffer: String::new(),
            last_search: String::new(),
            search_direction: SearchDirection::Forward,
        }
    }

    pub fn reset_pending(&mut self) {
        self.pending_operator = None;
        self.count = None;
    }

    pub fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            self.mode = mode;
            self.reset_pending();

            if mode == Mode::Command {
                self.command_buffer.clear();
            } else if mode == Mode::Search {
                self.search_buffer.clear();
            }
        }
    }

    pub fn effective_count(&self) -> u32 {
        self.count.unwrap_or(1)
    }

    pub fn accumulate_count(&mut self, digit: u32) {
        let current = self.count.unwrap_or(0);
        self.count = Some(current * 10 + digit);
    }

    /// Get current mode
    pub fn current_mode(&self) -> Mode {
        self.mode
    }

    /// Get pending operator
    pub fn get_pending_operator(&self) -> Option<Operator> {
        self.pending_operator
    }

    /// Get count
    pub fn get_count(&self) -> Option<u32> {
        self.count
    }

    /// Get current register
    pub fn get_register(&self) -> char {
        self.register
    }

    /// Set current register
    pub fn set_register(&mut self, reg: char) {
        self.register = reg;
    }

    /// Get command buffer
    pub fn get_command_buffer(&self) -> &str {
        &self.command_buffer
    }

    /// Append to command buffer
    pub fn append_command(&mut self, c: char) {
        self.command_buffer.push(c);
    }

    /// Get search buffer
    pub fn get_search_buffer(&self) -> &str {
        &self.search_buffer
    }

    /// Append to search buffer
    pub fn append_search(&mut self, c: char) {
        self.search_buffer.push(c);
    }

    /// Get last search
    pub fn get_last_search(&self) -> &str {
        &self.last_search
    }

    /// Save current search as last search
    pub fn save_search(&mut self) {
        if !self.search_buffer.is_empty() {
            self.last_search = self.search_buffer.clone();
        }
    }

    /// Get search direction
    pub fn get_search_direction(&self) -> SearchDirection {
        self.search_direction
    }

    /// Set search direction
    pub fn set_search_direction(&mut self, dir: SearchDirection) {
        self.search_direction = dir;
    }
}

impl Default for ModeState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Delete,
    Yank,
    Change,
    Indent,
    Outdent,
    Format,
    Uppercase,
    Lowercase,
    SwapCase,
}

impl Operator {
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'd' => Some(Operator::Delete),
            'y' => Some(Operator::Yank),
            'c' => Some(Operator::Change),
            '>' => Some(Operator::Indent),
            '<' => Some(Operator::Outdent),
            'g' => None,
            '~' => Some(Operator::SwapCase),
            _ => None,
        }
    }

    pub fn requires_motion(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchDirection {
    Forward,
    Backward,
}

impl SearchDirection {
    pub fn reverse(&self) -> Self {
        match self {
            SearchDirection::Forward => SearchDirection::Backward,
            SearchDirection::Backward => SearchDirection::Forward,
        }
    }
}
