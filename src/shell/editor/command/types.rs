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

extern crate alloc;

use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Write(Option<String>),
    Quit,
    WriteQuit,
    ForceQuit,
    Edit(String),
    Number(usize),
    Set(SetCommand),
    Substitute(String, String, SubstituteFlags),
    Global(String, String),
    Delete(Option<usize>, Option<usize>),
    Yank(Option<usize>, Option<usize>),
    Put,
    Registers,
    Marks,
    Help,
    Version,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetCommand {
    Number(bool),
    RelativeNumber(bool),
    TabStop(usize),
    ExpandTab(bool),
    AutoIndent(bool),
    ShowMatch(bool),
    IgnoreCase(bool),
    SmartCase(bool),
    Wrap(bool),
    List,
    All,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubstituteFlags {
    pub global: bool,
    pub ignore_case: bool,
    pub confirm: bool,
}

#[derive(Debug, Clone)]
pub enum CommandResult {
    Continue,
    Quit,
    Message(String),
    Error(String),
}
