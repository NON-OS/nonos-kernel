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
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabStatus {
    Loading,
    Ready,
    Error,
    Blank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatus {
    Secure,
    Insecure,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BrowserTab {
    pub id: u32,
    pub url: String,
    pub title: String,
    pub content: Vec<u8>,
    pub status: TabStatus,
    pub security: SecurityStatus,
    pub can_go_back: bool,
    pub can_go_forward: bool,
    pub scroll_position: u32,
    pub favicon: Option<Vec<u8>>,
    pub error_message: Option<String>,
    pub(super) history_index: usize,
    pub(super) history: Vec<String>,
}
