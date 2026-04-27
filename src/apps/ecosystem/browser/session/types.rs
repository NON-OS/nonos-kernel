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

use super::cookie::Cookie;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct BrowserSession {
    pub id: u64,
    pub name: String,
    pub created_at: u64,
    pub last_active: u64,
    pub is_private: bool,
    pub tabs: Vec<SessionTab>,
    pub storage: SessionStorage,
}

#[derive(Debug, Clone)]
pub struct SessionTab {
    pub url: String,
    pub title: String,
    pub scroll_position: u32,
}

#[derive(Debug, Clone, Default)]
pub struct SessionStorage {
    pub cookies: BTreeMap<String, Cookie>,
    pub local_storage: BTreeMap<String, BTreeMap<String, String>>,
    pub session_storage: BTreeMap<String, BTreeMap<String, String>>,
}
