// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::window::WindowType;

#[derive(Clone, Copy)]
pub(super) struct SearchResult {
    pub name: &'static [u8],
    pub category: ResultCategory,
    pub action: ResultAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResultCategory {
    Application,
    Setting,
    File,
    Command,
}

#[derive(Clone, Copy)]
pub(super) enum ResultAction {
    OpenApp(WindowType),
    OpenSetting(u8),
    OpenFile,
    RunCommand,
}

static ALL_RESULTS: &[SearchResult] = &[
    SearchResult {
        name: b"Terminal",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::Terminal),
    },
    SearchResult {
        name: b"Files",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::FileManager),
    },
    SearchResult {
        name: b"Editor",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::TextEditor),
    },
    SearchResult {
        name: b"Calculator",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::Calculator),
    },
    SearchResult {
        name: b"Browser",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::Browser),
    },
    SearchResult {
        name: b"Wallet",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::Wallet),
    },
    SearchResult {
        name: b"Settings",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::Settings),
    },
    SearchResult {
        name: b"Process Manager",
        category: ResultCategory::Application,
        action: ResultAction::OpenApp(WindowType::ProcessManager),
    },
    SearchResult {
        name: b"Display Settings",
        category: ResultCategory::Setting,
        action: ResultAction::OpenSetting(6),
    },
    SearchResult {
        name: b"Keyboard Settings",
        category: ResultCategory::Setting,
        action: ResultAction::OpenSetting(7),
    },
    SearchResult {
        name: b"Sound Settings",
        category: ResultCategory::Setting,
        action: ResultAction::OpenSetting(9),
    },
    SearchResult {
        name: b"Network Settings",
        category: ResultCategory::Setting,
        action: ResultAction::OpenSetting(1),
    },
    SearchResult {
        name: b"Privacy Settings",
        category: ResultCategory::Setting,
        action: ResultAction::OpenSetting(0),
    },
    SearchResult {
        name: b"Appearance",
        category: ResultCategory::Setting,
        action: ResultAction::OpenSetting(2),
    },
];

pub(super) fn search(query: &[u8]) -> impl Iterator<Item = &'static SearchResult> + use<'_> {
    ALL_RESULTS.iter().filter(move |r| matches_query(r.name, query))
}

pub(super) fn search_count(query: &[u8]) -> usize {
    ALL_RESULTS.iter().filter(|r| matches_query(r.name, query)).count()
}

fn matches_query(name: &[u8], query: &[u8]) -> bool {
    if query.is_empty() {
        return true;
    }
    let name_lower: [u8; 32] = to_lower(name);
    let query_lower: [u8; 32] = to_lower(query);
    let q_len = query.len().min(32);
    for i in 0..=(name.len().saturating_sub(q_len)) {
        if &name_lower[i..i + q_len] == &query_lower[..q_len] {
            return true;
        }
    }
    false
}

fn to_lower(s: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    for (i, &c) in s.iter().take(32).enumerate() {
        buf[i] = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
    }
    buf
}
