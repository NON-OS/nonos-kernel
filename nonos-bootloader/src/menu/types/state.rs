// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::action::MenuAction;
use super::mode::SecurityMode;

pub struct MenuState { pub selected: usize, pub entries: &'static [MenuAction], pub timeout_ms: u64, pub elapsed_ms: u64, pub visible: bool }
const DEFAULT_TIMEOUT_MS: u64 = 3000;
static DEFAULT_ENTRIES: [MenuAction; 9] = [MenuAction::Boot(SecurityMode::Standard), MenuAction::Boot(SecurityMode::Hardened), MenuAction::NetworkIsolated, MenuAction::SafeMode, MenuAction::Recovery, MenuAction::Diagnostics, MenuAction::MemoryTest, MenuAction::UefiShell, MenuAction::Boot(SecurityMode::Development)];

impl MenuState {
    pub const fn new(entries: &'static [MenuAction], timeout_ms: u64) -> Self { Self { selected: 0, entries, timeout_ms, elapsed_ms: 0, visible: false } }
    pub fn select_next(&mut self) { if !self.entries.is_empty() { self.selected = (self.selected + 1) % self.entries.len(); } }
    pub fn select_prev(&mut self) { if !self.entries.is_empty() { self.selected = self.selected.checked_sub(1).unwrap_or(self.entries.len() - 1); } }
    pub fn current_action(&self) -> MenuAction { self.entries.get(self.selected).copied().unwrap_or(MenuAction::Continue) }
    pub fn is_timed_out(&self) -> bool { self.elapsed_ms >= self.timeout_ms }
    pub fn remaining_ms(&self) -> u64 { self.timeout_ms.saturating_sub(self.elapsed_ms) }
}

impl Default for MenuState { fn default() -> Self { Self::new(&DEFAULT_ENTRIES, DEFAULT_TIMEOUT_MS) } }
