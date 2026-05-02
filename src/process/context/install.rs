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

use super::Context;
use crate::process::core::INTERRUPT_SAVED_CONTEXTS;

/// Atomically apply `f` to the saved user `Context` for `pid`. Returns
/// `true` if the entry existed and was modified, `false` if no saved
/// context was present.
pub fn modify_saved_context(pid: u32, f: impl FnOnce(&mut Context)) -> bool {
    let mut map = INTERRUPT_SAVED_CONTEXTS.write();
    match map.get_mut(&pid) {
        Some(ctx) => {
            f(ctx);
            true
        }
        None => false,
    }
}

/// Snapshot the saved user `Context` for `pid`.
pub fn read_saved_context(pid: u32) -> Option<Context> {
    INTERRUPT_SAVED_CONTEXTS.read().get(&pid).copied()
}
