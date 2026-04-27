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

mod types;

pub use types::Context;

use alloc::collections::BTreeMap;
use spin::Mutex;
extern crate alloc;

static SAVED_CONTEXTS: Mutex<BTreeMap<u64, Context>> = Mutex::new(BTreeMap::new());

pub fn save_context(pid: u64, ctx: Context) {
    SAVED_CONTEXTS.lock().insert(pid, ctx);
}

pub fn get_saved_context(pid: u64) -> Option<Context> {
    SAVED_CONTEXTS.lock().get(&pid).copied()
}

pub fn modify_saved_context<F: FnOnce(&mut Context)>(pid: u64, f: F) -> bool {
    let mut map = SAVED_CONTEXTS.lock();
    if let Some(ctx) = map.get_mut(&pid) {
        f(ctx);
        true
    } else {
        false
    }
}

pub fn remove_saved_context(pid: u64) {
    SAVED_CONTEXTS.lock().remove(&pid);
}
