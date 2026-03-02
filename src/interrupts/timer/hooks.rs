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

use spin::{Once, RwLock};

pub type TickHook = fn();

static HOOK: Once<RwLock<Option<TickHook>>> = Once::new();

pub fn init() {
    HOOK.call_once(|| RwLock::new(None));
}

pub fn set_tick_hook(hook: TickHook) {
    if let Some(lock) = HOOK.get() {
        *lock.write() = Some(hook);
    }
}

pub fn clear_tick_hook() {
    if let Some(lock) = HOOK.get() {
        *lock.write() = None;
    }
}

pub fn invoke_hook() {
    if let Some(lock) = HOOK.get() {
        if let Some(callback) = *lock.read() {
            callback();
        }
    }
}
