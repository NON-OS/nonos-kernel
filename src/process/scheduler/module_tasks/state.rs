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

use alloc::collections::{BTreeMap, BTreeSet};
use core::sync::atomic::AtomicU64;

pub(super) static MODULE_TASKS: spin::RwLock<BTreeMap<u64, BTreeSet<u64>>> =
    spin::RwLock::new(BTreeMap::new());
pub(super) static NEXT_MODULE_TASK_ID: AtomicU64 = AtomicU64::new(1);

pub fn has_running_tasks(module_id: u64) -> bool {
    let module_tasks = MODULE_TASKS.read();
    module_tasks.get(&module_id).map(|tasks| !tasks.is_empty()).unwrap_or(false)
}
