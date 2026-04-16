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

use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};
use super::config::ZkSyncConfig;
use super::state::StateManager;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut CONFIG: Option<ZkSyncConfig> = None;
static STATE_MANAGER: Once<Mutex<StateManager>> = Once::new();

pub fn init_zksync(config: ZkSyncConfig) -> Result<(), super::ZkSyncError> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }
    STATE_MANAGER.call_once(|| Mutex::new(StateManager::new()));
    unsafe { CONFIG = Some(config); }
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub(crate) fn get_config() -> Option<&'static ZkSyncConfig> {
    if !is_initialized() { return None; }
    unsafe { (*core::ptr::addr_of!(CONFIG)).as_ref() }
}

pub(crate) fn with_state<R, F: FnOnce(&StateManager) -> R>(f: F) -> Option<R> {
    STATE_MANAGER.get().map(|m| f(&m.lock()))
}

pub(crate) fn with_state_mut<R, F: FnOnce(&mut StateManager) -> R>(f: F) -> Option<R> {
    STATE_MANAGER.get().map(|m| f(&mut m.lock()))
}
