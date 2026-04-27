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

use super::manifest::AppManifest;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub const MAX_REGISTERED: usize = 128;

#[derive(Clone)]
pub struct AppInfo {
    pub id: u32,
    pub manifest: AppManifest,
    pub installed: bool,
    pub install_time: u64,
    pub last_run: u64,
    pub run_count: u32,
}

impl AppInfo {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            manifest: AppManifest::empty(),
            installed: false,
            install_time: 0,
            last_run: 0,
            run_count: 0,
        }
    }
}

static REGISTRY: Mutex<alloc::vec::Vec<AppInfo>> = Mutex::new(alloc::vec::Vec::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

pub fn register_app(manifest: AppManifest) -> Option<u32> {
    register_app_with_stats(manifest, 0)
}

pub fn register_app_with_stats(manifest: AppManifest, initial_installs: u32) -> Option<u32> {
    let mut reg = REGISTRY.lock();
    if reg.len() >= MAX_REGISTERED {
        return None;
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    reg.push(AppInfo {
        id,
        manifest,
        installed: true,
        install_time: crate::time::timestamp_millis() / 1000,
        last_run: 0,
        run_count: initial_installs,
    });
    Some(id)
}

pub fn get_app(id: u32) -> Option<AppInfo> {
    let reg = REGISTRY.lock();
    reg.iter().find(|a| a.id == id).cloned()
}

pub fn list_apps() -> alloc::vec::Vec<AppInfo> {
    let reg = REGISTRY.lock();
    reg.iter().filter(|a| a.installed).cloned().collect()
}

pub fn uninstall_app(id: u32) -> bool {
    let mut reg = REGISTRY.lock();
    for a in reg.iter_mut() {
        if a.id == id {
            a.installed = false;
            return true;
        }
    }
    false
}

pub fn app_count() -> u32 {
    REGISTRY.lock().len() as u32
}

pub(super) fn update_app_stats(id: u32, ts: u64) {
    let mut r = REGISTRY.lock();
    for a in r.iter_mut() {
        if a.id == id {
            a.run_count += 1;
            a.last_run = ts;
            return;
        }
    }
}
