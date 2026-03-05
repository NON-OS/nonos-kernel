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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::RwLock;

use super::entries::{AppEntry, AppInfo};
use crate::apps::types::{AppError, AppResult};

const MAX_APPS: usize = 64;

static REGISTRY: RwLock<BTreeMap<String, AppEntry>> = RwLock::new(BTreeMap::new());

pub fn register_app(info: AppInfo) -> AppResult<()> {
    let mut reg = REGISTRY.write();

    if reg.len() >= MAX_APPS {
        return Err(AppError::ResourceExhausted);
    }

    let name = String::from(info.name);
    if reg.contains_key(&name) {
        return Err(AppError::AlreadyRegistered);
    }

    let entry = AppEntry::new(info);
    reg.insert(name, entry);

    Ok(())
}

pub fn unregister_app(name: &str) -> AppResult<()> {
    let mut reg = REGISTRY.write();

    let entry = reg.get(name).ok_or(AppError::NotFound)?;

    if entry.is_running() {
        return Err(AppError::InvalidState);
    }

    reg.remove(name);
    Ok(())
}

pub fn get_app<F, R>(name: &str, f: F) -> AppResult<R>
where
    F: FnOnce(&AppEntry) -> R,
{
    let reg = REGISTRY.read();
    let entry = reg.get(name).ok_or(AppError::NotFound)?;
    Ok(f(entry))
}

pub fn get_app_mut<F, R>(name: &str, f: F) -> AppResult<R>
where
    F: FnOnce(&mut AppEntry) -> R,
{
    let mut reg = REGISTRY.write();
    let entry = reg.get_mut(name).ok_or(AppError::NotFound)?;
    Ok(f(entry))
}

pub fn list_apps() -> Vec<String> {
    let reg = REGISTRY.read();
    reg.keys().cloned().collect()
}

pub fn app_count() -> usize {
    REGISTRY.read().len()
}

pub fn running_apps() -> Vec<String> {
    let reg = REGISTRY.read();
    reg.iter()
        .filter(|(_, entry)| entry.is_running())
        .map(|(name, _)| name.clone())
        .collect()
}

pub fn for_each_app<F>(mut f: F)
where
    F: FnMut(&str, &AppEntry),
{
    let reg = REGISTRY.read();
    for (name, entry) in reg.iter() {
        f(name, entry);
    }
}

pub fn clear_all() {
    REGISTRY.write().clear();
}
