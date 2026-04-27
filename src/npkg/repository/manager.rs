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

extern crate alloc;
use super::config::load_custom_repositories;
use super::repo::Repository;
use super::types::RepositoryConfig;
use crate::npkg::error::NpkgResult;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::RwLock;

pub struct RepositoryManager {
    pub(super) repositories: Vec<Repository>,
    pub(super) sync_in_progress: AtomicBool,
    pub(super) total_packages: AtomicU64,
}

impl RepositoryManager {
    pub(super) fn new() -> Self {
        Self {
            repositories: Vec::new(),
            sync_in_progress: AtomicBool::new(false),
            total_packages: AtomicU64::new(0),
        }
    }
}

pub(super) static REPO_MANAGER: RwLock<Option<RepositoryManager>> = RwLock::new(None);

pub fn init_repository_manager() -> NpkgResult<()> {
    let mut manager = REPO_MANAGER.write();
    if manager.is_some() {
        return Ok(());
    }
    let mut rm = RepositoryManager::new();
    rm.repositories
        .push(Repository::new(RepositoryConfig::official("core", "https://repo.nonos.dev/core")));
    rm.repositories
        .push(Repository::new(RepositoryConfig::official("extra", "https://repo.nonos.dev/extra")));
    rm.repositories.push(Repository::new(RepositoryConfig::community(
        "community",
        "https://repo.nonos.dev/community",
    )));
    load_custom_repositories(&mut rm)?;
    *manager = Some(rm);
    Ok(())
}

pub fn get_repository_manager() -> Option<&'static RwLock<Option<RepositoryManager>>> {
    Some(&REPO_MANAGER)
}
