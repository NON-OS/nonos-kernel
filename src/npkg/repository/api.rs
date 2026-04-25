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
use super::config::save_repositories;
use super::manager::REPO_MANAGER;
use super::repo::Repository;
use super::types::RepositoryConfig;
use crate::npkg::error::{NpkgError, NpkgResult};
use alloc::{format, string::String, vec::Vec};

pub fn add_repository(config: RepositoryConfig) -> NpkgResult<()> {
    let mut guard = REPO_MANAGER.write();
    let manager =
        guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    if manager.repositories.iter().any(|r| r.config.name == config.name) {
        return Err(NpkgError::InternalError(format!("repository {} exists", config.name)));
    }
    manager.repositories.push(Repository::new(config));
    save_repositories()?;
    Ok(())
}

pub fn remove_repository(name: &str) -> NpkgResult<()> {
    let mut guard = REPO_MANAGER.write();
    let manager =
        guard.as_mut().ok_or(NpkgError::InternalError(String::from("not initialized")))?;
    let initial_len = manager.repositories.len();
    manager.repositories.retain(|r| r.config.name != name);
    if manager.repositories.len() == initial_len {
        return Err(NpkgError::RepositoryNotFound(String::from(name)));
    }
    save_repositories()?;
    Ok(())
}

pub fn list_repositories() -> Vec<RepositoryConfig> {
    let guard = REPO_MANAGER.read();
    guard
        .as_ref()
        .map(|m| m.repositories.iter().map(|r| r.config.clone()).collect())
        .unwrap_or_default()
}
