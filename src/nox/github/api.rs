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

use super::release::Release;
use crate::nox::{NoxError, NoxResult};
use alloc::string::String;
use alloc::vec::Vec;

pub struct GitHubApi {
    token: Option<String>,
}

impl GitHubApi {
    pub fn new(token: Option<String>) -> Self {
        Self { token }
    }

    pub fn get_releases(&self, owner: &str, repo: &str) -> NoxResult<Vec<Release>> {
        let _ = (owner, repo);
        Ok(Vec::new())
    }

    pub fn get_latest_release(&self, owner: &str, repo: &str) -> NoxResult<Release> {
        self.get_releases(owner, repo)?
            .into_iter()
            .find(|r| !r.prerelease)
            .ok_or_else(|| NoxError::GitHubApiError(String::from("no releases found")))
    }

    pub fn get_release_by_tag(&self, owner: &str, repo: &str, tag: &str) -> NoxResult<Release> {
        self.get_releases(owner, repo)?
            .into_iter()
            .find(|r| r.tag_name == tag)
            .ok_or_else(|| NoxError::GitHubApiError(alloc::format!("release {} not found", tag)))
    }

    pub fn authenticated(&self) -> bool {
        self.token.is_some()
    }
}

impl Default for GitHubApi {
    fn default() -> Self {
        Self::new(None)
    }
}
