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

use alloc::format;
use alloc::string::String;

#[derive(Clone, Debug)]
pub struct GitHubSource {
    pub owner: String,
    pub repo: String,
    pub reference: Option<String>,
    pub path: Option<String>,
}

impl GitHubSource {
    pub fn parse(spec: &str) -> Option<Self> {
        let spec = spec.trim_start_matches("github:");
        let spec = spec.trim_start_matches("https://github.com/");
        let spec = spec.trim_end_matches(".git");
        let parts: alloc::vec::Vec<&str> = spec.split('/').collect();
        if parts.len() < 2 {
            return None;
        }
        let owner = String::from(parts[0]);
        let repo_part = parts[1];
        let (repo, reference) = if let Some(idx) = repo_part.find('@') {
            (String::from(&repo_part[..idx]), Some(String::from(&repo_part[idx + 1..])))
        } else {
            (String::from(repo_part), None)
        };
        let path = if parts.len() > 2 { Some(parts[2..].join("/")) } else { None };
        Some(Self { owner, repo, reference, path })
    }

    pub fn clone_url(&self) -> String {
        format!("https://github.com/{}/{}.git", self.owner, self.repo)
    }
    pub fn api_url(&self) -> String {
        format!("https://api.github.com/repos/{}/{}", self.owner, self.repo)
    }
    pub fn releases_url(&self) -> String {
        format!("{}/releases", self.api_url())
    }
    pub fn tarball_url(&self, tag: &str) -> String {
        format!("https://github.com/{}/{}/archive/refs/tags/{}.tar.gz", self.owner, self.repo, tag)
    }
}
