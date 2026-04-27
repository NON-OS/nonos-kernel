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
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct Tap {
    pub user: String,
    pub repo: String,
    pub url: String,
    pub path: String,
    pub official: bool,
    pub private: bool,
    pub formula_count: usize,
    pub last_sync: u64,
}

impl Tap {
    pub fn new(user: &str, repo: &str) -> Self {
        let url = format!("https://github.com/{}/{}", user, repo);
        let path = format!("{}/{}/{}", crate::nox::NOX_TAPS, user, repo);
        let official = user == "nonos";
        Self {
            user: String::from(user),
            repo: String::from(repo),
            url,
            path,
            official,
            private: false,
            formula_count: 0,
            last_sync: 0,
        }
    }

    pub fn from_url(url: &str) -> Option<Self> {
        let url = url.trim_end_matches(".git");
        let parts: Vec<&str> = url.rsplitn(3, '/').collect();
        if parts.len() < 2 {
            return None;
        }
        Some(Self::new(parts[1], parts[0]))
    }

    pub fn name(&self) -> String {
        format!("{}/{}", self.user, self.repo)
    }

    pub fn formula_path(&self) -> String {
        format!("{}/Formula", self.path)
    }

    pub fn api_url(&self) -> String {
        format!("https://api.github.com/repos/{}/{}", self.user, self.repo)
    }
}
