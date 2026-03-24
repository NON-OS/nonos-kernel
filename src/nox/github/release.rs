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

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct Release {
    pub id: u64,
    pub tag_name: String,
    pub name: String,
    pub body: String,
    pub draft: bool,
    pub prerelease: bool,
    pub created_at: String,
    pub published_at: String,
    pub tarball_url: String,
    pub zipball_url: String,
    pub assets: Vec<Asset>,
}

#[derive(Clone, Debug)]
pub struct Asset {
    pub id: u64,
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub download_url: String,
    pub download_count: u64,
}

impl Release {
    pub fn find_asset(&self, pattern: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name.contains(pattern))
    }

    pub fn find_tarball(&self) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name.ends_with(".tar.gz") || a.name.ends_with(".tgz"))
    }
}
