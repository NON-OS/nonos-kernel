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
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryKind {
    Official,
    Community,
    ThirdParty,
    Local,
}

impl RepositoryKind {
    pub fn trust_level(&self) -> u8 {
        match self {
            Self::Official => 100,
            Self::Community => 75,
            Self::ThirdParty => 50,
            Self::Local => 25,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepositoryConfig {
    pub name: String,
    pub url: String,
    pub kind: RepositoryKind,
    pub enabled: bool,
    pub signature_required: bool,
    pub priority: u32,
}

impl RepositoryConfig {
    pub fn official(name: &str, url: &str) -> Self {
        Self {
            name: String::from(name),
            url: String::from(url),
            kind: RepositoryKind::Official,
            enabled: true,
            signature_required: true,
            priority: 100,
        }
    }
    pub fn community(name: &str, url: &str) -> Self {
        Self {
            name: String::from(name),
            url: String::from(url),
            kind: RepositoryKind::Community,
            enabled: true,
            signature_required: true,
            priority: 50,
        }
    }
    pub fn local(path: &str) -> Self {
        Self {
            name: String::from("local"),
            url: String::from(path),
            kind: RepositoryKind::Local,
            enabled: true,
            signature_required: false,
            priority: 200,
        }
    }
}
