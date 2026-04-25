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

use super::state::DependencyKind;
use super::version_req::VersionRequirement;
use alloc::string::String;

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: VersionRequirement,
    pub kind: DependencyKind,
    pub reason: Option<String>,
}

impl Dependency {
    pub fn runtime(name: &str, version: VersionRequirement) -> Self {
        Self { name: String::from(name), version, kind: DependencyKind::Runtime, reason: None }
    }

    pub fn optional(name: &str, reason: &str) -> Self {
        Self {
            name: String::from(name),
            version: VersionRequirement::Any,
            kind: DependencyKind::Optional,
            reason: Some(String::from(reason)),
        }
    }

    pub fn conflict(name: &str) -> Self {
        Self {
            name: String::from(name),
            version: VersionRequirement::Any,
            kind: DependencyKind::Conflict,
            reason: None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (name, version) =
            if let Some(idx) = s.find(|c: char| c == '>' || c == '<' || c == '=' || c == '^') {
                let name = s[..idx].trim();
                let version_str = &s[idx..];
                (name, VersionRequirement::parse(version_str)?)
            } else {
                (s, VersionRequirement::Any)
            };
        Some(Self {
            name: String::from(name),
            version,
            kind: DependencyKind::Runtime,
            reason: None,
        })
    }
}
