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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageState {
    Available,
    Downloading,
    Downloaded,
    Installing,
    Installed,
    Removing,
    Broken,
    OnHold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencyKind {
    Runtime,
    Build,
    Optional,
    Conflict,
    Replace,
    Provide,
}

impl DependencyKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "runtime" | "depends" => Some(Self::Runtime),
            "build" | "makedepends" => Some(Self::Build),
            "optional" | "optdepends" => Some(Self::Optional),
            "conflict" | "conflicts" => Some(Self::Conflict),
            "replace" | "replaces" => Some(Self::Replace),
            "provide" | "provides" => Some(Self::Provide),
            _ => None,
        }
    }
}
