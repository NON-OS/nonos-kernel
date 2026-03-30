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

use super::version::PackageVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRequirement {
    Exact(PackageVersion),
    GreaterThan(PackageVersion),
    GreaterOrEqual(PackageVersion),
    LessThan(PackageVersion),
    LessOrEqual(PackageVersion),
    Compatible(PackageVersion),
    Any,
}

impl VersionRequirement {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s == "*" || s.is_empty() {
            return Some(Self::Any);
        }
        if let Some(rest) = s.strip_prefix(">=") {
            PackageVersion::parse(rest.trim()).map(Self::GreaterOrEqual)
        } else if let Some(rest) = s.strip_prefix("<=") {
            PackageVersion::parse(rest.trim()).map(Self::LessOrEqual)
        } else if let Some(rest) = s.strip_prefix('>') {
            PackageVersion::parse(rest.trim()).map(Self::GreaterThan)
        } else if let Some(rest) = s.strip_prefix('<') {
            PackageVersion::parse(rest.trim()).map(Self::LessThan)
        } else if let Some(rest) = s.strip_prefix('^') {
            PackageVersion::parse(rest.trim()).map(Self::Compatible)
        } else if let Some(rest) = s.strip_prefix('=') {
            PackageVersion::parse(rest.trim()).map(Self::Exact)
        } else {
            PackageVersion::parse(s).map(Self::Exact)
        }
    }
}

impl PackageVersion {
    pub fn satisfies(&self, requirement: &VersionRequirement) -> bool {
        match requirement {
            VersionRequirement::Exact(v) => self == v,
            VersionRequirement::GreaterThan(v) => self > v,
            VersionRequirement::GreaterOrEqual(v) => self >= v,
            VersionRequirement::LessThan(v) => self < v,
            VersionRequirement::LessOrEqual(v) => self <= v,
            VersionRequirement::Compatible(v) => self.major == v.major && self >= v,
            VersionRequirement::Any => true,
        }
    }
}
