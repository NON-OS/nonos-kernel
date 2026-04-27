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
use alloc::string::String;
use alloc::vec::Vec;

impl PackageVersion {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (version_str, build) = if let Some(idx) = s.find('+') {
            (&s[..idx], Some(String::from(&s[idx + 1..])))
        } else {
            (s, None)
        };
        let (version_str, pre_release) = if let Some(idx) = version_str.find('-') {
            (&version_str[..idx], Some(String::from(&version_str[idx + 1..])))
        } else {
            (version_str, None)
        };
        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return None;
        }
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = if parts.len() == 3 { parts[2].parse().ok()? } else { 0 };
        Some(Self { major, minor, patch, pre_release, build })
    }

    pub fn to_string(&self) -> String {
        let mut s = alloc::format!("{}.{}.{}", self.major, self.minor, self.patch);
        if let Some(ref pre) = self.pre_release {
            s.push('-');
            s.push_str(pre);
        }
        if let Some(ref build) = self.build {
            s.push('+');
            s.push_str(build);
        }
        s
    }
}
