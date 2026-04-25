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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareVersion { pub major: u8, pub minor: u8, pub patch: u16, pub build: u16 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionComparison { Newer, Same, Older, Incompatible }

pub fn parse_firmware_version(version_string: &str) -> Option<FirmwareVersion> {
    let parts: alloc::vec::Vec<&str> = version_string.split('.').collect();
    if parts.len() < 3 { return None; }
    let major = parts[0].parse::<u8>().ok()?;
    let minor = parts[1].parse::<u8>().ok()?;
    let patch_build: alloc::vec::Vec<&str> = parts[2].split('-').collect();
    let patch = patch_build[0].parse::<u16>().ok()?;
    let build = if patch_build.len() > 1 { patch_build[1].parse::<u16>().unwrap_or(0) } else { 0 };
    Some(FirmwareVersion { major, minor, patch, build })
}

pub fn compare_versions(version_a: &FirmwareVersion, version_b: &FirmwareVersion) -> VersionComparison {
    if version_a.major != version_b.major { return VersionComparison::Incompatible; }
    match version_a.minor.cmp(&version_b.minor) {
        core::cmp::Ordering::Greater => VersionComparison::Newer,
        core::cmp::Ordering::Less => VersionComparison::Older,
        core::cmp::Ordering::Equal => match version_a.patch.cmp(&version_b.patch) {
            core::cmp::Ordering::Greater => VersionComparison::Newer,
            core::cmp::Ordering::Less => VersionComparison::Older,
            core::cmp::Ordering::Equal => match version_a.build.cmp(&version_b.build) {
                core::cmp::Ordering::Greater => VersionComparison::Newer,
                core::cmp::Ordering::Less => VersionComparison::Older,
                core::cmp::Ordering::Equal => VersionComparison::Same,
            }
        }
    }
}

impl Default for FirmwareVersion {
    fn default() -> Self { Self { major: 0, minor: 0, patch: 0, build: 0 } }
}

impl core::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.build > 0 { write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, self.build) } else { write!(f, "{}.{}.{}", self.major, self.minor, self.patch) }
    }
}