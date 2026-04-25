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

use super::parse::parse_manifest;
use super::serialize::serialize_manifest;
use super::types::Manifest;
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::types::Package;

const MANIFEST_CACHE_DIR: &str = "/var/lib/npkg/manifests";

pub fn cache_manifest(name: &str, manifest: &Manifest) -> NpkgResult<()> {
    let _ = crate::fs::mkdir(MANIFEST_CACHE_DIR, 0o755);
    let path = alloc::format!("{}/{}.manifest", MANIFEST_CACHE_DIR, name);
    let data = serialize_manifest(manifest);
    crate::fs::nonos_vfs::vfs_write_file(&path, &data)
        .map_err(|_| NpkgError::IoError(alloc::format!("failed to cache manifest: {}", name)))?;
    Ok(())
}

pub fn get_cached_manifest(name: &str) -> Option<Package> {
    let path = alloc::format!("{}/{}.manifest", MANIFEST_CACHE_DIR, name);
    let data = crate::fs::read_file_bytes(&path).ok()?;
    let manifest = parse_manifest(&data).ok()?;
    Some(manifest.package)
}

pub fn remove_cached_manifest(name: &str) -> NpkgResult<()> {
    let path = alloc::format!("{}/{}.manifest", MANIFEST_CACHE_DIR, name);
    let _ = crate::fs::unlink(&path);
    Ok(())
}
