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

use super::options::RemoveOptions;
use crate::npkg::database::{query_by_name, unregister_package};
use crate::npkg::error::{NpkgError, NpkgResult};
use crate::npkg::hooks::{run_post_remove, run_pre_remove};
use alloc::string::String;

pub(super) fn remove_single_package(name: &str, options: &RemoveOptions) -> NpkgResult<()> {
    let pkg = query_by_name(name).ok_or_else(|| NpkgError::NotInstalled(String::from(name)))?;
    crate::info!("npkg: removing {} {}", pkg.meta.name, pkg.meta.version.to_string());
    if !options.no_scripts {
        run_pre_remove(name, "")?;
    }
    for file in pkg.files.iter().rev() {
        if options.keep_config && is_config_file(file) {
            continue;
        }
        if crate::fs::is_directory(file) {
            let _ = crate::fs::rmdir(file);
        } else {
            let _ = crate::fs::unlink(file);
        }
    }
    if options.purge {
        let config_dir = alloc::format!("/etc/{}", name);
        let _ = remove_directory_recursive(&config_dir);
        let data_dir = alloc::format!("/var/lib/{}", name);
        let _ = remove_directory_recursive(&data_dir);
    }
    unregister_package(name)?;
    let _ = crate::npkg::manifest::remove_cached_manifest(name);
    if !options.no_scripts {
        run_post_remove(name, "")?;
    }
    crate::info!("npkg: {} removed", name);
    Ok(())
}

fn is_config_file(path: &str) -> bool {
    path.starts_with("/etc/") || path.ends_with(".conf") || path.ends_with(".cfg")
}

fn remove_directory_recursive(path: &str) -> NpkgResult<()> {
    let entries =
        crate::fs::vfs::get_vfs().and_then(|vfs| vfs.list_dir(path).ok()).unwrap_or_default();
    for entry in entries {
        let full_path = alloc::format!("{}/{}", path, entry);
        if crate::fs::is_directory(&full_path) {
            remove_directory_recursive(&full_path)?;
        } else {
            let _ = crate::fs::unlink(&full_path);
        }
    }
    let _ = crate::fs::rmdir(path);
    Ok(())
}
