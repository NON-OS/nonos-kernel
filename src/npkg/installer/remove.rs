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
use super::remove_single::remove_single_package;
use crate::npkg::database::is_installed;
use crate::npkg::error::{NpkgError, NpkgResult};
use alloc::string::String;
use alloc::vec::Vec;

pub fn remove_package(name: &str, options: &RemoveOptions) -> NpkgResult<()> {
    remove_packages(&[name], options)
}

pub fn remove_packages(names: &[&str], options: &RemoveOptions) -> NpkgResult<()> {
    for name in names {
        if !is_installed(name) {
            return Err(NpkgError::NotInstalled(String::from(*name)));
        }
    }
    if options.recursive {
        let mut to_remove: Vec<String> = names.iter().map(|s| String::from(*s)).collect();
        let orphans = crate::npkg::database::get_orphans();
        for orphan in orphans {
            if !to_remove.contains(&orphan) {
                to_remove.push(orphan);
            }
        }
        for name in &to_remove {
            remove_single_package(name, options)?;
        }
    } else {
        for name in names {
            remove_single_package(name, options)?;
        }
    }
    Ok(())
}
