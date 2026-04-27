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

use crate::npkg::error::NpkgResult;
use alloc::string::String;
use alloc::vec::Vec;

pub fn create_isolated_namespace() -> NpkgResult<IsolatedNamespace> {
    Ok(IsolatedNamespace::new())
}

pub struct IsolatedNamespace {
    mount_points: Vec<String>,
}

impl IsolatedNamespace {
    pub(super) fn new() -> Self {
        Self { mount_points: Vec::new() }
    }

    pub fn bind_mount(&mut self, _src: &str, dst: &str) -> NpkgResult<()> {
        self.mount_points.push(String::from(dst));
        Ok(())
    }

    pub fn overlay_mount(&mut self, _lower: &str, _upper: &str, merged: &str) -> NpkgResult<()> {
        self.mount_points.push(String::from(merged));
        Ok(())
    }

    pub fn cleanup(&mut self) -> NpkgResult<()> {
        for mount in self.mount_points.iter().rev() {
            let _ = crate::fs::umount(mount);
        }
        self.mount_points.clear();
        Ok(())
    }
}

impl Drop for IsolatedNamespace {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
