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

extern crate alloc;

use super::registry::list_devices;
use super::types::{DeviceNode, DeviceType};
use alloc::string::String;
use alloc::vec::Vec;

pub fn devfs_lookup(parent_ino: u64, name: &str) -> Option<DeviceNode> {
    if parent_ino == 1 {
        return lookup_root(name);
    }
    if parent_ino == 100 {
        return lookup_pts(name);
    }
    None
}

fn lookup_root(name: &str) -> Option<DeviceNode> {
    if name == "pts" {
        return Some(DeviceNode {
            name: String::from("pts"),
            dev_type: DeviceType::CharDevice,
            major: 0,
            minor: 0,
            mode: 0o755,
            inode: 100,
        });
    }
    list_devices().into_iter().find(|d| d.name == name)
}

fn lookup_pts(name: &str) -> Option<DeviceNode> {
    if let Ok(num) = name.parse::<u32>() {
        return Some(DeviceNode::char_device(name, 136, num, 0o620, 100 + num as u64 + 1));
    }
    None
}

pub fn devfs_readdir(inode: u64) -> Vec<DeviceNode> {
    if inode == 1 {
        let mut entries = list_devices();
        entries.push(DeviceNode {
            name: String::from("pts"),
            dev_type: DeviceType::CharDevice,
            major: 0,
            minor: 0,
            mode: 0o755,
            inode: 100,
        });
        return entries;
    }
    if inode == 100 {
        return super::pts::list_ptys();
    }
    Vec::new()
}

pub fn devfs_mknod(
    name: &str,
    dev_type: DeviceType,
    major: u32,
    minor: u32,
    mode: u32,
) -> Result<u64, i32> {
    super::registry::register_device(name, dev_type, major, minor, mode)
}

pub fn devfs_getattr(inode: u64) -> Result<DevfsAttr, i32> {
    let dev = super::registry::get_device_by_inode(inode).ok_or(-2)?;
    Ok(DevfsAttr { ino: inode, mode: dev.mode, rdev: dev.dev(), size: 0 })
}

#[derive(Debug, Clone, Copy)]
pub struct DevfsAttr {
    pub ino: u64,
    pub mode: u32,
    pub rdev: u64,
    pub size: u64,
}
