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
use super::dir::{dir_add_entry, dir_lookup, dir_remove_entry, EXT4_FT_DIR, EXT4_FT_REG_FILE};
use super::ialloc::{alloc_inode, free_inode, init_inode};
use super::inode::{read_inode, write_inode, EXT4_ROOT_INO, S_IFDIR, S_IFREG};
use super::mount::Ext4MountInfo;
use alloc::sync::Arc;

pub fn ext4_lookup(mount: &Arc<Ext4MountInfo>, path: &str) -> Result<u32, i32> {
    if path.is_empty() || path == "/" {
        return Ok(EXT4_ROOT_INO);
    }
    let path = path.trim_start_matches('/');
    let mut current_ino = EXT4_ROOT_INO;
    for component in path.split('/') {
        if component.is_empty() {
            continue;
        }
        let inode = read_inode(&mount.device, &mount.sb, current_ino)?;
        if !inode.is_dir() {
            return Err(-20);
        }
        current_ino = dir_lookup(&mount.device, &mount.sb, &inode, component)?;
    }
    Ok(current_ino)
}

pub fn ext4_create(
    mount: &Arc<Ext4MountInfo>,
    parent_ino: u32,
    name: &str,
    mode: u16,
) -> Result<u32, i32> {
    let parent = read_inode(&mount.device, &mount.sb, parent_ino)?;
    if !parent.is_dir() {
        return Err(-20);
    }
    if dir_lookup(&mount.device, &mount.sb, &parent, name).is_ok() {
        return Err(-17);
    }
    let ino = alloc_inode(mount, false)?;
    init_inode(mount, ino, S_IFREG | (mode & 0o777), 0, 0)?;
    dir_add_entry(&mount.device, &mount.sb, parent_ino, name, ino, EXT4_FT_REG_FILE)?;
    Ok(ino)
}

pub fn ext4_mkdir(
    mount: &Arc<Ext4MountInfo>,
    parent_ino: u32,
    name: &str,
    mode: u16,
) -> Result<u32, i32> {
    let parent = read_inode(&mount.device, &mount.sb, parent_ino)?;
    if !parent.is_dir() {
        return Err(-20);
    }
    if dir_lookup(&mount.device, &mount.sb, &parent, name).is_ok() {
        return Err(-17);
    }
    let ino = alloc_inode(mount, true)?;
    init_inode(mount, ino, S_IFDIR | (mode & 0o777), 0, 0)?;
    dir_add_entry(&mount.device, &mount.sb, ino, ".", ino, EXT4_FT_DIR)?;
    dir_add_entry(&mount.device, &mount.sb, ino, "..", parent_ino, EXT4_FT_DIR)?;
    dir_add_entry(&mount.device, &mount.sb, parent_ino, name, ino, EXT4_FT_DIR)?;
    let mut pinode = read_inode(&mount.device, &mount.sb, parent_ino)?;
    pinode.i_links_count += 1;
    write_inode(&mount.device, &mount.sb, parent_ino, &pinode)?;
    Ok(ino)
}

pub fn ext4_unlink(mount: &Arc<Ext4MountInfo>, parent_ino: u32, name: &str) -> Result<(), i32> {
    let parent = read_inode(&mount.device, &mount.sb, parent_ino)?;
    if !parent.is_dir() {
        return Err(-20);
    }
    let ino = dir_lookup(&mount.device, &mount.sb, &parent, name)?;
    let mut inode = read_inode(&mount.device, &mount.sb, ino)?;
    if inode.is_dir() {
        return Err(-21);
    }
    dir_remove_entry(&mount.device, &mount.sb, parent_ino, name)?;
    inode.i_links_count -= 1;
    if inode.i_links_count == 0 {
        free_inode(mount, ino)?;
    } else {
        write_inode(&mount.device, &mount.sb, ino, &inode)?;
    }
    Ok(())
}

pub fn ext4_rmdir(mount: &Arc<Ext4MountInfo>, parent_ino: u32, name: &str) -> Result<(), i32> {
    let parent = read_inode(&mount.device, &mount.sb, parent_ino)?;
    let ino = dir_lookup(&mount.device, &mount.sb, &parent, name)?;
    let inode = read_inode(&mount.device, &mount.sb, ino)?;
    if !inode.is_dir() {
        return Err(-20);
    }
    dir_remove_entry(&mount.device, &mount.sb, parent_ino, name)?;
    free_inode(mount, ino)?;
    let mut pinode = read_inode(&mount.device, &mount.sb, parent_ino)?;
    pinode.i_links_count -= 1;
    write_inode(&mount.device, &mount.sb, parent_ino, &pinode)?;
    Ok(())
}
