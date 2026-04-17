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
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;
use super::superblock::{Ext4Superblock, read_superblock, write_superblock};
use super::journal::Ext4Journal;

static MOUNTS: Mutex<BTreeMap<String, Arc<Ext4MountInfo>>> = Mutex::new(BTreeMap::new());

pub struct Ext4MountInfo {
    pub device: String,
    pub mountpoint: String,
    pub sb: Ext4Superblock,
    pub flags: u32,
    pub journal: Option<Arc<Ext4Journal>>,
}

pub fn ext4_mount(device: &str, mountpoint: &str, flags: u32) -> Result<Arc<Ext4MountInfo>, i32> {
    let sb = read_superblock(device)?;
    if !sb.is_valid() { return Err(-22); }
    let journal = if sb.s_journal_inum != 0 {
        None
    } else { None };
    let mount = Arc::new(Ext4MountInfo {
        device: String::from(device),
        mountpoint: String::from(mountpoint),
        sb, flags, journal,
    });
    MOUNTS.lock().insert(String::from(mountpoint), mount.clone());
    crate::fs::vfs::register_mount(mountpoint, "ext4").map_err(|e| i32::from(e))?;
    Ok(mount)
}

pub fn ext4_unmount(mountpoint: &str) -> Result<(), i32> {
    let mount = MOUNTS.lock().remove(mountpoint).ok_or(-22)?;
    if let Some(ref j) = mount.journal { super::journal::journal_commit(j)?; }
    let mut sb = mount.sb;
    sb.s_state = 1;
    sb.s_mnt_count += 1;
    write_superblock(&mount.device, &sb)?;
    crate::fs::vfs::unregister_mount(mountpoint)?;
    Ok(())
}

pub fn ext4_sync(mountpoint: &str) -> Result<(), i32> {
    let mounts = MOUNTS.lock();
    let mount = mounts.get(mountpoint).ok_or(-22)?;
    if let Some(ref j) = mount.journal { super::journal::journal_commit(j)?; }
    crate::drivers::block::flush(&mount.device)?;
    Ok(())
}

pub fn get_mount(mountpoint: &str) -> Option<Arc<Ext4MountInfo>> {
    MOUNTS.lock().get(mountpoint).cloned()
}

pub fn get_mount_for_path(path: &str) -> Option<Arc<Ext4MountInfo>> {
    let mounts = MOUNTS.lock();
    let mut best_match: Option<(&String, &Arc<Ext4MountInfo>)> = None;
    for (mp, mount) in mounts.iter() {
        if path.starts_with(mp.as_str()) {
            let dominated = best_match.as_ref().map_or(true, |(best_mp, _)| mp.len() > best_mp.len());
            if dominated { best_match = Some((mp, mount)); }
        }
    }
    best_match.map(|(_, m)| m.clone())
}
