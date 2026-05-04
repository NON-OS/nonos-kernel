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

use spin::Mutex;

pub(super) struct BlockDevice {
    pub id: u8,
    pub name: [u8; 16],
    pub sector_size: u32,
    pub sector_count: u64,
    pub mounted: bool,
}

static DEVICES: Mutex<[Option<BlockDevice>; 8]> = Mutex::new([const { None }; 8]);

pub(super) fn register_device(name: &[u8], sector_size: u32, sector_count: u64) -> Option<u8> {
    let mut devices = DEVICES.lock();
    for (i, slot) in devices.iter_mut().enumerate() {
        if slot.is_none() {
            let mut dev_name = [0u8; 16];
            let len = core::cmp::min(name.len(), 16);
            dev_name[..len].copy_from_slice(&name[..len]);
            *slot = Some(BlockDevice {
                id: i as u8,
                name: dev_name,
                sector_size,
                sector_count,
                mounted: false,
            });
            return Some(i as u8);
        }
    }
    None
}

pub(super) fn mount_device(id: u8) -> bool {
    let mut devices = DEVICES.lock();
    if let Some(Some(dev)) = devices.get_mut(id as usize) {
        dev.mounted = true;
        return true;
    }
    false
}

pub(super) fn unmount_device(id: u8) -> bool {
    let mut devices = DEVICES.lock();
    if let Some(Some(dev)) = devices.get_mut(id as usize) {
        dev.mounted = false;
        return true;
    }
    false
}

pub(super) fn get_device(id: u8) -> Option<BlockDevice> {
    let devices = DEVICES.lock();
    devices.get(id as usize)?.as_ref().map(|d| BlockDevice {
        id: d.id,
        name: d.name,
        sector_size: d.sector_size,
        sector_count: d.sector_count,
        mounted: d.mounted,
    })
}

pub(super) fn device_count() -> u8 {
    DEVICES.lock().iter().filter(|d| d.is_some()).count() as u8
}
