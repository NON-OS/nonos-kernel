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
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;
use super::registry::get_device;

static OPEN_DEVICES: Mutex<BTreeMap<alloc::string::String, AtomicU32>> = Mutex::new(BTreeMap::new());

pub fn open(name: &str) -> Result<(), i32> {
    let _ = get_device(name).ok_or(-19i32)?;
    let mut open_devs = OPEN_DEVICES.lock();
    if let Some(count) = open_devs.get(name) {
        count.fetch_add(1, Ordering::SeqCst);
    } else {
        open_devs.insert(alloc::string::String::from(name), AtomicU32::new(1));
    }
    Ok(())
}

pub fn close(name: &str) -> Result<(), i32> {
    let mut open_devs = OPEN_DEVICES.lock();
    if let Some(count) = open_devs.get(name) {
        let prev = count.fetch_sub(1, Ordering::SeqCst);
        if prev <= 1 {
            open_devs.remove(name);
        }
        Ok(())
    } else {
        Err(-9)
    }
}

pub fn is_open(name: &str) -> bool {
    OPEN_DEVICES.lock().contains_key(name)
}

pub fn open_count(name: &str) -> u32 {
    OPEN_DEVICES.lock().get(name).map(|c| c.load(Ordering::SeqCst)).unwrap_or(0)
}

pub fn read(name: &str, buf: &mut [u8], offset: u64) -> Result<usize, i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.read(buf, offset)
}

pub fn write(name: &str, buf: &[u8], offset: u64) -> Result<usize, i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.write(buf, offset)
}

pub fn flush(name: &str) -> Result<(), i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.flush()
}

pub fn ioctl(name: &str, cmd: u32, arg: u64) -> Result<i64, i32> {
    let dev = get_device(name).ok_or(-19i32)?;
    dev.ioctl(cmd, arg)
}
