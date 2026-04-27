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

use crate::capabilities::CapabilityToken;
use crate::runtime::zerostate;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(super) const MAX_CAPSULES: usize = 32;
pub(super) const TREASURY: [u8; 20] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
];

#[derive(Clone, Copy)]
pub(super) struct Capsule {
    pub(super) app_idx: u8,
    pub(super) capsule_id: [u8; 32],
    pub(super) caps_granted: u64,
    pub(super) running: bool,
    pub(super) install_time: u64,
    pub(super) active: bool,
    name: [u8; 64],
}

impl Capsule {
    const fn empty() -> Self {
        Self {
            app_idx: 0,
            capsule_id: [0u8; 32],
            caps_granted: 0,
            running: false,
            install_time: 0,
            active: false,
            name: [0u8; 64],
        }
    }
    pub(super) fn is_running(&self) -> bool {
        self.running
    }
    pub(super) fn copy_name(&self, buf: &mut [u8; 64]) -> usize {
        buf.copy_from_slice(&self.name);
        self.name.iter().position(|&c| c == 0).unwrap_or(64)
    }
}

static CAPSULES: Mutex<[Capsule; MAX_CAPSULES]> = Mutex::new([Capsule::empty(); MAX_CAPSULES]);
static CAPSULE_COUNT: AtomicU32 = AtomicU32::new(0);

pub(super) fn capsule_count() -> u32 {
    CAPSULE_COUNT.load(Ordering::Relaxed)
}

pub(super) fn get_capsule(idx: usize) -> Option<Capsule> {
    let arr = CAPSULES.lock();
    arr.get(idx).filter(|c| c.active).copied()
}

pub(super) fn create_capsule(
    app_idx: usize,
    id: &[u8; 32],
    name: &str,
    caps: u64,
) -> Option<usize> {
    let mut arr = CAPSULES.lock();
    for (i, c) in arr.iter_mut().enumerate() {
        if !c.active {
            c.app_idx = app_idx as u8;
            c.capsule_id = *id;
            c.caps_granted = caps;
            c.running = false;
            c.install_time = crate::time::timestamp_millis() / 1000;
            c.active = true;
            let bytes = name.as_bytes();
            let len = core::cmp::min(bytes.len(), 63);
            c.name[..len].copy_from_slice(&bytes[..len]);
            c.name[len] = 0;
            CAPSULE_COUNT.fetch_add(1, Ordering::Relaxed);
            return Some(i);
        }
    }
    None
}

pub(super) fn launch_capsule(idx: usize, token: &CapabilityToken) -> Result<(), &'static str> {
    let mut name_buf = [0u8; 64];
    let name_len;
    {
        let arr = CAPSULES.lock();
        let cap = arr.get(idx).ok_or("Invalid index")?;
        if !cap.active {
            return Err("Capsule not installed");
        }
        if cap.running {
            return Err("Already running");
        }
        name_len = cap.copy_name(&mut name_buf);
    }
    let name = core::str::from_utf8(&name_buf[..name_len]).map_err(|_| "Invalid name")?;
    zerostate::start_capsule(name, token)?;
    let mut arr = CAPSULES.lock();
    if let Some(c) = arr.get_mut(idx) {
        c.running = true;
    }
    Ok(())
}

pub(super) fn stop_capsule(idx: usize) -> Result<(), &'static str> {
    let mut name_buf = [0u8; 64];
    let name_len;
    {
        let arr = CAPSULES.lock();
        let cap = arr.get(idx).ok_or("Invalid index")?;
        if !cap.running {
            return Err("Not running");
        }
        name_len = cap.copy_name(&mut name_buf);
    }
    let name = core::str::from_utf8(&name_buf[..name_len]).map_err(|_| "Invalid name")?;
    zerostate::stop_capsule(name)?;
    let mut arr = CAPSULES.lock();
    if let Some(c) = arr.get_mut(idx) {
        c.running = false;
    }
    Ok(())
}
