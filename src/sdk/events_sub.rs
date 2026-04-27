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

pub(super) const MAX_SUBSCRIBERS: usize = 64;

#[derive(Clone, Copy)]
pub(super) struct Subscriber {
    pub app_id: u32,
    pub event_type: [u8; 32],
    pub active: bool,
}

pub(super) static SUBSCRIBERS: Mutex<[Subscriber; MAX_SUBSCRIBERS]> =
    Mutex::new([Subscriber { app_id: 0, event_type: [0; 32], active: false }; MAX_SUBSCRIBERS]);

pub(crate) fn subscribe(app_id: u32, event_type: &[u8]) -> bool {
    let mut subs = SUBSCRIBERS.lock();
    let mut et = [0u8; 32];
    let len = event_type.len().min(32);
    et[..len].copy_from_slice(&event_type[..len]);
    for s in subs.iter_mut() {
        if !s.active {
            *s = Subscriber { app_id, event_type: et, active: true };
            return true;
        }
    }
    false
}

pub(crate) fn unsubscribe(app_id: u32, event_type: &[u8]) -> bool {
    let mut subs = SUBSCRIBERS.lock();
    let mut et = [0u8; 32];
    let len = event_type.len().min(32);
    et[..len].copy_from_slice(&event_type[..len]);
    for s in subs.iter_mut() {
        if s.active && s.app_id == app_id && s.event_type == et {
            s.active = false;
            return true;
        }
    }
    false
}

pub(super) fn get_subscribed_types(app_id: u32) -> alloc::vec::Vec<[u8; 32]> {
    let subs = SUBSCRIBERS.lock();
    subs.iter().filter(|s| s.active && s.app_id == app_id).map(|s| s.event_type).collect()
}
