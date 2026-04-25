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

use alloc::vec::Vec;
use spin::Mutex;

pub const MAX_EVENTS: usize = 256;

#[derive(Clone)]
pub struct AppEvent {
    pub id: u32,
    pub source_app: u32,
    pub event_type: [u8; 32],
    pub data: Vec<u8>,
    pub timestamp: u64,
}

static EVENTS: Mutex<Vec<AppEvent>> = Mutex::new(Vec::new());
static mut NEXT_EVENT_ID: u32 = 1;

pub fn emit(source_app: u32, event_type: &[u8], data: &[u8]) -> u32 {
    let mut evts = EVENTS.lock();
    if evts.len() >= MAX_EVENTS {
        evts.remove(0);
    }
    let id = unsafe {
        NEXT_EVENT_ID += 1;
        NEXT_EVENT_ID - 1
    };
    let mut et = [0u8; 32];
    let len = event_type.len().min(32);
    et[..len].copy_from_slice(&event_type[..len]);
    evts.push(AppEvent {
        id,
        source_app,
        event_type: et,
        data: data.to_vec(),
        timestamp: crate::time::timestamp_millis(),
    });
    id
}

pub fn poll_events(app_id: u32, since: u64) -> Vec<AppEvent> {
    let evts = EVENTS.lock();
    let subscribed = crate::sdk::events_sub::get_subscribed_types(app_id);
    evts.iter()
        .filter(|e| e.timestamp > since && subscribed.contains(&e.event_type))
        .cloned()
        .collect()
}

pub fn subscribe(app_id: u32, event_type: &[u8]) -> bool {
    crate::sdk::events_sub::subscribe(app_id, event_type)
}

pub fn unsubscribe(app_id: u32, event_type: &[u8]) -> bool {
    crate::sdk::events_sub::unsubscribe(app_id, event_type)
}

pub fn clear_old_events(max_age_ms: u64) {
    let now = crate::time::timestamp_millis();
    let mut evts = EVENTS.lock();
    evts.retain(|e| now - e.timestamp < max_age_ms);
}
