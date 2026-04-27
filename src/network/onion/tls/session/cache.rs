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

use super::consts::MAX_ENTRIES;
use super::ticket::SessionTicket;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use spin::Mutex;

pub struct SessionCache {
    entries: Mutex<BTreeMap<String, (SessionTicket, u64)>>,
    access_counter: Mutex<u64>,
}

impl SessionCache {
    pub const fn new() -> Self {
        Self { entries: Mutex::new(BTreeMap::new()), access_counter: Mutex::new(0) }
    }

    pub fn store(&self, host: &str, port: u16, ticket: SessionTicket) {
        let key = format!("{}:{}", host, port);
        let mut entries = self.entries.lock();
        let mut counter = self.access_counter.lock();
        *counter += 1;
        let order = *counter;
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
            if let Some(oldest_key) =
                entries.iter().min_by_key(|(_, (_, ord))| *ord).map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }
        entries.insert(key, (ticket, order));
    }

    pub fn get(&self, host: &str, port: u16) -> Option<SessionTicket> {
        let key = format!("{}:{}", host, port);
        let now_ms = crate::time::timestamp_millis();
        let mut entries = self.entries.lock();
        match entries.remove(&key) {
            Some((ticket, _)) => {
                if ticket.is_expired(now_ms) {
                    None
                } else {
                    Some(ticket)
                }
            }
            None => None,
        }
    }

    pub fn clear(&self) {
        let mut entries = self.entries.lock();
        entries.clear();
        let mut counter = self.access_counter.lock();
        *counter = 0;
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }
}
