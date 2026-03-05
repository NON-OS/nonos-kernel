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

//! Clipboard: multi-format clipboard with bounded storage and deterministic eviction.

#![cfg(feature = "ui")]

use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::Mutex;

type Format = String;

pub struct Clipboard {
    storage: BTreeMap<Format, String>,
    max_entries: usize,
}

static CLIPBOARD: Mutex<Option<Clipboard>> = Mutex::new(None);

impl Clipboard {
    pub fn new(max_entries: usize) -> Self {
        Clipboard { storage: BTreeMap::new(), max_entries }
    }

    pub fn set(&mut self, format: &str, data: &str) {
        if self.storage.len() >= self.max_entries && !self.storage.contains_key(format) {
            if let Some(first_key) = self.storage.keys().next().cloned() {
                self.storage.remove(&first_key);
            }
        }
        self.storage.insert(format.into(), data.into());
    }

    pub fn get(&self, format: &str) -> Option<String> {
        self.storage.get(format).cloned()
    }

    pub fn clear(&mut self) {
        self.storage.clear();
    }
}

pub fn init_clipboard() {
    let mut g = CLIPBOARD.lock();
    if g.is_none() {
        *g = Some(Clipboard::new(8));
        crate::log_info!("ui: clipboard initialized");
    }
}

pub fn set_clipboard(format: &str, data: &str) -> Result<(), &'static str> {
    let mut g = CLIPBOARD.lock();
    if let Some(ref mut cb) = *g {
        cb.set(format, data);
        crate::ui::event::publish_event(crate::ui::event::Event::ClipboardChanged).ok();
        Ok(())
    } else {
        Err("clipboard not initialized")
    }
}

pub fn get_clipboard(format: &str) -> Result<Option<String>, &'static str> {
    let g = CLIPBOARD.lock();
    if let Some(ref cb) = *g {
        Ok(cb.get(format))
    } else {
        Err("clipboard not initialized")
    }
}
