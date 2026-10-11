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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use super::store_entry::{Entry, Status};
use super::store_lookup::Joined;

/// A decoded raster: ARGB8888, row-major, top-down.
pub struct Decoded {
    pub w: u32,
    pub h: u32,
    pub px: Vec<u32>,
}

/// Images by absolute URL: their state, the largest box each is drawn
/// into, the natural size once known, and the decoded rasters, held under
/// a byte budget that evicts the least recently painted first.
#[derive(Default)]
pub struct Store {
    pub(super) entries: BTreeMap<String, Entry>,
    pub(super) bytes: usize,
    pub(super) clock: Cell<u64>,
    /* Page-relative sources already joined against the base, by source. */
    pub(super) joined: RefCell<Joined>,
    pub(super) natural_dirty: bool,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every image and free the budget, as a navigation does; the old
    /// store's drop refunds what it held.
    pub fn reset(&mut self) {
        *self = Store::new();
    }

    /// True once the url is known in any state, so layout does not queue it
    /// again; an evicted raster comes back through requeue_visible.
    pub fn contains(&self, url: &str) -> bool {
        self.entries.contains_key(url)
    }

    /// The decoded raster for `url`, marked as just used.
    pub fn ready(&self, url: &str) -> Option<&Decoded> {
        let e = self.entries.get(url)?;
        let Status::Ready(d) = &e.status else { return None };
        self.clock.set(self.clock.get() + 1);
        e.used.set(self.clock.get());
        Some(d)
    }
}

/* A store that goes, with its tab or its page, gives its rasters back. */
impl Drop for Store {
    fn drop(&mut self) {
        super::resident::refund(self.bytes);
    }
}
