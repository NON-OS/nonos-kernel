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

use alloc::string::String;
use alloc::vec::Vec;

use super::store::Store;
use super::store_entry::Status;

impl Store {
    /// Give every raster back to the budget as the tab goes out of view,
    /// and leave each image `queued` to fetch evicted rather than pending:
    /// the images the page draws keep their sizes, so its layout holds, and
    /// those near the screen come back when the tab is shown again
    /// (`requeue_visible`).
    pub fn put_away(&mut self, queued: &[String]) {
        let ready: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| matches!(e.status, Status::Ready(_)))
            .map(|(k, _)| k.clone())
            .collect();
        for url in ready {
            self.drop_raster(&url, Status::Evicted);
        }
        for url in queued {
            if let Some(e) = self.entries.get_mut(url.as_str()) {
                if matches!(e.status, Status::Pending) {
                    e.status = Status::Evicted;
                }
            }
        }
    }
}
