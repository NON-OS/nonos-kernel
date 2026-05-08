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

use super::state::EventRing;

impl EventRing {
    /// True when the TRB at the consumer cursor carries the
    /// expected cycle bit (the controller wrote it). When the
    /// consumer crosses a segment boundary it flips its cycle so
    /// stale (already-consumed) entries with the old cycle stop
    /// matching.
    pub fn has_event(&self) -> bool {
        let trb = self.current_trb();
        trb.get_cycle() == (self.consumer_cycle != 0)
    }
}
