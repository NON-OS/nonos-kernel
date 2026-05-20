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

use crate::state::Entry;
use crate::tcp::{Endpoint4, State};

use super::types::Table;

impl Table {
    pub fn owned_mut(&mut self, owner: u32, handle: u32) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.owner_pid == owner && e.handle == handle)
    }

    pub fn by_handle_mut(&mut self, handle: u32) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.handle == handle)
    }

    pub fn listener_for_mut(&mut self, port: u16) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.tcb.state == State::Listen && e.tcb.local.port == port)
    }

    pub fn connection_match_mut(
        &mut self,
        local: Endpoint4,
        remote: Endpoint4,
    ) -> Option<&mut Entry> {
        self.entries
            .iter_mut()
            .find(|e| e.tcb.state != State::Listen && e.tcb.matches(&local, &remote))
    }
}
