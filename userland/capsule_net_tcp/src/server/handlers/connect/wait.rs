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

use nonos_libc::mk_yield;

use crate::server::tcp_rx;
use crate::state::TABLE;
use crate::tcp::State;

const WAIT_TRIES: usize = 128;

pub fn established(owner: u32, handle: u32) -> bool {
    for _ in 0..WAIT_TRIES {
        tcp_rx::drain_one();
        let ready =
            TABLE.lock().owned_mut(owner, handle).map(|e| e.tcb.state == State::Established);
        if ready.map_or(false, |state| state) {
            return true;
        }
        mk_yield();
    }
    false
}
