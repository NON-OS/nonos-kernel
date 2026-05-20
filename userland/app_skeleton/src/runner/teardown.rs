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

use nonos_libc::mk_exit;

use crate::clients::{compositor, wm};
use crate::discover::Peers;

use super::request_id::next;

pub(super) fn close(peers: &Peers, window_id: u32, request_id: &mut u32) -> ! {
    let rid = next(request_id);
    let _ = wm::window_close(peers.wm, rid, window_id);
    let rid = next(request_id);
    let _ = compositor::scene_remove(peers.compositor, rid, 0);
    mk_exit(0)
}
