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

use super::lookup::lookup_port;
use super::peers::Peers;

const READY_ATTEMPTS: usize = 256;

pub fn require_peers() -> Result<Peers, &'static str> {
    let mut compositor: Option<u32> = None;
    let mut wm: Option<u32> = None;
    let mut input_router: Option<u32> = None;
    let mut toolkit: Option<u32> = None;
    for _ in 0..READY_ATTEMPTS {
        if compositor.is_none() {
            compositor = lookup_port(b"compositor");
        }
        if wm.is_none() {
            wm = lookup_port(b"wm");
        }
        if input_router.is_none() {
            input_router = lookup_port(b"input_router");
        }
        if toolkit.is_none() {
            toolkit = lookup_port(b"toolkit");
        }
        if let (Some(c), Some(w), Some(i), Some(t)) = (compositor, wm, input_router, toolkit) {
            return Ok(Peers { compositor: c, wm: w, input_router: i, toolkit: t });
        }
        mk_yield();
    }
    Err("desktop peers not announced")
}
