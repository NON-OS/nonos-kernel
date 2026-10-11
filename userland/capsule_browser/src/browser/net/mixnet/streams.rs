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

//! Which stream a new conversation with a proxy names.
//!
//! A proxy keys a conversation on our pid and the stream a frame names, and
//! holds at most eight for one caller (capsule_socks5 server/who.rs,
//! capsule_net_anon server/socks/who.rs). The browser names streams from a
//! small fixed set, the lowest free one first, so it never asks for more
//! than the proxy gives and a stream it let go without the proxy hearing is
//! reset by the next conversation that takes its number.
//!
//! Pure; the proofs hold it.

/// Streams the browser names at one proxy, 1 to this. Below the proxy's
/// eight, which also counts the unnamed stream 0.
pub const STREAMS: u32 = 7;

/// The lowest stream not in `used`, or `None` when every one is.
pub fn lowest_free(used: &[u32]) -> Option<u32> {
    (1..=STREAMS).find(|s| !used.contains(s))
}

/// Streams a tab out of view leaves free at each proxy for the tab in view:
/// its next navigation and the first of what that page asks for.
pub const SPARE: u32 = 3;

/// The lowest stream not in `used`, when more than `spare` are free; one
/// asked for with `spare` streams to leave must not take the last of them.
pub fn lowest_free_leaving(used: &[u32], spare: u32) -> Option<u32> {
    let free = (1..=STREAMS).filter(|s| !used.contains(s)).count() as u32;
    lowest_free(used).filter(|_| free > spare)
}
