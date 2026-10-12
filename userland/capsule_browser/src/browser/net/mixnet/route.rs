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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::choice::{chosen, Network};
use super::conv::Conv;
use super::pace::Pace;
use super::streams::lowest_free_leaving;
use super::way::{Routes, Way};

/// One conversation with a proxy, as the socket calls above see it.
///
/// `net.socks5` and `net.anon` speak RFC 1928 over IPC and have no listening
/// socket, so they cannot be bypassed by dialling past them. A slot holds
/// what makes a service call look like a socket: the proxy's port and the
/// conversation, with the frame it has asked and not had answered (`conv`).
pub struct Slot {
    pub handle: u32,
    pub port: u32,
    pub conv: Conv,
}

static SLOTS: Mutex<Vec<Slot>> = Mutex::new(Vec::new());

/// The routes before any page has set them: no network service known.
pub const UNSET: Routes = Routes { page: Network::Nym, nym: 0, anon: 0 };

/// The ways the page being loaded may take, set at each navigation. The
/// page is the tab being stepped's: each tab keeps its own (`tab_scope`).
static ROUTES: Mutex<Routes> = Mutex::new(UNSET);

/// Streams a new conversation must leave free at its proxy: none for the
/// tab in view, `streams::SPARE` while a tab out of view steps.
static LEAVE: AtomicU32 = AtomicU32::new(0);

/// Leave `spare` streams free at each proxy until told otherwise.
pub fn leave_spare(spare: u32) {
    LEAVE.store(spare, Ordering::Relaxed);
}

/// How often the proxies are asked, across every conversation.
pub static PACE: Mutex<Pace> = Mutex::new(Pace::new());

/// The ways of the page now being loaded. The routes they replace.
pub fn set_routes(routes: Routes) -> Routes {
    core::mem::replace(&mut *ROUTES.lock(), routes)
}

/// The way a connection to `host` takes now.
pub fn way(host: &str) -> Way {
    ROUTES.lock().way(host)
}

/// Whether a connection may leave direct now (`Routes::direct`).
pub fn direct_allowed() -> bool {
    ROUTES.lock().direct(chosen())
}

/// Streams let go whose proxy has not yet heard so: (port, stream).
static RESETS: Mutex<Vec<(u32, u32)>> = Mutex::new(Vec::new());

/// Keep a new conversation with the proxy at `port` on `handle`, on the
/// lowest stream free there (`streams`). `None` when every stream is held.
pub fn insert(handle: u32, port: u32) -> Option<()> {
    let mut slots = SLOTS.lock();
    let used: Vec<u32> = slots.iter().filter(|s| s.port == port).map(|s| s.conv.stream()).collect();
    let stream = lowest_free_leaving(&used, LEAVE.load(Ordering::Relaxed))?;
    /* Its own opening reset ends whatever the stream held at the proxy. */
    RESETS.lock().retain(|&r| r != (port, stream));
    slots.push(Slot { handle, port, conv: Conv::opening(stream) });
    Some(())
}

/// Whether a new conversation with the proxy at `port` would get a stream.
pub fn room(port: u32) -> bool {
    let slots = SLOTS.lock();
    let used: Vec<u32> = slots.iter().filter(|s| s.port == port).map(|s| s.conv.stream()).collect();
    lowest_free_leaving(&used, LEAVE.load(Ordering::Relaxed)).is_some()
}

/// Forget the conversation on `handle`. `tell` asks the proxy to end its
/// stream too (`pending_resets`), so the exit stops sending for a fetch
/// that is gone; a conversation that never opened needs no telling.
pub fn remove(handle: u32, tell: bool) {
    let mut slots = SLOTS.lock();
    let Some(at) = slots.iter().position(|s| s.handle == handle) else { return };
    let slot = slots.swap_remove(at);
    if tell {
        RESETS.lock().push((slot.port, slot.conv.stream()));
    }
}

/// A stream let go whose proxy should still be told, if any.
pub fn pending_reset() -> Option<(u32, u32)> {
    RESETS.lock().first().copied()
}

/// The proxy heard that reset, or cannot be asked: stop asking.
pub fn reset_done(r: (u32, u32)) {
    RESETS.lock().retain(|&x| x != r);
}

/// Run `f` against the conversation on `handle`, or report there is none.
pub fn with<R>(handle: u32, f: impl FnOnce(&mut Slot) -> R) -> Result<R, ()> {
    let mut slots = SLOTS.lock();
    match slots.iter_mut().find(|s| s.handle == handle) {
        Some(slot) => Ok(f(slot)),
        None => Err(()),
    }
}
