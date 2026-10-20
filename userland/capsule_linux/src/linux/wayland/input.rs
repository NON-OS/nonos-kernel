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

//! NONOS input events, as Wayland sees them.
//!
//! Routed, not drained: the personality subscribes to the input router like
//! any app and gets only what arrives while its surface has focus. It holds no
//! InputSource, and a frame from anyone but the router is not believed.

use nonos_app_skeleton::clients::input_router::subscribe;
use nonos_app_skeleton::discover::{from_router, lookup_port};
use nonos_app_skeleton::input::{InputEvent, InputKind};
use nonos_libc::mk_ipc_recv_from;

use crate::linux::guest::Guest;

use super::input_key::key;
use super::input_send::{axis, button, motion};

/// Key down and up, absolute pointer, wheel, button down and up.
const KINDS: u32 = 0x7B;
const OWN_INBOX: u64 = 0;
const NOWAIT: u64 = 1;
const NINP_MAGIC: u32 = 0x4E49_4E50;
const HEADER: usize = 8;
/// Frames taken in one pass. A deeper backlog is drained on the next.
const BATCH: usize = 32;

pub fn pump(guest: &mut Guest) {
    if guest.scene.pointer.is_none() && guest.scene.keyboard.is_none() {
        return;
    }
    if !guest.scene.subscribed {
        guest.scene.subscribed =
            lookup_port(b"input_router").is_some_and(|port| subscribe(port, 1, KINDS).is_ok());
    }
    let mut rx = [0u8; HEADER + 32];
    for _ in 0..BATCH {
        let mut sender = 0u32;
        let n = mk_ipc_recv_from(OWN_INBOX, rx.as_mut_ptr(), rx.len(), NOWAIT, &mut sender);
        if n < rx.len() as i64 {
            return;
        }
        if u32::from_le_bytes([rx[0], rx[1], rx[2], rx[3]]) != NINP_MAGIC || !from_router(sender) {
            continue;
        }
        if let Some(event) = InputEvent::from_delivery(&rx[HEADER..]) {
            deliver(guest, &event);
        }
    }
}

/// F11, which takes a guest window full screen and back (toplevel.rs).
const KEY_F11: u32 = nonos_app_skeleton::KEY_F1 + 10;

fn deliver(guest: &mut Guest, event: &InputEvent) {
    match event.kind {
        InputKind::KeyDown if event.code == KEY_F11 && super::toplevel::toggle(guest) => {}
        InputKind::KeyUp if event.code == KEY_F11 && super::toplevel::has_toplevel(guest) => {}
        InputKind::KeyDown => key(guest, event.code, 1),
        InputKind::KeyUp => key(guest, event.code, 0),
        InputKind::PointerAbs => motion(guest, event.x, event.y),
        InputKind::Wheel => axis(guest, event.x, event.y, event.delta_y),
        InputKind::ButtonDown => button(guest, event.code, 1),
        InputKind::ButtonUp => button(guest, event.code, 0),
        _ => {}
    }
}
