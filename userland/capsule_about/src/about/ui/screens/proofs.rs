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

//! The live proof board: one answer at the top, and under it every check the
//! answer rests on, each of which can fail.
//!
//! Read once a second while the screen is open (`State::refresh_proofs`), so
//! a route that drops, a capsule that starts, or a report that goes stale is
//! on screen within a second of happening. Nothing here is a claim the window
//! makes for itself: every row is the kernel's table, the kernel's registry,
//! the bootloader's record or a transport's own report, judged by rules
//! proven on the host.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{centre_top, left};
use nonos_toolkit::widgets::Rect;

use crate::about::data::proofs::Snapshot;
use crate::about::state::State;

use super::super::card;
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_GAP, CARD_PAD};
use super::{proofs_network, proofs_route, proofs_session};

pub fn content_h(state: &State, _rect: &Rect) -> u32 {
    match &state.proofs {
        Some(s) => {
            proofs_session::HEIGHT
                + CARD_GAP
                + proofs_route::HEIGHT
                + CARD_GAP
                + proofs_network::height(s)
        }
        None => card::OVERHEAD + ROW_H,
    }
}

pub fn paint(state: &State, fb: &mut PaintBuffer, rect: &Rect) {
    let mut pane = fb.sub(rect.x, rect.y, rect.w, rect.h);
    let y = -(state.scroll as i32);
    let Some(s) = &state.proofs else {
        waiting(&mut pane, y, rect.w);
        return;
    };
    paint_all(&mut pane, y, rect.w, s);
}

fn paint_all(fb: &mut PaintBuffer, y: i32, w: u32, s: &Snapshot) {
    proofs_session::paint(fb, y, w, s);
    let route_y = y + (proofs_session::HEIGHT + CARD_GAP) as i32;
    proofs_route::paint(fb, route_y, w, s);
    let net_y = route_y + (proofs_route::HEIGHT + CARD_GAP) as i32;
    proofs_network::paint(fb, net_y, w, s);
}

fn waiting(fb: &mut PaintBuffer, y: i32, w: u32) {
    let r = roles();
    let top = card::titled(fb, 0, y, w, card::OVERHEAD + ROW_H, b"This session");
    let msg = "reading the kernel and the route board";
    left(fb, CARD_PAD, top + centre_top(0, ROW_H, BODY_PX), msg, r.muted, BODY_PX);
}
