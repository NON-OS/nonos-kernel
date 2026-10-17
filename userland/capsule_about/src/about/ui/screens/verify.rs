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

//! The system checking its own claims, from inside itself.
//!
//! Six cards in the order a sceptic would want them: what was checked just now
//! and by whom, what the hardware will sign for and the capsules that signature
//! covers, each proved by the kernel at spawn, what was checked once at boot by
//! something that is no longer running and what the kernel checked of it in
//! turn, and what this window cannot check at all.
//! Ordering live evidence first is the point.
//! Every other operating system's About box opens with the strongest-sounding
//! claim; this one opens with the only claims the reader can watch being made.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::widgets::Rect;

use crate::about::data::verify::attested;
use crate::about::state::State;

use super::super::card;
use super::super::metrics::CARD_GAP;
use super::{verify_boot, verify_doc, verify_live, verify_loader, verify_open, verify_spawn};

pub fn content_h(rect: &Rect) -> u32 {
    let inner = card::inner(rect.w);
    verify_live::HEIGHT
        + CARD_GAP
        + verify_doc::HEIGHT
        + CARD_GAP
        + verify_spawn::height(attested().as_deref())
        + CARD_GAP
        + verify_boot::HEIGHT
        + CARD_GAP
        + verify_loader::HEIGHT
        + CARD_GAP
        + verify_open::height(inner)
}

pub fn paint(state: &State, fb: &mut PaintBuffer, rect: &Rect) {
    let mut pane = fb.sub(rect.x, rect.y, rect.w, rect.h);
    let y = -(state.scroll as i32);
    verify_live::paint(&mut pane, y, rect.w);
    let doc_y = y + (verify_live::HEIGHT + CARD_GAP) as i32;
    verify_doc::paint(&mut pane, doc_y, rect.w, &state.attest);
    let list = attested();
    let spawn_y = doc_y + (verify_doc::HEIGHT + CARD_GAP) as i32;
    verify_spawn::paint(&mut pane, spawn_y, rect.w, list.as_deref());
    let boot_y = spawn_y + (verify_spawn::height(list.as_deref()) + CARD_GAP) as i32;
    verify_boot::paint(&mut pane, boot_y, rect.w);
    let loader_y = boot_y + (verify_boot::HEIGHT + CARD_GAP) as i32;
    verify_loader::paint(&mut pane, loader_y, rect.w);
    let open_y = loader_y + (verify_loader::HEIGHT + CARD_GAP) as i32;
    verify_open::paint(&mut pane, open_y, rect.w);
}
