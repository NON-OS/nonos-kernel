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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme;
use nonos_toolkit::widgets::text::{centre_top, left, truncate};

use crate::about::data::caps::ALL_CAPS;

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD};
use super::super::mono::valid;
use super::trust_caps_list::{height, names, summary, CAP_SLOTS, DENIED_GAP, ROLE_GAP};
use super::trust_pills;

const UNREAD: &str = "the kernel did not show this window its process table row";

// Granted and denied are the same named bits shown twice: as pills that can be
// counted at a glance, and, for the ones this window holds, as the sentence
// that says what each of them actually permits. The word is the one the kernel
// recorded for this pid (`State::held`), not the one the build declared.
pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, held: Option<u64>) {
    let muted = theme::roles().muted;
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, height(inner, held), b"Capabilities");
    let Some(mask) = held else {
        left(fb, CARD_PAD, top + centre_top(0, ROW_H, BODY_PX), UNREAD, muted, BODY_PX);
        return;
    };
    let mut head = [0u8; 48];
    let label = summary(&mut head, mask, true, true);
    left(fb, CARD_PAD, top + centre_top(0, ROW_H, BODY_PX), valid(label), muted, BODY_PX);
    let mut slots: [&'static [u8]; CAP_SLOTS] = [b""; CAP_SLOTS];
    let granted = names(&mut slots, mask, true);
    let chips_y = top + ROW_H as i32;
    let chips_h = trust_pills::paint(fb, CARD_PAD, chips_y, inner, &slots[..granted], true);
    let roles_y = chips_y + (chips_h + ROLE_GAP) as i32;
    roles(fb, roles_y, inner, mask);
    let denied_y = roles_y + (granted as u32 * ROW_H + DENIED_GAP) as i32;
    let mut foot = [0u8; 48];
    let label = summary(&mut foot, mask, false, false);
    left(fb, CARD_PAD, denied_y + centre_top(0, ROW_H, BODY_PX), valid(label), muted, BODY_PX);
    let denied = names(&mut slots, mask, false);
    trust_pills::paint(fb, CARD_PAD, denied_y + ROW_H as i32, inner, &slots[..denied], false);
}

// Name then role on one baseline, drawn as two runs from the measured advance of
// the first so the separator sits against the name whatever the name measures.
fn roles(fb: &mut PaintBuffer, y: i32, inner: u32, mask: u64) {
    let r = theme::roles();
    let mut row = 0u32;
    for cap in ALL_CAPS {
        if mask & cap.bit == 0 {
            continue;
        }
        let ry = y + (row * ROW_H) as i32 + centre_top(0, ROW_H, BODY_PX);
        let x = left(fb, CARD_PAD, ry, valid(cap.name), r.text_2, BODY_PX);
        let x = left(fb, x.max(0) as u32, ry, "   ", r.muted, BODY_PX);
        let room = (CARD_PAD + inner).saturating_sub(x.max(0) as u32);
        let cut = truncate(valid(cap.role), room, BODY_PX);
        left(fb, x.max(0) as u32, ry, &cut, r.muted, BODY_PX);
        row += 1;
    }
}
