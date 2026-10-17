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
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{centre_top, left, truncate};
use nonos_toolkit::widgets::{Rect, Separator};

use crate::about::data::third_party::COMPONENTS;

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD, KV_GAP, NUM_PX};
use super::super::mono::{mono, truncate_mono, valid};
use super::licenses_cols::{band, columns};

pub const HEAD_COMPONENT: &[u8] = b"COMPONENT";
pub const HEAD_ROLE: &[u8] = b"ROLE";
const HEAD_LICENSE: &[u8] = b"LICENCE";
const HEAD_RULE_GAP: u32 = 6;

pub const HEIGHT: u32 = card::OVERHEAD + ROW_H + HEAD_RULE_GAP + ROW_H * COMPONENTS.len() as u32;

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32) {
    let r = roles();
    let (value, muted) = (r.text_2, r.muted);
    let top = titled(fb, 0, y, w, HEIGHT, b"Third-party components");
    let (role_x, license_x) = columns();
    let inner = card::inner(w);
    let head = top + centre_top(0, ROW_H, BODY_PX);
    left(fb, CARD_PAD, head, valid(HEAD_COMPONENT), muted, BODY_PX);
    left(fb, role_x, head, valid(HEAD_ROLE), muted, BODY_PX);
    left(fb, license_x, head, valid(HEAD_LICENSE), muted, BODY_PX);
    if let Ok(y) = u32::try_from(top + (ROW_H + HEAD_RULE_GAP / 2) as i32) {
        Separator::new().draw(fb, Rect { x: CARD_PAD, y, w: inner, h: 1 });
    }
    let first = top + (ROW_H + HEAD_RULE_GAP) as i32;
    let name_w = role_x.saturating_sub(CARD_PAD + KV_GAP);
    let license_w = (CARD_PAD + inner).saturating_sub(license_x);
    for (i, c) in COMPONENTS.iter().enumerate() {
        let row_y = first + (i as u32 * ROW_H) as i32;
        if i % 2 == 1 {
            band(fb, row_y, inner);
        }
        let cell = row_y + centre_top(0, ROW_H, BODY_PX);
        left(fb, CARD_PAD, cell, &truncate(valid(c.name), name_w, BODY_PX), value, BODY_PX);
        let role = truncate_mono(c.role, license_x - role_x - KV_GAP, NUM_PX);
        mono(fb, role_x, cell, role.as_bytes(), muted, NUM_PX);
        let license = truncate_mono(c.license, license_w, NUM_PX);
        mono(fb, license_x, cell, license.as_bytes(), value, NUM_PX);
    }
}
