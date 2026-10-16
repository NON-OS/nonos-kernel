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
use nonos_toolkit::theme::{roles, Opaque, Roles};

use crate::pm::format::{mem_human, percent, state_label, u32_decimal};
use crate::pm::format_sys::rate_human;
use crate::pm::state::Row;

use super::chrome::Rect;
use super::metrics::{BODY_PX, CELL_PAD_X, NUM_PX, RISK_SLOT_H, ROW_H};
use super::table_geom::{self, Col};
use super::tint::state_tint;
use super::{risk_strip, text};

// Every numeric cell is placed from its right edge so the digits form a column
// the eye can compare down. Name belongs to the row painter, which owns the
// protected mark that shifts the text.
pub fn paint(fb: &mut PaintBuffer, r: &Rect, cols: &[Col], row: &Row, col: Col, y: u32) {
    let x = r.x + table_geom::col_x(cols, r.w, col);
    let right = x + table_geom::col_w(cols, r.w, col).saturating_sub(CELL_PAD_X);
    let (c, top) = (roles(), text::centred_top(y, ROW_H, BODY_PX));
    let mut buf = [0u8; 24];
    let (n, tint) = match col {
        Col::Pid => (u32_decimal(row.pid, &mut buf), c.muted),
        Col::Cpu => (percent(row.cpu_pct, &mut buf), c.text_2),
        Col::Mem => (mem_human(row.mem_kb, &mut buf), c.text_2),
        Col::Ipc => (rate_human(row.ipc_ps, &mut buf), rate_tint(&c, row.ipc_ps)),
        Col::Sysc => (rate_human(row.sysc_ps, &mut buf), rate_tint(&c, row.sysc_ps)),
        Col::State => {
            let ink = state_tint(row.state).colour(&c);
            text::left(fb, x, top, state_label(row.state), ink, BODY_PX);
            return;
        }
        Col::Auth => {
            risk_strip::paint(fb, x, y + (ROW_H - RISK_SLOT_H) / 2, row.caps);
            return;
        }
        Col::Name => return,
    };
    text::mono_right(fb, right, top, &buf[..n], tint, NUM_PX);
}

// A zero rate is the common case and reads quietest; anything moving is ink.
fn rate_tint(c: &Roles, per_second: u32) -> Opaque {
    if per_second == 0 {
        c.muted
    } else {
        c.text_2
    }
}
