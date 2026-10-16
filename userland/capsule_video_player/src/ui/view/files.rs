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

//! Folders: the roots the catalogue reads down the left, each with the number
//! of videos found in it, and the chosen folder's videos on the right with an
//! Open button. Every rect a click is tested against is computed here.

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::roles;

use super::grid::{paint_grid, paint_list};
use crate::app::state::VideoApp;
use crate::catalog::folders::{in_folder, LABELS};
use crate::catalog::says::library_unavailable;
use crate::ui::format::count;
use crate::ui::icon;
use crate::ui::layout::Rect;
use crate::ui::paint::{rrect, shape};
use crate::ui::text::{center_y, BODY_PX};
use crate::ui::widget::button::{paint_button, Tone};
use crate::ui::widget::empty::paint_empty;

const RAIL_W: u32 = 190;
const GAP: u32 = 20;
const ROW_H: u32 = 36;
const RAIL_TOP: u32 = 28;
const ACTIONS_H: u32 = 52;
const BTN_W: u32 = 130;
const BTN_H: u32 = 38;

/// Row `i` of the rail: 0 is every folder, then one row per root.
pub fn rail_row(body: Rect, i: usize) -> Rect {
    Rect { x: body.x, y: body.y + RAIL_TOP + i as u32 * ROW_H, w: RAIL_W, h: ROW_H }
}

/// The folder a click on the rail picks: `Some(None)` for every folder.
pub fn folder_at(body: Rect, x: i32, y: i32) -> Option<Option<usize>> {
    (0..=LABELS.len()).find(|&i| rail_row(body, i).contains(x, y)).map(|i| {
        if i == 0 {
            None
        } else {
            Some(i - 1)
        }
    })
}

/// Where the chosen folder's videos are drawn.
pub fn area(body: Rect) -> Rect {
    let x = body.x + RAIL_W + GAP;
    Rect {
        x,
        y: body.y,
        w: body.w.saturating_sub(RAIL_W + GAP),
        h: body.h.saturating_sub(ACTIONS_H),
    }
}

pub fn open_button(body: Rect) -> Rect {
    let a = area(body);
    let y = body.y + body.h.saturating_sub(BTN_H);
    Rect { x: (a.x + a.w).saturating_sub(BTN_W), y, w: BTN_W, h: BTN_H }
}

fn paint_rail(fb: &mut PaintBuffer, app: &VideoApp, body: Rect) {
    let theme = roles();
    fb.text_ttf(body.x as i32, body.y as i32, "FOLDERS", theme.muted.argb(), BODY_PX);
    let items = &app.browse.items;
    for i in 0..=LABELS.len() {
        let r = rail_row(body, i);
        let (name, n) = match i {
            0 => ("All folders", items.len()),
            _ => (LABELS[i - 1], items.iter().filter(|m| in_folder(&m.path, i - 1)).count()),
        };
        let active = app.browse.folder == i.checked_sub(1);
        let ink = if active { theme.accent } else { theme.muted }.argb();
        if active {
            rrect::fill_round(fb, r.x, r.y, r.w, r.h, 8, theme.raised.argb());
        }
        icon::nav::files(fb, r.x + 8, r.y + r.h.saturating_sub(18) / 2, 18, ink);
        fb.text_ttf((r.x + 34) as i32, center_y(r.y, r.h), name, ink, BODY_PX);
        let tally = alloc::format!("{}", n);
        let tw = fb.measure_ttf(&tally, BODY_PX).max(0) as u32;
        let tx = (r.x + r.w).saturating_sub(tw + 10);
        fb.text_ttf(tx as i32, center_y(r.y, r.h), &tally, theme.muted.argb(), BODY_PX);
    }
    shape::vline(fb, body.x + RAIL_W, body.y, body.h, theme.border.argb());
}

pub fn paint(fb: &mut PaintBuffer, app: &VideoApp, body: Rect) {
    paint_rail(fb, app, body);
    let right = area(body);
    if app.browse.items.is_empty() {
        let (head, note) = library_unavailable(app.browse.scanned, app.browse.scan_error)
            .unwrap_or(("No videos found", "None of these folders holds a Motion-JPEG .avi"));
        paint_empty(fb, right, icon::nav::files, head, note);
        return;
    }
    if app.browse.is_empty() {
        let note = if app.browse.query.is_empty() {
            "No video in this folder"
        } else {
            "No video in this folder matches that search"
        };
        paint_empty(fb, right, icon::nav::files, "Nothing here", note);
        return;
    }
    if app.browse.grid {
        paint_grid(fb, &app.browse, right);
    } else {
        paint_list(fb, &app.browse, right);
    }
    let tally = count(app.browse.len(), "video", "videos");
    let b = open_button(body);
    fb.text_ttf(right.x as i32, center_y(b.y, b.h), &tally, roles().muted.argb(), BODY_PX);
    paint_button(fb, b, "Open", Tone::Primary);
}
