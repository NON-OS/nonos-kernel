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

use super::layout::{
    bottom_dock_rect, dock_box_inset, dock_divider_w, dock_gap, dock_pad, launchpad_slot_x,
    taskbar_entry_w, Rect,
};
use super::surface::surface;
use super::ui_font;
use crate::state::{Context, DOCK_APPS, LAUNCHER_APPS, TASKBAR_NO_ACTIVE};

const TILE_RADIUS_LOGICAL: u32 = 10;

fn icon_size() -> u32 {
    taskbar_entry_w()
}

// The rule between the app run and the Launchpad slot.
fn draw_divider(ctx: &Context, box_top: u32, box_h: u32) {
    let slot_x = launchpad_slot_x(bottom_dock_rect(ctx.width, ctx.height));
    let sc = ui_font::scale();
    let h = box_h.saturating_sub(ui_font::px(12));
    let x = slot_x.saturating_sub(dock_divider_w() / 2);
    surface(ctx).blend_rect(x, box_top + (box_h - h) / 2, sc, h, ctx.palette.line);
}

// The Launchpad button: the familiar 3x3 grid, sitting in the dock slot just
// past the last app.
/// The launchpad button: the brand mark, at the end of the dock.
///
/// It was a three by three grid of dots, which is the generic "more" glyph
/// every launcher uses and says nothing about whose machine this is. The mark
/// is already rasterised from the brand SVG and drawn elsewhere in this shell;
/// the one place a person looks for the system itself was the one place it did
/// not appear.
fn draw_launchpad_button(ctx: &Context, box_top: u32, box_h: u32) {
    let slot_x = launchpad_slot_x(bottom_dock_rect(ctx.width, ctx.height));
    // Sized to the tile the way an app icon is, so the row reads evenly rather
    // than ending on something larger or smaller than its neighbours.
    let size = icon_size();
    let x = slot_x + (taskbar_entry_w().saturating_sub(size)) / 2;
    let y = box_top + (box_h.saturating_sub(size)) / 2;
    super::icons::draw_logo(ctx, x, y, size);
}

// The running indicator: a dot under the tile, accented when the app holds
// focus and dimmed when it is merely open.
fn running_dot(ctx: &Context, cx: u32, active: bool) {
    let dock = bottom_dock_rect(ctx.width, ctx.height);
    let cy = dock.y + dock.height - ui_font::px(2);
    let argb = if active { ctx.palette.accent } else { ctx.palette.accent_dim };
    surface(ctx).circle(cx, cy, ui_font::px(2), argb);
}

pub fn paint_bottom_taskbar(ctx: &Context) {
    let dock = bottom_dock_rect(ctx.width, ctx.height);
    let box_top = dock.y + dock_box_inset();
    let box_h = dock.height - 2 * dock_box_inset();
    let mut x = dock.x + dock_pad();
    let p = &ctx.palette;
    for (index, app) in LAUNCHER_APPS.iter().enumerate().take(DOCK_APPS) {
        let open = ctx.taskbar.open[index];
        let active =
            ctx.taskbar.active != TASKBAR_NO_ACTIVE && ctx.taskbar.active as usize == index;
        let pulsing = ctx.taskbar.pulse_until_ms[index] > 0;
        let bg = if active {
            p.tile_active
        } else if pulsing {
            p.tile_pulse
        } else if open {
            p.tile_open
        } else {
            super::off_tile::idle_fill(p, app.service)
        };
        let tile = Rect { x, y: box_top, width: taskbar_entry_w(), height: box_h };
        let edge = if active || pulsing { p.line_hard } else { p.line_soft };
        super::panel::panel(ctx, tile, TILE_RADIUS_LOGICAL, bg, edge);
        if open || active || pulsing {
            running_dot(ctx, x + taskbar_entry_w() / 2, active);
        }
        super::off_tile::dock_glyph(ctx, x, box_top, app, icon_size());
        x += taskbar_entry_w() + dock_gap();
    }
    draw_divider(ctx, box_top, box_h);
    draw_launchpad_button(ctx, box_top, box_h);
}
