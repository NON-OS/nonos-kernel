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

use super::layout::bottom_dock_rect;
use super::paint_bottom_taskbar;
use crate::state::Context;

mod clear_overlay;
mod constants;

pub fn paint_chrome(ctx: &mut Context) {
    let frame_start = crate::frametime::begin();
    ctx.palette = super::palette::current();
    let row_words = (ctx.stride / 4) as usize;
    let words = row_words * ctx.height as usize;
    let (desk, chrome) = (ctx.desk_va, ctx.chrome_va);
    // Every painter draws on `backing_va`; it points at the off-screen frame
    // for each pass, and at the chrome again after them.
    let mut back = core::mem::take(&mut ctx.back);
    super::whole_frame::draw_whole(&mut back, desk, words, row_words, |va| {
        ctx.backing_va = va;
        paint_desk(ctx);
    });
    super::whole_frame::draw_whole(&mut back, chrome, words, row_words, |va| {
        ctx.backing_va = va;
        paint_over_windows(ctx);
    });
    ctx.back = back;
    ctx.backing_va = chrome;
    crate::frametime::end(frame_start);
}

/// The chrome band: everything the shell draws over the windows.
fn paint_over_windows(ctx: &mut Context) {
    clear_overlay::clear_overlay(ctx);
    super::topbar::paint(ctx);
    // A dragged icon rides under the cursor, over every window, until it is
    // dropped.
    super::desktop_icons::paint_drag_ghost(ctx);
    if ctx.taskbar.visible {
        super::panel::shadow_panel(
            ctx,
            bottom_dock_rect(ctx.width, ctx.height),
            super::palette::R_DOCK,
            ctx.palette.dock,
            ctx.palette.line,
        );
        paint_bottom_taskbar(ctx);
    }
    // The Launchpad, when open, covers the whole desktop and its dock.
    if ctx.launchpad {
        super::launchpad::paint_launchpad(ctx);
    }
    // The right-click menu floats above everything else, dock included.
    super::desktop_menu::paint(ctx);
    super::menubar_menu::paint(ctx);
    // The consent modal draws last so it sits above every other layer.
    super::consent::paint_consent(ctx);
    super::pkg_consent::paint_pkg_consent(ctx);
    super::live_prompt::paint_live_prompt(ctx);
    super::delete_prompt::paint_delete_prompt(ctx);
    super::toasts::paint_in_chrome(ctx);
}

/// The desktop's icons go on the desk surface, under every window.
fn paint_desk(ctx: &mut Context) {
    clear_overlay::clear_overlay(ctx);
    super::desktop_icons::paint_desktop_icons(ctx);
}
