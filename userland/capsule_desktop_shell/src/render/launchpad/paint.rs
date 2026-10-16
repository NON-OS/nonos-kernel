// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Paint the Launchpad: a full-screen wash in the theme's ground, a title,
//! the search pill, the tiles of the current page, and the page dots. A
//! search that leaves nothing standing says so, and how to get back, instead
//! of an empty wash.

use super::grid::{grid_top, title_y};
use super::view::page_slice;
use super::{dots, search, tile};
use crate::render::fill::fill_rect;
use crate::render::measure_aa::measure_aa_bytes;
use crate::render::text_aa::text_aa_bytes;
use crate::render::ui_font::{line_h, TITLE_PX, UI_PX};
use crate::state::says::launchpad_empty;
use crate::state::Context;

const TITLE: &[u8] = b"Applications";

pub fn paint_launchpad(ctx: &Context) {
    fill_rect(
        ctx.backing_va,
        ctx.stride,
        ctx.width,
        ctx.height,
        0,
        0,
        ctx.width,
        ctx.height,
        ctx.palette.launchpad,
    );
    let title_x = ctx.width.saturating_sub(measure_aa_bytes(TITLE, TITLE_PX)) / 2;
    text_aa_bytes(ctx, title_x, title_y(), TITLE, ctx.palette.text, TITLE_PX);
    search::paint(ctx);
    for (i, t) in page_slice(ctx).iter().enumerate() {
        tile::paint(ctx, i, *t);
    }
    if let Some(lines) = launchpad_empty(&ctx.launchpad_query, ctx.launchpad_view.len()) {
        let mut y = grid_top();
        for (i, line) in lines.iter().enumerate() {
            let x = ctx.width.saturating_sub(measure_aa_bytes(line.as_bytes(), UI_PX)) / 2;
            let fg = if i == 0 { ctx.palette.text } else { ctx.palette.text_dim };
            text_aa_bytes(ctx, x, y, line.as_bytes(), fg, UI_PX);
            y += line_h(UI_PX);
        }
    }
    dots::paint(ctx);
}
