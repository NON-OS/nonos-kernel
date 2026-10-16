// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Launchpad page indicator dots.

use super::grid::dots_band;
use super::view::pages;
use crate::render::surface::surface;
use crate::render::ui_font::px;
use crate::state::Context;

const R: u32 = 4;
const GAP: u32 = 16;

fn layout(ctx: &Context) -> (u32, u32, u32, usize) {
    let n = pages(ctx);
    let r = px(R);
    let step = 2 * r + px(GAP);
    let total = (n as u32) * step - px(GAP);
    let x = ctx.width.saturating_sub(total) / 2 + r;
    let y = ctx.height.saturating_sub(dots_band() / 2);
    (x, y, step, n)
}

pub(super) fn paint(ctx: &Context) {
    let (x0, y, step, n) = layout(ctx);
    if n < 2 {
        return;
    }
    let r = px(R);
    let mut buf = surface(ctx);
    for i in 0..n {
        let argb = if i == ctx.launchpad_page { ctx.palette.accent } else { ctx.palette.text_dim };
        buf.circle(x0 + (i as u32) * step, y, r, argb);
    }
}

pub(crate) fn hit(ctx: &Context, x: u32, py: u32) -> Option<usize> {
    let (x0, y, step, n) = layout(ctx);
    if n < 2 {
        return None;
    }
    let r = px(R) * 2;
    if py + r < y || py > y + r {
        return None;
    }
    for i in 0..n {
        let cx = x0 + (i as u32) * step;
        if x + r >= cx && x <= cx + r {
            return Some(i);
        }
    }
    None
}
