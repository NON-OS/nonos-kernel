// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Paint the third-party-app consent modal above the desktop: a centred panel
//! carrying a title, the app name, a permissions note, and Approve / Cancel
//! buttons. Button rects come from the handler so paint and hit-test agree.
//! Every width is measured from the face, so nothing the user must read before
//! granting a capability can silently run past the panel edge.

use crate::render::fill::fill_rect;
use crate::render::layout::Rect;
use crate::render::measure_aa::{measure_aa, truncate_to_width};
use crate::render::text_aa::text_aa;
use crate::render::ui_font;
use crate::render::ui_font::{line_h, top_y_centered, valid_str, TITLE_PX, UI_PX};
use crate::server::handlers::consent::{approve_rect, cancel_rect, panel_rect};
use crate::state::dialog_keys::Choice;
use crate::state::Context;
use nonos_toolkit::theme::contrast::{at_least, LARGE};

const MARGIN_LOGICAL: u32 = 20;

const ELLIPSIS: &str = "...";
const TITLE: &str = "Launch third-party app?";
const NOTE: &str = "Its signature is checked as it loads; it gets only its manifest's permissions.";

pub(super) fn margin() -> u32 {
    ui_font::px(MARGIN_LOGICAL)
}

pub fn paint_consent(ctx: &Context) {
    let Some(name) = ctx.pending_consent.as_deref() else {
        return;
    };
    let c = ctx.palette.prompt;
    let p = panel_rect(ctx.width, ctx.height);
    fill(ctx, p, c.panel);
    border(ctx, p, c.border);
    let x = p.x + margin();
    let max_w = p.width.saturating_sub(margin() * 2);
    let mut y = p.y + margin();
    line(ctx, x, y, TITLE, c.fg, TITLE_PX, max_w);
    y += line_h(TITLE_PX);
    line(ctx, x, y, valid_str(name), c.fg, UI_PX, max_w);
    y += line_h(UI_PX);
    note(ctx, x, y, max_w);
    let act = ctx.dialog_focus.focused() == Choice::Act;
    button(ctx, approve_rect(ctx.width, ctx.height), c.approve, c.approve_fg, "Approve", act);
    button(ctx, cancel_rect(ctx.width, ctx.height), c.cancel, c.cancel_fg, "Cancel", !act);
}

fn note(ctx: &Context, x: u32, top_y: u32, max_w: u32) {
    let mut rest = NOTE;
    let mut y = top_y;
    while !rest.is_empty() {
        let end = wrap_at(rest, UI_PX, max_w);
        line(ctx, x, y, &rest[..end], ctx.palette.prompt.dim, UI_PX, max_w);
        rest = rest[end..].trim_start();
        y += line_h(UI_PX);
    }
}

pub(super) fn line(ctx: &Context, x: u32, top_y: u32, text: &str, argb: u32, px: f32, max_w: u32) {
    let fitted = truncate_to_width(text, px, max_w);
    if fitted.len() == text.len() {
        text_aa(ctx, x, top_y, text, argb, px);
        return;
    }
    let room = max_w.saturating_sub(measure_aa(ELLIPSIS, px));
    let cut = truncate_to_width(text, px, room);
    let advance = text_aa(ctx, x, top_y, cut, argb, px);
    text_aa(ctx, x + advance, top_y, ELLIPSIS, argb, px);
}

pub(super) fn wrap_at(text: &str, px: f32, max_w: u32) -> usize {
    let fitted = truncate_to_width(text, px, max_w);
    if fitted.len() == text.len() {
        return text.len();
    }
    match fitted.rfind(' ') {
        Some(i) if i > 0 => i,
        _ if !fitted.is_empty() => fitted.len(),
        _ => text.char_indices().nth(1).map_or(text.len(), |(i, _)| i),
    }
}

/// A dialog button; the one the keyboard is on (state::dialog_keys) wears
/// a ring in the accent, so Enter's target is never a guess. Where the accent
/// would not stand out from the button's own fill, the ring takes `ink`, the
/// label's colour, which reads on that fill.
pub(super) fn button(ctx: &Context, r: Rect, bg: u32, ink: u32, label: &str, focused: bool) {
    fill(ctx, r, bg);
    border(ctx, r, ctx.palette.prompt.border);
    if focused {
        let s = ui_font::scale();
        let accent = ctx.palette.accent;
        let ring = if at_least(accent, bg, LARGE) { accent } else { ink };
        border(ctx, r, ring);
        let inner = Rect {
            x: r.x + s,
            y: r.y + s,
            width: r.width.saturating_sub(2 * s),
            height: r.height.saturating_sub(2 * s),
        };
        border(ctx, inner, ring);
    }
    let inner = r.width.saturating_sub(ui_font::px(8));
    let fitted = truncate_to_width(label, UI_PX, inner);
    let tx = r.x + r.width.saturating_sub(measure_aa(fitted, UI_PX)) / 2;
    text_aa(ctx, tx, top_y_centered(r.y, r.height, UI_PX), fitted, ink, UI_PX);
}

pub(super) fn fill(ctx: &Context, r: Rect, argb: u32) {
    fill_rect(ctx.backing_va, ctx.stride, ctx.width, ctx.height, r.x, r.y, r.width, r.height, argb);
}

pub(super) fn border(ctx: &Context, r: Rect, argb: u32) {
    let (va, st, w, h) = (ctx.backing_va, ctx.stride, ctx.width, ctx.height);
    let s = ui_font::scale();
    fill_rect(va, st, w, h, r.x, r.y, r.width, s, argb);
    fill_rect(va, st, w, h, r.x, r.y + r.height.saturating_sub(s), r.width, s, argb);
    fill_rect(va, st, w, h, r.x, r.y, s, r.height, argb);
    fill_rect(va, st, w, h, r.x + r.width.saturating_sub(s), r.y, s, r.height, argb);
}
