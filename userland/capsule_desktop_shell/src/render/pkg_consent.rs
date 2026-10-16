// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Paint the package install-consent modal: the kernel-verified slug, its
//! publisher namespace, the trust tier, and the capability ceiling. The
//! capability list wraps into the space above the buttons; when even that is
//! not enough the last line says so instead of dropping a granted capability.

use alloc::vec::Vec;

use super::consent::{border, button, fill, line, margin, wrap_at};
use crate::render::ui_font::{line_h, valid_str, TITLE_PX, UI_PX};
use crate::server::handlers::pkg_consent::{approve_rect, cancel_rect, panel_rect};
use crate::state::dialog_keys::Choice;
use crate::state::Context;

const TITLE: &str = "Install package?";
const TRUNCATED: &str = "! caps hidden - do not approve";

pub fn paint_pkg_consent(ctx: &Context) {
    let Some(prompt) = ctx.pending_pkg_install.as_ref() else {
        return;
    };
    let c = ctx.palette.prompt;
    let p = panel_rect(ctx.width, ctx.height);
    fill(ctx, p, c.panel);
    border(ctx, p, c.border);
    let s = &prompt.summary;
    let tier = if s.tier == 2 { "Publisher-signed" } else { "NONOS-enrolled" };
    let mut caps = Vec::with_capacity(320);
    caps.extend_from_slice(b"Caps: ");
    super::cap_names::append(s.caps, &mut caps);
    let approve = approve_rect(ctx.width, ctx.height);
    let x = p.x + margin();
    let max_w = p.width.saturating_sub(margin() * 2);
    let mut y = p.y + margin();
    line(ctx, x, y, TITLE, c.fg, TITLE_PX, max_w);
    y += line_h(TITLE_PX);
    line(ctx, x, y, valid_str(&s.slug), c.fg, UI_PX, max_w);
    y += line_h(UI_PX);
    line(ctx, x, y, valid_str(&s.namespace), c.dim, UI_PX, max_w);
    y += line_h(UI_PX);
    line(ctx, x, y, tier, c.dim, UI_PX, max_w);
    y += line_h(UI_PX);
    paint_caps(ctx, x, y, approve.y, max_w, valid_str(&caps));
    let act = ctx.dialog_focus.focused() == Choice::Act;
    button(ctx, approve, c.approve, c.approve_fg, "Approve", act);
    button(ctx, cancel_rect(ctx.width, ctx.height), c.cancel, c.cancel_fg, "Cancel", !act);
}

fn paint_caps(ctx: &Context, x: u32, top_y: u32, buttons_y: u32, max_w: u32, caps: &str) {
    let lh = line_h(UI_PX).max(1);
    let budget = core::cmp::max(1, buttons_y.saturating_sub(top_y) / lh);
    let mut rest = caps;
    let mut drawn = 0u32;
    while !rest.is_empty() && drawn < budget {
        let end = wrap_at(rest, UI_PX, max_w);
        let y = top_y + drawn * lh;
        if drawn + 1 == budget && end < rest.len() {
            line(ctx, x, y, TRUNCATED, ctx.palette.prompt.warn, UI_PX, max_w);
            return;
        }
        line(ctx, x, y, &rest[..end], ctx.palette.prompt.dim, UI_PX, max_w);
        rest = rest[end..].trim_start();
        drawn += 1;
    }
}
