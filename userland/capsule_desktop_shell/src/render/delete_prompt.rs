// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Paint the question a desktop Delete asks: the same centred panel as the
//! other prompts, naming the item, with Delete and Cancel.

use alloc::format;

use super::consent::{border, button, fill, line, margin, wrap_at};
use crate::render::ui_font::{line_h, TITLE_PX, UI_PX};
use crate::server::handlers::delete_prompt::{cancel_rect, delete_rect, panel_rect};
use crate::state::dialog_keys::Choice;
use crate::state::Context;

/// A red, so the button that loses the file does not read as the safe one.
const DELETE_BG: u32 = 0xFFA1_2A2A;
const FILE_NOTE: &str =
    "The file is removed from your desktop. There is no Trash to get it back from.";
const FOLDER_NOTE: &str =
    "The folder and everything in it are removed. There is no Trash to get them back from.";

pub fn paint_delete_prompt(ctx: &Context) {
    let Some(target) = ctx.pending_delete.target() else {
        return;
    };
    let c = ctx.palette.prompt;
    let p = panel_rect(ctx.width, ctx.height);
    fill(ctx, p, c.panel);
    border(ctx, p, c.border);
    let x = p.x + margin();
    let max_w = p.width.saturating_sub(margin() * 2);
    let mut y = p.y + margin();
    let title = format!("Delete \"{}\"?", target.name);
    line(ctx, x, y, &title, c.fg, TITLE_PX, max_w);
    y += line_h(TITLE_PX) + line_h(UI_PX) / 3;
    let buttons = delete_rect(ctx.width, ctx.height);
    let mut rest = if target.is_dir { FOLDER_NOTE } else { FILE_NOTE };
    while !rest.is_empty() && y + line_h(UI_PX) <= buttons.y {
        let end = wrap_at(rest, UI_PX, max_w);
        line(ctx, x, y, &rest[..end], c.dim, UI_PX, max_w);
        rest = rest[end..].trim_start();
        y += line_h(UI_PX);
    }
    let act = ctx.dialog_focus.focused() == Choice::Act;
    button(ctx, buttons, DELETE_BG, c.ink_on(DELETE_BG), "Delete", act);
    button(ctx, cancel_rect(ctx.width, ctx.height), c.cancel, c.cancel_fg, "Cancel", !act);
}
