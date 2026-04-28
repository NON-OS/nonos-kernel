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

extern crate alloc;

use super::context::RenderContext;
use crate::apps::ecosystem::browser::engine::types::{RenderContent, RenderElement};
use alloc::vec::Vec;

pub(super) fn render_text(ctx: &mut RenderContext, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        return;
    }

    let extra_margin = ctx.indent_level * ctx.indent_px;

    for word in text.split_whitespace() {
        if ctx.is_full() {
            return;
        }
        let word_width = (word.len() as u32) * ctx.char_width;
        let available = ctx.usable_width.saturating_sub(extra_margin);

        if ctx.current_x + word_width > available && ctx.current_x > 0 {
            ctx.flush_line();
            if ctx.is_full() {
                return;
            }
        }

        ctx.current_line_elements.push(RenderElement {
            x: ctx.margin + extra_margin + ctx.current_x,
            width: word_width + ctx.char_width,
            content: RenderContent::Text {
                text: alloc::format!("{} ", word),
                style: ctx.current_style,
            },
        });
        ctx.current_x += word_width + ctx.char_width;
    }
}
