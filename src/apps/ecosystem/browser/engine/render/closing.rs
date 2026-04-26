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

use super::context::RenderContext;

pub(super) fn handle_closing_tag(ctx: &mut RenderContext, tag: &str) {
    match tag {
        "b" | "strong" | "i" | "em" | "u" | "code" | "pre" | "th" => {}
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            if !ctx.current_line_elements.is_empty() {
                ctx.flush_line();
                ctx.current_y += ctx.line_height;
            }
        }
        "blockquote" => {
            ctx.flush_line();
            if ctx.indent_level > 0 { ctx.indent_level -= 1; }
        }
        "p" | "div" | "li" | "tr" | "table" | "nav" | "header" | "footer"
        | "section" | "article" | "aside" | "main" | "figure" | "details" => {
            ctx.flush_line();
        }
        "ul" | "ol" => {
            ctx.flush_line();
        }
        "form" => {
            ctx.flush_line();
            ctx.form_action = None;
            ctx.form_method = None;
        }
        _ => {}
    }
    if let Some(s) = ctx.style_stack.pop() { ctx.current_style = s; }
}
