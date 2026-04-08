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

mod types;
mod parser;
mod render;
mod browser;
mod png;
mod svg;
mod jpeg;
pub mod css;
pub mod layout;
pub mod image_loader;

pub use types::{
    Document, Node, NodeType, Link, Form, FormInput, Image, ImageData,
    RenderLine, RenderElement, RenderContent, TextStyle, TextAlign, RenderOutput,
    CanvasContext2D, AnimationState, AnimatedProperty,
};
pub use parser::parse_html;
pub use render::{render_page, render_page_with_url, render_to_lines, render_to_lines_with_links};
pub use browser::BrowserEngine;
pub use png::decode_png;
pub use jpeg::decode_jpeg;
pub use svg::render_svg;
