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

pub mod a11y;
mod browser;
pub mod canvas;
pub mod css;
pub mod dom;
pub mod events;
pub mod fonts;
pub mod image_loader;
mod jpeg;
pub mod layout;
pub mod media;
mod parser;
mod png;
mod render;
mod svg;
mod types;

pub use browser::BrowserEngine;
pub use jpeg::decode_jpeg;
pub use parser::parse_html;
pub use png::decode_png;
pub use render::{render_page, render_page_with_url, render_to_lines, render_to_lines_with_links};
pub use svg::render_svg;
pub use types::{
    AnimatedProperty, AnimationState, CanvasContext2D, Document, Form, FormInput, Image, ImageData,
    Link, Node, NodeType, RenderContent, RenderElement, RenderLine, RenderOutput, TextAlign,
    TextStyle,
};
