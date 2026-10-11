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

mod band;
mod bg_image;
mod bg_tile;
mod blit_rows;
mod border_corners;
mod borders;
mod box_fragment;
mod box_page;
mod bubble;
mod canvas;
mod clip;
mod corners;
pub mod document;
mod fade;
mod field_text;
mod fill_page;
mod fill_rounded;
mod glyph;
mod grad;
mod mask;
mod mask_weights;
mod masked;
mod page_parts;
mod paint;
mod paint_image;
mod paint_text;
mod region;
mod round_clip;
mod rows;
mod scroll_paint;
mod select_list;
mod shadow;
mod short_notice;
mod sidebar;
pub mod start;
mod tinted;
pub mod tokens;
pub mod toolbar;

pub(crate) use band::band_rows;
pub(crate) use field_text::{field_text, FieldInk};
pub use paint::paint;
