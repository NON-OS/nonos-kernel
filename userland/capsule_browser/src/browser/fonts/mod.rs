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

mod collect;
mod draw_text;
mod em_units;
mod ingest;
mod key;
mod pick_src;
mod registry;
mod run_face;
mod sfnt_header;
mod text;
mod woff;
mod woff2;

pub use collect::collect_font_faces;
pub use draw_text::draw_text;
pub use em_units::{ch_px, ex_px};
pub use ingest::ingest_font;
pub use key::{family_key, weight_of, weighted};
pub use registry::{clear, swap_faces, with_face, Faces};
pub use text::{content_height, measure_text, TextRun, NO_CLIP};
