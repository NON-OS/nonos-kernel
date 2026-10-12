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

/* Real raster images for the document view. Sources discovered during
 * layout are fetched through the same socket state machine as pages,
 * decoded (PNG, JPEG, GIF, BMP, WebP, ICO, SVG) into ARGB8888 at the size
 * they are drawn, cached under a byte budget, and scale-blitted into their
 * box. */
mod blit;
mod data_uri;
mod decode;
mod decode_full;
#[cfg(not(feature = "harness"))]
mod fetch;
mod ico;
mod ico_dib;
mod ingest;
mod jpeg;
mod plan;
mod plan_vector;
#[cfg(not(feature = "harness"))]
mod queue;
mod resident;
#[cfg(not(feature = "harness"))]
mod revival;
#[cfg(not(feature = "harness"))]
mod revive;
mod shrink;
mod sniff;
mod store;
mod store_blur;
mod store_budget;
mod store_entry;
mod store_hint;
mod store_lookup;
mod store_natural;
mod svg;
mod webp;

pub use blit::{blit_into, blit_rect};
pub(crate) use data_uri::data_uri_bytes;
#[cfg(feature = "harness")]
pub use decode::{decode_body, natural};
#[cfg(not(feature = "harness"))]
pub use fetch::{follow_redirect, pump};
pub use ingest::ingest;
#[cfg(feature = "harness")]
pub use ingest::{note_img_size, note_size};
#[cfg(not(feature = "harness"))]
pub use queue::enqueue_from_doc;
#[cfg(not(feature = "harness"))]
pub use revive::requeue_visible;
pub use store::{Decoded, Store};
