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

pub mod bmp;
pub mod format;
pub mod lz4_raw;
pub mod png;
pub mod types;

pub use bmp::decode_bmp;
pub use format::{decode, detect_format, ImageFormat};
pub use lz4_raw::decode_lz4_raw;
pub use png::decode_png;
pub use types::{draw_wallpaper, DecodedImage};
