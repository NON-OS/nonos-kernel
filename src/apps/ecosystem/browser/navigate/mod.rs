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

mod api;
pub mod chunked;
pub mod compression;
mod decompress;
mod http;
pub mod http2;
mod https;
mod image_fetch;
mod response;
mod state;
mod url;

pub use api::{
    cancel_navigation, is_navigating, is_running, navigate, navigate_with_post, poll_navigation,
    start, stop,
};
pub use chunked::{decode_chunked, encode_chunked, is_chunked_encoding};
pub use compression::{
    accept_encoding_header, content_encoding, needs_decompression, supports_brotli, supports_gzip,
};
