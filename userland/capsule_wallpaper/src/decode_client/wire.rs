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

use nonos_toolkit::image::{
    bmp::decode_bmp_argb8888,
    jpeg::decode_jpeg_argb8888,
    lz4_raw::decode_lz4_raw_argb8888,
    png::decoder::decode_png_argb8888,
    types::{DecodeError, ImageSize},
};

use super::header::{DecodeKind, DecodeReq};

pub fn decode_argb(req: &DecodeReq<'_>, out: &mut [u32]) -> Result<ImageSize, DecodeError> {
    match req.kind {
        DecodeKind::Png => decode_png_argb8888(req.payload, out),
        DecodeKind::Bmp => decode_bmp_argb8888(req.payload, out),
        DecodeKind::Lz4Raw => decode_lz4_raw_argb8888(req.width, req.height, req.payload, out),
        DecodeKind::Jpeg => decode_jpeg_argb8888(req.payload, out),
    }
}
