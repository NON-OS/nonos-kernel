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

use super::types::DecodedImage;
use super::{decode_bmp, decode_png};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Bmp,
    Png,
    Unknown,
}

pub fn detect_format(data: &[u8]) -> ImageFormat {
    if data.len() < 8 {
        return ImageFormat::Unknown;
    }

    if data.len() >= 2 && data[0] == b'B' && data[1] == b'M' {
        return ImageFormat::Bmp;
    }

    if data.len() >= 8 && &data[0..8] == b"\x89PNG\r\n\x1a\n" {
        return ImageFormat::Png;
    }

    ImageFormat::Unknown
}

pub fn decode(data: &[u8]) -> Option<DecodedImage> {
    match detect_format(data) {
        ImageFormat::Bmp => decode_bmp(data),
        ImageFormat::Png => decode_png(data),
        ImageFormat::Unknown => None,
    }
}
