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

extern crate alloc;

use super::super::ImageData;
use super::resolve::resolve_url;
use super::state::{FETCH_DISABLED, IMAGE_LOAD_COUNT};
use super::types::{ImageFormat, MAX_DIMENSION, MAX_IMAGES_PER_PAGE, MAX_IMAGE_BYTES};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

pub fn detect_image_format(data: &[u8]) -> ImageFormat {
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8 {
        ImageFormat::Jpeg
    } else if data.len() >= 8 && data[0..8] == *b"\x89PNG\r\n\x1a\n" {
        ImageFormat::Png
    } else {
        ImageFormat::Unknown
    }
}

fn fetch_image_bytes(url: &str) -> Option<Vec<u8>> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return None;
    }
    let response = crate::network::http_client::fetch_response(url).ok()?;
    if !response.is_success() {
        return None;
    }
    if response.body.len() > MAX_IMAGE_BYTES {
        return None;
    }
    Some(response.body)
}

pub fn load_image(src: &str, base_url: &str) -> Option<ImageData> {
    if FETCH_DISABLED.load(Ordering::Acquire) {
        return None;
    }
    let count = IMAGE_LOAD_COUNT.fetch_add(1, Ordering::Relaxed);
    if count >= MAX_IMAGES_PER_PAGE {
        return None;
    }
    let url = resolve_url(src, base_url)?;
    let data = fetch_image_bytes(&url)?;
    let image = match detect_image_format(&data) {
        ImageFormat::Jpeg => super::super::decode_jpeg(&data),
        ImageFormat::Png => super::super::decode_png(&data),
        ImageFormat::Unknown => None,
    }?;
    if image.width > MAX_DIMENSION || image.height > MAX_DIMENSION {
        return None;
    }
    Some(image)
}
