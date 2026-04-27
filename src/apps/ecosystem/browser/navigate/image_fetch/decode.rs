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

use super::body::extract_img_body;
use super::queue::skip_current_image;
use super::types::*;
use crate::apps::ecosystem::browser::engine;
use crate::graphics::window::ecosystem::state as window_state;
use core::sync::atomic::Ordering;

pub(super) fn poll_img_decode() {
    let response_data = IMG_RESPONSE.lock().clone();
    if response_data.is_empty() {
        skip_current_image();
        return;
    }
    let body = extract_img_body(&response_data);
    if body.is_empty() {
        crate::sys::serial::println(b"[IMG-FETCH] empty body");
        skip_current_image();
        return;
    }
    crate::sys::serial::print(b"[IMG-FETCH] decode body=");
    crate::sys::serial::print_dec(body.len() as u64);
    crate::sys::serial::println(b"");
    let format = engine::image_loader::detect_image_format(&body);
    let decoded = match format {
        engine::image_loader::ImageFormat::Jpeg => engine::decode_jpeg(&body),
        engine::image_loader::ImageFormat::Png => engine::decode_png(&body),
        engine::image_loader::ImageFormat::Unknown => {
            crate::sys::serial::println(b"[IMG-FETCH] unknown format");
            None
        }
    };
    match decoded {
        Some(data) => {
            crate::sys::serial::print(b"[IMG-FETCH] decoded ");
            crate::sys::serial::print_dec(data.width as u64);
            crate::sys::serial::print(b"x");
            crate::sys::serial::print_dec(data.height as u64);
            crate::sys::serial::println(b"");
            patch_render_output(&data);
            IMG_FAIL_COUNT.store(0, Ordering::Relaxed);
        }
        None => {
            crate::sys::serial::println(b"[IMG-FETCH] decode failed");
            IMG_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
    IMG_RESPONSE.lock().clear();
    IMG_TARGETS.lock().clear();
    set_img_state(ImgFetchState::Idle);
}

fn patch_render_output(data: &engine::ImageData) {
    let targets = IMG_TARGETS.lock().clone();
    let mut page = window_state::PAGE_RENDER.lock();
    if let Some(ref mut ro) = *page {
        for &(line_idx, elem_idx) in &targets {
            if let Some(line) = ro.lines.get_mut(line_idx) {
                if let Some(elem) = line.elements.get_mut(elem_idx) {
                    elem.content = engine::RenderContent::DecodedImage { data: data.clone() };
                }
            }
        }
    }
    drop(page);
    window_state::mark_content_changed();
}
