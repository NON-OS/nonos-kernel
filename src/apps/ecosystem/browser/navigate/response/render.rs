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

use super::body::extract_title;
use super::redirect::resolve_noscript_redirect;
use crate::apps::ecosystem::browser::engine;
use crate::apps::ecosystem::browser::navigate::state::*;
use crate::graphics::window::ecosystem::state as window_state;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub(super) fn render_page(content_str: &str, url: &str, body: &[u8]) {
    let render_output = engine::render_page_with_url(content_str, 800, url);
    engine::image_loader::enable_fetch();
    if let Some(ref redirect) = render_output.noscript_redirect {
        let target = resolve_noscript_redirect(url, redirect);
        let count = REDIRECT_COUNT.load(Ordering::Relaxed);
        if count < MAX_REDIRECTS {
            crate::sys::serial::print(b"[NAV] noscript redirect -> ");
            crate::sys::serial::println(target.as_bytes());
            REDIRECT_COUNT.fetch_add(1, Ordering::Relaxed);
            cleanup_navigation();
            set_state(NavState::Done);
            crate::apps::ecosystem::browser::navigate::api::navigate_internal(&target);
            return;
        }
    }
    let mut link_count: u64 = 0;
    for (line_idx, render_line) in render_output.lines.iter().enumerate() {
        for elem in &render_line.elements {
            if let engine::RenderContent::Link { href, .. } = &elem.content {
                if !href.is_empty() {
                    window_state::add_page_link(
                        line_idx,
                        8 + elem.x,
                        8 + elem.x + elem.width,
                        href,
                    );
                    link_count += 1;
                }
            }
        }
    }
    let (lines, _flat_links) = engine::render_to_lines_with_links(content_str);
    crate::sys::serial::print(b"[NAV] rendered lines=");
    crate::sys::serial::print_dec(render_output.lines.len() as u64);
    crate::sys::serial::print(b", links=");
    crate::sys::serial::print_dec(link_count);
    crate::sys::serial::println(b"");
    let title = extract_title(body).unwrap_or_else(|| String::from("Untitled"));
    window_state::set_page_title(&title);
    finalize_render(render_output, lines);
}

fn finalize_render(render_output: engine::RenderOutput, lines: alloc::vec::Vec<String>) {
    crate::sys::serial::println(b"[NAV] finalize: enter");
    {
        let mut page_content = window_state::PAGE_CONTENT.lock();
        page_content.clear();
        window_state::PAGE_TOTAL_LINES.store(render_output.lines.len(), Ordering::Relaxed);
        page_content.extend(lines);
    }
    crate::sys::serial::println(b"[NAV] finalize: scan images");
    let mut pending = PENDING_IMAGES.lock();
    pending.clear();
    for (line_idx, render_line) in render_output.lines.iter().enumerate() {
        for (elem_idx, elem) in render_line.elements.iter().enumerate() {
            if let engine::RenderContent::Image { ref src, .. } = elem.content {
                if !src.is_empty() && (src.starts_with("https://") || src.starts_with("http://")) {
                    pending.push((line_idx, elem_idx, src.clone()));
                }
            }
        }
    }
    let img_count = pending.len();
    drop(pending);
    if img_count > 0 {
        crate::sys::serial::print(b"[NAV] queued async images: ");
        crate::sys::serial::print_dec(img_count as u64);
        crate::sys::serial::println(b"");
    }
    crate::sys::serial::println(b"[NAV] finalize: store PAGE_RENDER");
    {
        *window_state::PAGE_RENDER.lock() = Some(render_output);
    }
    window_state::PAGE_SCROLL.store(0, Ordering::Relaxed);
    window_state::LOADING.store(false, Ordering::Relaxed);
    window_state::mark_content_changed();
    let nav_host = PENDING_HOST.lock().clone().unwrap_or_default();
    let nav_ip = *RESOLVED_IP.lock();
    crate::apps::ecosystem::browser::navigate::image_fetch::set_nav_context(&nav_host, nav_ip);
    cleanup_navigation();
    if img_count > 0 {
        crate::apps::ecosystem::browser::navigate::image_fetch::reset();
        set_state(NavState::LoadingImages);
    } else {
        set_state(NavState::Done);
    }
    crate::sys::serial::println(b"[NAV] finalize: done");
}
