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

use super::types::*;
use super::url::parse_image_url;
use crate::network::stack::async_ops::{dns_start_query, tcp_start_connect};
use alloc::vec;
use core::sync::atomic::Ordering;

pub(super) fn skip_current_image() {
    IMG_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
    IMG_RESPONSE.lock().clear();
    IMG_TARGETS.lock().clear();
    set_img_state(ImgFetchState::Idle);
}

pub(super) fn finish_all_images() {
    crate::sys::serial::println(b"[IMG-FETCH] all done");
    crate::apps::ecosystem::browser::navigate::state::set_state(
        crate::apps::ecosystem::browser::navigate::state::NavState::Done,
    );
}

pub(super) fn start_next_image() {
    if IMG_FAIL_COUNT.load(Ordering::Relaxed) >= MAX_IMG_FAILURES {
        crate::sys::serial::println(b"[IMG-FETCH] too many failures, bailing");
        finish_all_images();
        return;
    }
    let entry = crate::apps::ecosystem::browser::navigate::state::PENDING_IMAGES.lock().pop();
    let (line_idx, elem_idx, url) = match entry {
        Some(e) => e,
        None => {
            finish_all_images();
            return;
        }
    };
    crate::sys::serial::print(b"[IMG-FETCH] start: ");
    crate::sys::serial::println(url.as_bytes());
    let mut targets = vec![(line_idx, elem_idx)];
    {
        let mut queue = crate::apps::ecosystem::browser::navigate::state::PENDING_IMAGES.lock();
        let mut i = 0;
        while i < queue.len() {
            if queue[i].2 == url {
                targets.push((queue[i].0, queue[i].1));
                queue.remove(i);
            } else {
                i += 1;
            }
        }
    }
    *IMG_TARGETS.lock() = targets;
    let (host, port, path, is_https) = match parse_image_url(&url) {
        Some(parts) => parts,
        None => {
            crate::sys::serial::println(b"[IMG-FETCH] bad url, skip");
            skip_current_image();
            return;
        }
    };
    *IMG_HOST.lock() = Some(host.clone());
    *IMG_PATH.lock() = Some(path);
    *IMG_PORT.lock() = port;
    IMG_IS_HTTPS.store(is_https, Ordering::Relaxed);
    IMG_DEADLINE.store(crate::time::timestamp_millis() + IMG_TIMEOUT_MS, Ordering::Relaxed);
    IMG_RESPONSE.lock().clear();
    IMG_REASSEMBLY.lock().clear();
    try_same_host_connect(&host, port);
}

fn try_same_host_connect(host: &str, port: u16) {
    let nav_host = IMG_NAV_HOST.lock().clone();
    let nav_ip = *IMG_NAV_IP.lock();
    if Some(host) == nav_host.as_deref() {
        if let Some(ip) = nav_ip {
            crate::sys::serial::println(b"[IMG-FETCH] same host, reusing IP");
            *IMG_IP.lock() = Some(ip);
            match tcp_start_connect(ip, port) {
                Ok(conn_id) => {
                    IMG_CONN_ID.store(conn_id, Ordering::Relaxed);
                    set_img_state(ImgFetchState::Connecting);
                }
                Err(e) => {
                    crate::sys::serial::print(b"[IMG-FETCH] tcp start failed: ");
                    crate::sys::serial::println(e.as_bytes());
                    skip_current_image();
                }
            }
            return;
        }
    }
    *IMG_IP.lock() = None;
    match dns_start_query(host) {
        Ok(_) => set_img_state(ImgFetchState::DnsResolve),
        Err(e) => {
            crate::sys::serial::print(b"[IMG-FETCH] dns start failed: ");
            crate::sys::serial::println(e.as_bytes());
            skip_current_image();
        }
    }
}
