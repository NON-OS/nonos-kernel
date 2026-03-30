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

use alloc::string::String;
use core::sync::atomic::Ordering;
use crate::network::stack::async_ops::dns_cancel;
use super::types::*;
use super::queue::start_next_image;
use super::dns::poll_img_dns;
use super::connect::{poll_img_connect, img_cleanup};
use super::tls::poll_img_tls;
use super::send::poll_img_send;
use super::receive::poll_img_receive;
use super::decode::poll_img_decode;

pub fn set_nav_context(host: &str, ip: Option<[u8; 4]>) {
    *IMG_NAV_HOST.lock() = if host.is_empty() { None } else { Some(String::from(host)) };
    *IMG_NAV_IP.lock() = ip;
}

pub fn reset() {
    set_img_state(ImgFetchState::Idle);
    IMG_DEADLINE.store(0, Ordering::Relaxed);
    IMG_CONN_ID.store(0, Ordering::Relaxed);
    *IMG_TLS.lock() = None;
    IMG_REASSEMBLY.lock().clear();
    IMG_RESPONSE.lock().clear();
    *IMG_HOST.lock() = None;
    *IMG_PATH.lock() = None;
    *IMG_PORT.lock() = 443;
    *IMG_IP.lock() = None;
    IMG_IS_HTTPS.store(true, Ordering::Relaxed);
    IMG_TARGETS.lock().clear();
    IMG_FAIL_COUNT.store(0, Ordering::Relaxed);
}

pub fn abort() {
    let state = get_img_state();
    match state {
        ImgFetchState::DnsResolve => { dns_cancel(); }
        ImgFetchState::Connecting | ImgFetchState::TlsHandshake
        | ImgFetchState::Sending | ImgFetchState::Receiving => { img_cleanup(); }
        _ => {}
    }
    reset();
}

pub fn poll_image_fetch() {
    crate::network::poll_network();
    match get_img_state() {
        ImgFetchState::Idle => start_next_image(),
        ImgFetchState::DnsResolve => poll_img_dns(),
        ImgFetchState::Connecting => poll_img_connect(),
        ImgFetchState::TlsHandshake => poll_img_tls(),
        ImgFetchState::Sending => poll_img_send(),
        ImgFetchState::Receiving => poll_img_receive(),
        ImgFetchState::Decoding => poll_img_decode(),
    }
}
