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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use crate::network::stack::async_ops::{tcp_poll_receive, AsyncResult};
use crate::apps::ecosystem::browser::navigate::response::{find_header_end, is_response_complete};
use super::types::*;
use super::queue::skip_current_image;
use super::connect::img_cleanup;

pub(super) fn poll_img_receive() {
    crate::network::poll_network();
    if is_timed_out() {
        let has_data = !IMG_RESPONSE.lock().is_empty();
        if has_data { crate::sys::serial::println(b"[IMG-FETCH] timeout with partial data"); img_cleanup(); set_img_state(ImgFetchState::Decoding); }
        else { crate::sys::serial::println(b"[IMG-FETCH] receive timeout"); img_cleanup(); skip_current_image(); }
        return;
    }
    if IMG_IS_HTTPS.load(Ordering::Relaxed) { poll_img_receive_https(); }
    else { poll_img_receive_http(); }
}

fn poll_img_receive_https() {
    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            if received.is_empty() { if !IMG_RESPONSE.lock().is_empty() { img_cleanup(); set_img_state(ImgFetchState::Decoding); } return; }
            let (collected, got_alert) = process_tls_records(&received);
            if !collected.is_empty() {
                let mut response = IMG_RESPONSE.lock();
                response.extend_from_slice(&collected);
                if response.len() > MAX_IMG_RESPONSE { crate::sys::serial::println(b"[IMG-FETCH] too large"); drop(response); img_cleanup(); skip_current_image(); return; }
            }
            if got_alert { img_cleanup(); set_img_state(ImgFetchState::Decoding); return; }
            let response = IMG_RESPONSE.lock();
            if response.len() > 4 && find_header_end(&response).is_some() {
                if is_response_complete(&response) || response.len() > MAX_IMG_RESPONSE { drop(response); img_cleanup(); set_img_state(ImgFetchState::Decoding); return; }
            }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(_) => { if !IMG_RESPONSE.lock().is_empty() { img_cleanup(); set_img_state(ImgFetchState::Decoding); } else { img_cleanup(); skip_current_image(); } }
    }
}

fn poll_img_receive_http() {
    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            if received.is_empty() { if !IMG_RESPONSE.lock().is_empty() { img_cleanup(); set_img_state(ImgFetchState::Decoding); } return; }
            let mut response = IMG_RESPONSE.lock();
            response.extend_from_slice(&received);
            if response.len() > MAX_IMG_RESPONSE { drop(response); img_cleanup(); skip_current_image(); return; }
            if response.len() > 4 && find_header_end(&response).is_some() && is_response_complete(&response) { drop(response); img_cleanup(); set_img_state(ImgFetchState::Decoding); }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(_) => { if !IMG_RESPONSE.lock().is_empty() { img_cleanup(); set_img_state(ImgFetchState::Decoding); } else { img_cleanup(); skip_current_image(); } }
    }
}

fn process_tls_records(received: &[u8]) -> (Vec<u8>, bool) {
    let mut collected: Vec<u8> = Vec::new();
    let mut got_alert = false;
    let mut reasm = IMG_REASSEMBLY.lock();
    if reasm.len() + received.len() > MAX_IMG_REASSEMBLY {
        crate::sys::serial::println(b"[IMG-FETCH] reassembly cap exceeded");
        reasm.clear();
        return (collected, true);
    }
    reasm.extend_from_slice(received);
    let mut tls_guard = IMG_TLS.lock();
    let tls = match tls_guard.as_mut() { Some(t) => t, None => { return (collected, true); } };
    let mut offset = 0;
    while offset + 5 <= reasm.len() {
        let content_type = reasm[offset];
        let record_len = u16::from_be_bytes([reasm[offset + 3], reasm[offset + 4]]) as usize;
        if record_len > MAX_IMG_TLS_RECORD {
            crate::sys::serial::println(b"[IMG-FETCH] malformed TLS record length");
            reasm.clear();
            return (collected, true);
        }
        if offset + 5 + record_len > reasm.len() { break; }
        let record_data = &reasm[offset + 5..offset + 5 + record_len];
        if content_type == 0x17 {
            if let Ok(plaintext) = tls.decrypt_app(record_data) {
                if !plaintext.is_empty() {
                    let mut end = plaintext.len();
                    while end > 0 && plaintext[end - 1] == 0 { end -= 1; }
                    if end > 0 { end -= 1; }
                    collected.extend_from_slice(&plaintext[..end]);
                }
            } else { crate::sys::serial::println(b"[IMG-FETCH] decrypt failed"); }
        } else if content_type == 0x15 { got_alert = true; break; }
        offset += 5 + record_len;
    }
    if offset > 0 { reasm.drain(..offset); }
    (collected, got_alert)
}
