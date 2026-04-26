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
use core::sync::atomic::{AtomicU64, Ordering};
use crate::graphics::window::ecosystem::state as window_state;
use crate::network::stack::async_ops::{tcp_poll_receive, AsyncResult};
use super::super::state::*;
use super::super::response::{find_header_end, is_response_complete};

const PARTIAL_RESPONSE_IDLE_MS: u64 = 1200;
static RX_LAST_PROGRESS_MS: AtomicU64 = AtomicU64::new(0);

pub(in crate::apps::ecosystem::browser::navigate) fn poll_receive_response() {
    crate::network::poll_network();
    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    if crate::time::timestamp_millis() > deadline {
        let response_data = RESPONSE_DATA.lock().clone();
        if !response_data.is_empty() { window_state::set_error("Partial response loaded"); cleanup_https(); set_state(NavState::ProcessingResponse); return; }
        cleanup_https(); finish_with_error("http timeout"); return;
    }
    static RX_DBG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let rx_ctr = RX_DBG.fetch_add(1, Ordering::Relaxed);
    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            crate::sys::serial::print(b"[HTTPS-RX] Ready len=");
            crate::sys::serial::print_dec(received.len() as u64);
            crate::sys::serial::println(b"");
            if received.is_empty() {
                let response_data = RESPONSE_DATA.lock();
                if !response_data.is_empty() { drop(response_data); cleanup_https(); set_state(NavState::ProcessingResponse); }
                return;
            }
            let (collected_plaintext, got_alert) = process_tls_records(&received);
            if !collected_plaintext.is_empty() {
                RESPONSE_DATA.lock().extend_from_slice(&collected_plaintext);
                RX_LAST_PROGRESS_MS.store(crate::time::timestamp_millis(), Ordering::Relaxed);
            }
            if got_alert { cleanup_https(); set_state(NavState::ProcessingResponse); return; }
            let response_data = RESPONSE_DATA.lock();
            if response_data.len() > 4 {
                if let Some(_) = find_header_end(&response_data) {
                    if response_data.len() > 65536 || is_response_complete(&response_data) {
                        drop(response_data); cleanup_https(); set_state(NavState::ProcessingResponse); return;
                    }
                }
            }
            drop(response_data);
            if maybe_finish_idle_partial() { return; }
        }
        AsyncResult::Pending => {
            if maybe_finish_idle_partial() { return; }
            if rx_ctr % 2000 == 0 { crate::sys::serial::print(b"[HTTPS-RX] Pending #"); crate::sys::serial::print_dec(rx_ctr as u64); crate::sys::serial::println(b""); }
        }
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[HTTPS-RX] Error: "); crate::sys::serial::println(e.as_bytes());
            let response_data = RESPONSE_DATA.lock();
            if !response_data.is_empty() { window_state::set_error("Partial response loaded"); drop(response_data); cleanup_https(); set_state(NavState::ProcessingResponse); }
        }
    }
}

fn maybe_finish_idle_partial() -> bool {
    let response_data = RESPONSE_DATA.lock();
    if response_data.is_empty() || find_header_end(&response_data).is_none() { return false; }
    let last_progress = RX_LAST_PROGRESS_MS.load(Ordering::Relaxed);
    if last_progress == 0 || crate::time::timestamp_millis().saturating_sub(last_progress) <= PARTIAL_RESPONSE_IDLE_MS { return false; }
    crate::sys::serial::println(b"[HTTPS-RX] partial response idle");
    window_state::set_error("Partial response loaded");
    drop(response_data);
    cleanup_https();
    set_state(NavState::ProcessingResponse);
    true
}

fn process_tls_records(received: &[u8]) -> (Vec<u8>, bool) {
    let mut collected_plaintext: Vec<u8> = Vec::new();
    let mut got_alert = false;
    let mut reasm = HTTPS_REASSEMBLY_BUF.lock();
    if reasm.len() + received.len() > MAX_HTTPS_REASSEMBLY {
        crate::sys::serial::println(b"[HTTPS-RX] reassembly cap exceeded");
        reasm.clear();
        return (collected_plaintext, true);
    }
    reasm.extend_from_slice(received);
    let mut tls_guard = HTTPS_TLS.lock();
    let tls = match tls_guard.as_mut() { Some(t) => t, None => { return (collected_plaintext, got_alert); } };
    let mut offset = 0;
    while offset + 5 <= reasm.len() {
        let content_type = reasm[offset];
        let record_len = u16::from_be_bytes([reasm[offset + 3], reasm[offset + 4]]) as usize;
        if record_len > MAX_HTTPS_RECORD {
            crate::sys::serial::println(b"[HTTPS-RX] malformed TLS record length");
            reasm.clear();
            return (collected_plaintext, true);
        }
        if offset + 5 + record_len > reasm.len() { break; }
        let record_data = &reasm[offset + 5..offset + 5 + record_len];
        if content_type == 0x17 {
            if let Ok(plaintext) = tls.decrypt_app(record_data) {
                if !plaintext.is_empty() {
                    let mut end = plaintext.len();
                    while end > 0 && plaintext[end - 1] == 0 { end -= 1; }
                    if end > 0 { end -= 1; }
                    collected_plaintext.extend_from_slice(&plaintext[..end]);
                }
            }
        } else if content_type == 0x15 { got_alert = true; break; }
        offset += 5 + record_len;
    }
    if offset > 0 { reasm.drain(..offset); }
    (collected_plaintext, got_alert)
}
