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
use crate::graphics::window::ecosystem::state as window_state;
use crate::network::stack::async_ops::{dns_start_query, dns_poll, dns_cancel, AsyncResult};
use super::state::*;
use super::url::parse_url;
use super::http::{start_http_connection, poll_http_connection};
use super::https::{start_https_connection, poll_tcp_connect, poll_tls_handshake, poll_send_request, poll_receive_response};
use super::response::process_response;

pub fn start() {
    RUNNING.store(true, Ordering::SeqCst);
}

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn is_navigating() -> bool {
    let state = get_state();
    state != NavState::Idle && state != NavState::Done && state != NavState::Error
}

pub fn navigate(url: &str) {
    if is_navigating() {
        return;
    }

    cancel_navigation();
    REDIRECT_COUNT.store(0, Ordering::Relaxed);

    // Clear any previous POST state
    *PENDING_METHOD.lock() = None;
    *PENDING_BODY.lock() = None;
    *PENDING_CONTENT_TYPE.lock() = None;

    window_state::LOADING.store(true, Ordering::Relaxed);
    window_state::clear_error();
    window_state::IS_HTTPS.store(false, Ordering::Relaxed);
    window_state::CERT_VERIFIED.store(false, Ordering::Relaxed);

    navigate_core(url);
}

/// Navigate to a URL with a POST body and content type.
pub fn navigate_with_post(url: &str, body: &[u8], content_type: &str) {
    if is_navigating() {
        return;
    }

    cancel_navigation();
    REDIRECT_COUNT.store(0, Ordering::Relaxed);

    *PENDING_METHOD.lock() = Some(String::from("POST"));
    *PENDING_BODY.lock() = Some(body.to_vec());
    *PENDING_CONTENT_TYPE.lock() = Some(String::from(content_type));

    window_state::LOADING.store(true, Ordering::Relaxed);
    window_state::clear_error();
    window_state::IS_HTTPS.store(false, Ordering::Relaxed);
    window_state::CERT_VERIFIED.store(false, Ordering::Relaxed);

    navigate_core(url);
}

/// Called by redirect logic — skips the is_navigating guard and preserves
/// the redirect counter so the chain can continue.
pub(super) fn navigate_internal(url: &str) {
    window_state::set_url(url);
    navigate_core(url);
}

fn navigate_core(url: &str) {
    let parts = match parse_url(url) {
        Some(p) => p,
        None => {
            window_state::set_error("Invalid URL");
            window_state::LOADING.store(false, Ordering::Relaxed);
            window_state::mark_content_changed();
            return;
        }
    };

    window_state::IS_HTTPS.store(parts.is_https, Ordering::Relaxed);

    *PENDING_URL.lock() = Some(String::from(url));
    *PENDING_HOST.lock() = Some(parts.host.clone());
    *PENDING_PORT.lock() = parts.port;
    *PENDING_PATH.lock() = Some(parts.path);
    PENDING_HTTPS.store(parts.is_https, Ordering::Relaxed);
    *RESOLVED_IP.lock() = None;
    *NAV_ERROR.lock() = None;
    RESPONSE_DATA.lock().clear();
    *HTTPS_TLS.lock() = None;
    HTTPS_CONN_ID.store(0, Ordering::Relaxed);

    let net_ready = crate::network::stack::is_network_available()
        && crate::network::stack::get_current_ipv4()
            .map(|(ip, _)| ip != [0, 0, 0, 0] && ip[0] != 127)
            .unwrap_or(false);
    if !net_ready {
        *NAV_ERROR.lock() = Some("network not ready");
        set_state(NavState::Error);
        return;
    }

    crate::sys::serial::println(b"[NAV] navigate_core: dns_start_query");
    if let Err(e) = dns_start_query(&parts.host) {
        *NAV_ERROR.lock() = Some(e);
        set_state(NavState::Error);
        return;
    }

    set_state(NavState::ResolvingDns);
}

static POLL_DBG_CTR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn poll_navigation() {
    let state = get_state();

    let ctr = POLL_DBG_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if ctr % 5000 == 0 && state != NavState::Idle && state != NavState::Done {
        crate::sys::serial::print(b"[NAV] state=");
        crate::sys::serial::print_dec(state as u8 as u64);
        crate::sys::serial::print(b" t=");
        crate::sys::serial::print_dec(crate::time::timestamp_millis());
        crate::sys::serial::println(b"");
    }

    let poll_start = crate::time::timestamp_millis();

    match state {
        NavState::Idle | NavState::Done => {}

        NavState::LoadingImages => {
            super::image_fetch::poll_image_fetch();
        }

        NavState::ResolvingDns => {
            match dns_poll() {
                AsyncResult::Ready(ip) => {
                    *RESOLVED_IP.lock() = Some(ip);
                    start_connection(ip);
                }
                AsyncResult::Pending => {}
                AsyncResult::Error(e) => {
                    finish_with_error(e);
                }
            }
        }

        NavState::Connecting => {
            if PENDING_HTTPS.load(Ordering::Relaxed) {
                poll_tcp_connect();
            } else {
                poll_http_connection();
            }
        }

        NavState::TlsHandshake => {
            poll_tls_handshake();
        }

        NavState::SendingRequest => {
            poll_send_request();
        }

        NavState::ReceivingResponse => {
            poll_receive_response();
        }

        NavState::ProcessingResponse => {
            process_response();
        }

        NavState::Error => {
            if let Some(e) = *NAV_ERROR.lock() {
                crate::sys::serial::print(b"[NAV] ERROR: ");
                crate::sys::serial::println(e.as_bytes());
                let error_msg = match e {
                    "dns timeout" => "DNS resolution timed out",
                    "no dns records" => "Domain not found",
                    "http timeout" => "Request timed out",
                    "no network" => "No network connection",
                    "network not ready" => "Network not ready (waiting for DHCP)",
                    "no network stack" => "Network not ready (waiting for DHCP)",
                    "no ipv4 address" => "Network not ready (waiting for DHCP)",
                    "no routable ip" => "Network not ready (waiting for DHCP)",
                    "dns query already in progress" => "DNS busy, retry",
                    "dns bind failed" => "DNS socket error",
                    "dns send failed" => "DNS send failed (network down)",
                    "TLS handshake failed" => "TLS/SSL error",
                    "TCP connect failed" => "Connection refused",
                    _ => e,
                };
                window_state::set_error(error_msg);
            }
            window_state::LOADING.store(false, Ordering::Relaxed);
            window_state::mark_content_changed();
            set_state(NavState::Idle);
        }
    }

    let poll_elapsed = crate::time::timestamp_millis().saturating_sub(poll_start);
    if poll_elapsed > 250 {
        crate::sys::serial::print(b"[NAV] WARN slow poll ms=");
        crate::sys::serial::print_dec(poll_elapsed);
        crate::sys::serial::print(b" state=");
        crate::sys::serial::print_dec(state as u8 as u64);
        crate::sys::serial::println(b"");
    }
}

pub fn cancel_navigation() {
    let state = get_state();

    match state {
        NavState::ResolvingDns => {
            dns_cancel();
        }
        NavState::Connecting => {
            if PENDING_HTTPS.load(Ordering::Relaxed) {
                cleanup_https();
            } else {
                crate::network::stack::async_ops::http_cancel();
            }
        }
        NavState::TlsHandshake | NavState::SendingRequest | NavState::ReceivingResponse => {
            cleanup_https();
        }
        NavState::LoadingImages => {
            super::image_fetch::abort();
            PENDING_IMAGES.lock().clear();
        }
        _ => {}
    }

    cleanup_navigation();
    RESPONSE_DATA.lock().clear();
    set_state(NavState::Idle);
    window_state::LOADING.store(false, Ordering::Relaxed);
}

fn start_connection(ip: [u8; 4]) {
    let port = *PENDING_PORT.lock();
    let is_https = PENDING_HTTPS.load(Ordering::Relaxed);

    crate::sys::serial::print(b"[NAV] start_connection ip=");
    crate::sys::serial::print_dec(ip[0] as u64);
    crate::sys::serial::print(b".");
    crate::sys::serial::print_dec(ip[1] as u64);
    crate::sys::serial::print(b".");
    crate::sys::serial::print_dec(ip[2] as u64);
    crate::sys::serial::print(b".");
    crate::sys::serial::print_dec(ip[3] as u64);
    crate::sys::serial::print(b" port=");
    crate::sys::serial::print_dec(port as u64);
    crate::sys::serial::print(b" https=");
    crate::sys::serial::println(if is_https { b"true" } else { b"false" });

    if is_https {
        start_https_connection(ip, port);
    } else {
        start_http_connection(ip, port);
    }
}

/// Fetch one pending image per poll tick, then replace its placeholder in
/// `PAGE_RENDER` with decoded pixel data. Transitions to `Done` when the
/// queue is empty or after too many failures.
///
/// DEPRECATED: replaced by `image_fetch::poll_image_fetch()` which uses
/// non-blocking TCP/TLS instead of the synchronous HTTP client.
#[allow(dead_code)]
fn poll_load_images() {
    use crate::apps::ecosystem::browser::engine;

    let entry = PENDING_IMAGES.lock().pop();
    let (line_idx, elem_idx, url) = match entry {
        Some(e) => e,
        None => {
            set_state(NavState::Done);
            return;
        }
    };

    crate::sys::serial::print(b"[NAV] async img fetch: ");
    crate::sys::serial::println(url.as_bytes());

    // Attempt to load and decode
    if let Some(data) = engine::image_loader::load_image(&url, "") {
        let mut page = window_state::PAGE_RENDER.lock();
        if let Some(ref mut ro) = *page {
            if let Some(line) = ro.lines.get_mut(line_idx) {
                if let Some(elem) = line.elements.get_mut(elem_idx) {
                    elem.content = engine::RenderContent::DecodedImage { data };
                }
            }
        }
        drop(page);
        window_state::mark_content_changed();
    }

    // Check if more images remain
    if PENDING_IMAGES.lock().is_empty() {
        crate::sys::serial::println(b"[NAV] async image loading done");
        set_state(NavState::Done);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphics::window::ecosystem::state as window_state;

    #[test]
    fn navigate_without_network_yields_friendly_error() {
        set_state(NavState::Idle);
        window_state::clear_error();

        navigate("http://example.com");
        poll_navigation();

        let err = window_state::get_error();
        assert_eq!(err.as_deref(), Some("Network not ready (waiting for DHCP)"));
        assert_eq!(get_state(), NavState::Idle);
    }
}
