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

    window_state::LOADING.store(true, Ordering::Relaxed);
    window_state::clear_error();

    let parts = match parse_url(url) {
        Some(p) => p,
        None => {
            window_state::set_error("Invalid URL");
            window_state::LOADING.store(false, Ordering::Relaxed);
            window_state::mark_content_changed();
            return;
        }
    };

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

    if let Err(e) = dns_start_query(&parts.host) {
        *NAV_ERROR.lock() = Some(e);
        set_state(NavState::Error);
        window_state::set_error("DNS lookup failed");
        window_state::LOADING.store(false, Ordering::Relaxed);
        window_state::mark_content_changed();
        return;
    }

    set_state(NavState::ResolvingDns);
}

pub fn poll_navigation() {
    let state = get_state();

    match state {
        NavState::Idle | NavState::Done => {}

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
                let error_msg = match e {
                    "dns timeout" => "DNS resolution timed out",
                    "no dns records" => "Domain not found",
                    "http timeout" => "Request timed out",
                    "no network" => "No network connection",
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

    if is_https {
        start_https_connection(ip, port);
    } else {
        start_http_connection(ip, port);
    }
}
