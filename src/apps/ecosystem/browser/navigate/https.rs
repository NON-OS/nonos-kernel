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
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::Ordering;
use crate::network::stack::async_ops::{tcp_start_connect, tcp_poll_connect, tcp_send, tcp_poll_receive, tcp_close, AsyncResult};
use crate::network::onion::tls::TLSConnection;
use crate::network::tcp::TcpSocket as TcpSocketWrapper;
use super::state::*;
use super::response::{find_header_end, is_response_complete};

pub(super) fn start_https_connection(ip: [u8; 4], port: u16) {
    match tcp_start_connect(ip, port) {
        Ok(conn_id) => {
            HTTPS_CONN_ID.store(conn_id, Ordering::Relaxed);
            HTTPS_DEADLINE.store(crate::time::timestamp_millis() + 20000, Ordering::Relaxed);
            set_state(NavState::Connecting);
        }
        Err(e) => {
            finish_with_error(e);
        }
    }
}

pub(super) fn poll_tcp_connect() {
    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    if crate::time::timestamp_millis() > deadline {
        tcp_close();
        finish_with_error("TCP connect timeout");
        return;
    }

    match tcp_poll_connect() {
        AsyncResult::Ready(()) => {
            start_tls_handshake();
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            finish_with_error(e);
        }
    }
}

fn start_tls_handshake() {
    let conn_id = HTTPS_CONN_ID.load(Ordering::Relaxed);

    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            tcp_close();
            finish_with_error("no host");
            return;
        }
    };

    let socket = TcpSocketWrapper::from_connection(conn_id);
    let mut tls = TLSConnection::new();

    if let Err(_) = tls.start_handshake(&socket, Some(&host), Some(&["http/1.1"])) {
        tcp_close();
        finish_with_error("TLS start failed");
        return;
    }

    *HTTPS_TLS.lock() = Some(tls);
    set_state(NavState::TlsHandshake);
}

pub(super) fn poll_tls_handshake() {
    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    if crate::time::timestamp_millis() > deadline {
        cleanup_https();
        finish_with_error("TLS handshake timeout");
        return;
    }

    crate::network::poll_network();

    let conn_id = HTTPS_CONN_ID.load(Ordering::Relaxed);
    let socket = TcpSocketWrapper::from_connection(conn_id);

    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            cleanup_https();
            finish_with_error("no host");
            return;
        }
    };

    let verifier = crate::network::onion::tls::get_cert_verifier()
        .unwrap_or(&crate::network::onion::tls::HTTPS_CERT_VERIFIER);

    let mut tls_guard = HTTPS_TLS.lock();
    let tls = match tls_guard.as_mut() {
        Some(t) => t,
        None => {
            drop(tls_guard);
            cleanup_https();
            finish_with_error("no TLS context");
            return;
        }
    };

    match tls.poll_handshake(&socket, Some(&host), verifier) {
        Ok(Some(_)) => {
            drop(tls_guard);
            set_state(NavState::SendingRequest);
        }
        Ok(None) => {}
        Err(_) => {
            drop(tls_guard);
            cleanup_https();
            finish_with_error("TLS handshake failed");
        }
    }
}

pub(super) fn poll_send_request() {
    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            cleanup_https();
            finish_with_error("no host");
            return;
        }
    };

    let path = PENDING_PATH.lock().clone().unwrap_or_else(|| String::from("/"));

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NONOS/1.0\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n",
        path, host
    );

    let mut tls_guard = HTTPS_TLS.lock();
    let tls = match tls_guard.as_mut() {
        Some(t) => t,
        None => {
            drop(tls_guard);
            cleanup_https();
            finish_with_error("no TLS session");
            return;
        }
    };

    let encrypted = match tls.encrypt_app(request.as_bytes()) {
        Ok(data) => data,
        Err(_) => {
            drop(tls_guard);
            cleanup_https();
            finish_with_error("TLS encrypt failed");
            return;
        }
    };
    drop(tls_guard);

    let wrapped = wrap_tls_record(0x17, &encrypted);
    if tcp_send(&wrapped).is_err() {
        cleanup_https();
        finish_with_error("TCP send failed");
        return;
    }

    HTTPS_DEADLINE.store(crate::time::timestamp_millis() + 15000, Ordering::Relaxed);
    set_state(NavState::ReceivingResponse);
}

pub(super) fn poll_receive_response() {
    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    if crate::time::timestamp_millis() > deadline {
        let response_data = RESPONSE_DATA.lock().clone();
        if !response_data.is_empty() {
            cleanup_https();
            set_state(NavState::ProcessingResponse);
            return;
        }
        cleanup_https();
        finish_with_error("http timeout");
        return;
    }

    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            if received.is_empty() {
                let response_data = RESPONSE_DATA.lock();
                if !response_data.is_empty() {
                    drop(response_data);
                    cleanup_https();
                    set_state(NavState::ProcessingResponse);
                }
                return;
            }

            let mut collected_plaintext: Vec<u8> = Vec::new();
            let mut got_alert = false;

            {
                let mut tls_guard = HTTPS_TLS.lock();
                let tls = match tls_guard.as_mut() {
                    Some(t) => t,
                    None => {
                        drop(tls_guard);
                        cleanup_https();
                        finish_with_error("no TLS session");
                        return;
                    }
                };

                let mut offset = 0;
                while offset + 5 <= received.len() {
                    let content_type = received[offset];
                    let record_len = u16::from_be_bytes([received[offset + 3], received[offset + 4]]) as usize;

                    if offset + 5 + record_len > received.len() {
                        break;
                    }

                    let record_data = &received[offset + 5..offset + 5 + record_len];

                    if content_type == 0x17 {
                        if let Ok(plaintext) = tls.decrypt_app(record_data) {
                            if !plaintext.is_empty() {
                                collected_plaintext.extend_from_slice(&plaintext[..plaintext.len().saturating_sub(1)]);
                            }
                        }
                    } else if content_type == 0x15 {
                        got_alert = true;
                        break;
                    }

                    offset += 5 + record_len;
                }
            }

            if !collected_plaintext.is_empty() {
                let mut response = RESPONSE_DATA.lock();
                response.extend_from_slice(&collected_plaintext);
            }

            if got_alert {
                cleanup_https();
                set_state(NavState::ProcessingResponse);
                return;
            }

            let response_data = RESPONSE_DATA.lock();
            if response_data.len() > 4 {
                if let Some(_) = find_header_end(&response_data) {
                    if response_data.len() > 65536 || is_response_complete(&response_data) {
                        drop(response_data);
                        cleanup_https();
                        set_state(NavState::ProcessingResponse);
                        return;
                    }
                }
            }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(_) => {
            let response_data = RESPONSE_DATA.lock();
            if !response_data.is_empty() {
                drop(response_data);
                cleanup_https();
                set_state(NavState::ProcessingResponse);
            }
        }
    }
}

fn wrap_tls_record(content_type: u8, data: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(content_type);
    record.push(0x03);
    record.push(0x03);
    record.push((data.len() >> 8) as u8);
    record.push((data.len() & 0xff) as u8);
    record.extend_from_slice(data);
    record
}
