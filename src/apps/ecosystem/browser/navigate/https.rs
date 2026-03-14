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
    use crate::sys::serial;

    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    if crate::time::timestamp_millis() > deadline {
        serial::println(b"[BROWSER] TLS handshake timeout");
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
            serial::println(b"[BROWSER] no host in TLS handshake");
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
            serial::println(b"[BROWSER] no TLS context");
            drop(tls_guard);
            cleanup_https();
            finish_with_error("no TLS context");
            return;
        }
    };

    match tls.poll_handshake(&socket, Some(&host), verifier) {
        Ok(Some(_info)) => {
            serial::println(b"[BROWSER] TLS handshake complete!");
            drop(tls_guard);
            set_state(NavState::SendingRequest);
        }
        Ok(None) => {}
        Err(e) => {
            serial::print(b"[BROWSER] TLS handshake failed: ");
            match e {
                crate::network::onion::OnionError::CryptoError => serial::println(b"CryptoError"),
                crate::network::onion::OnionError::NetworkError => serial::println(b"NetworkError"),
                crate::network::onion::OnionError::InvalidState => serial::println(b"InvalidState"),
                crate::network::onion::OnionError::AuthenticationFailed => serial::println(b"AuthenticationFailed"),
                crate::network::onion::OnionError::CertificateError => serial::println(b"CertificateError"),
                crate::network::onion::OnionError::Timeout => serial::println(b"Timeout"),
                _ => serial::println(b"other"),
            }
            drop(tls_guard);
            cleanup_https();
            finish_with_error("TLS handshake failed");
        }
    }
}

pub(super) fn poll_send_request() {
    use crate::sys::serial;
    serial::println(b"[HTTPS] poll_send_request called");

    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            serial::println(b"[HTTPS] no host!");
            cleanup_https();
            finish_with_error("no host");
            return;
        }
    };

    serial::print(b"[HTTPS] host=");
    serial::print(host.as_bytes());
    serial::println(b"");

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
    serial::print(b"[HTTPS] sending ");
    serial::print_dec(wrapped.len() as u64);
    serial::println(b" bytes");

    if tcp_send(&wrapped).is_err() {
        serial::println(b"[HTTPS] TCP send failed!");
        cleanup_https();
        finish_with_error("TCP send failed");
        return;
    }

    serial::println(b"[HTTPS] request sent, waiting for response");

    // Poll network multiple times to flush and receive initial response
    for _ in 0..100 {
        crate::network::poll_network();
        if let Some(ns) = crate::network::get_network_stack() {
            ns.poll();
        }
        for _ in 0..1000 { core::hint::spin_loop(); }
    }

    HTTPS_DEADLINE.store(crate::time::timestamp_millis() + 15000, Ordering::Relaxed);
    set_state(NavState::ReceivingResponse);
}

pub(super) fn poll_receive_response() {
    use crate::sys::serial;

    // Poll the network drivers to receive packets from hardware
    crate::network::poll_network();

    // Check socket state
    static POLL_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let count = POLL_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if count < 20 || count % 100 == 0 {
        if let Some(ns) = crate::network::get_network_stack() {
            ns.poll();
        }
    }

    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    if crate::time::timestamp_millis() > deadline {
        let response_data = RESPONSE_DATA.lock().clone();
        if !response_data.is_empty() {
            serial::print(b"[HTTPS] timeout with ");
            serial::print_dec(response_data.len() as u64);
            serial::println(b" bytes");
            cleanup_https();
            set_state(NavState::ProcessingResponse);
            return;
        }
        serial::println(b"[HTTPS] timeout with no data!");
        cleanup_https();
        finish_with_error("http timeout");
        return;
    }

    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            serial::print(b"[HTTPS] received ");
            serial::print_dec(received.len() as u64);
            serial::print(b" bytes");
            if !received.is_empty() {
                serial::print(b" first=0x");
                serial::print_hex(received[0] as u64);
                if received.len() > 1 {
                    serial::print(b" 0x");
                    serial::print_hex(received[1] as u64);
                }
            }
            serial::println(b"");

            if received.is_empty() {
                let response_data = RESPONSE_DATA.lock();
                if !response_data.is_empty() {
                    serial::println(b"[HTTPS] empty recv, processing response");
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
                        serial::println(b"[HTTPS] no TLS session!");
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

                    serial::print(b"[HTTPS] record type=");
                    serial::print_hex(content_type as u64);
                    serial::print(b" len=");
                    serial::print_dec(record_len as u64);
                    serial::println(b"");

                    if offset + 5 + record_len > received.len() {
                        serial::println(b"[HTTPS] incomplete record");
                        break;
                    }

                    let record_data = &received[offset + 5..offset + 5 + record_len];

                    if content_type == 0x17 {
                        match tls.decrypt_app(record_data) {
                            Ok(plaintext) => {
                                serial::print(b"[HTTPS] decrypted ");
                                serial::print_dec(plaintext.len() as u64);
                                serial::println(b" bytes");
                                if !plaintext.is_empty() {
                                    collected_plaintext.extend_from_slice(&plaintext[..plaintext.len().saturating_sub(1)]);
                                }
                            }
                            Err(_) => {
                                serial::println(b"[HTTPS] decrypt failed!");
                            }
                        }
                    } else if content_type == 0x15 {
                        serial::println(b"[HTTPS] got alert");
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
