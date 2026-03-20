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
            crate::sys::serial::print(b"[HTTPS] TCP connect started, id=");
            crate::sys::serial::print_dec(conn_id as u64);
            crate::sys::serial::println(b"");
            HTTPS_CONN_ID.store(conn_id, Ordering::Relaxed);
            HTTPS_DEADLINE.store(crate::time::timestamp_millis() + 20000, Ordering::Relaxed);
            set_state(NavState::Connecting);
        }
        Err(e) => {
            crate::sys::serial::print(b"[HTTPS] TCP start failed: ");
            crate::sys::serial::println(e.as_bytes());
            finish_with_error(e);
        }
    }
}

pub(super) fn poll_tcp_connect() {
    // Drive the network stack so SYN-ACK frames are processed.
    crate::network::poll_network();

    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    let now = crate::time::timestamp_millis();
    if now > deadline {
        crate::sys::serial::println(b"[HTTPS] TCP connect deadline exceeded");
        tcp_close();
        finish_with_error("TCP connect timeout");
        return;
    }

    match tcp_poll_connect() {
        AsyncResult::Ready(()) => {
            crate::sys::serial::println(b"[HTTPS] TCP connected, starting TLS");
            start_tls_handshake();
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[HTTPS] tcp_poll_connect error: ");
            crate::sys::serial::println(e.as_bytes());
            finish_with_error(e);
        }
    }
}

fn start_tls_handshake() {
    crate::sys::serial::println(b"[HTTPS] start_tls_handshake()");
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
        crate::sys::serial::println(b"[HTTPS] tls.start_handshake FAILED");
        tcp_close();
        finish_with_error("TLS start failed");
        return;
    }

    *HTTPS_TLS.lock() = Some(tls);
    crate::sys::serial::println(b"[HTTPS] TLS handshake started, state=TlsHandshake");
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
    // Ensure outbound TCP segments from the TLS handshake are flushed
    // and any late server frames are ingested before we send the request.
    crate::network::poll_network();

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
    crate::sys::serial::print(b"[HTTPS] sending request, wrapped_len=");
    crate::sys::serial::print_dec(wrapped.len() as u64);
    crate::sys::serial::println(b"");
    match tcp_send(&wrapped) {
        Ok(n) => {
            crate::sys::serial::print(b"[HTTPS] tcp_send ok, sent=");
            crate::sys::serial::print_dec(n as u64);
            crate::sys::serial::println(b"");
        }
        Err(e) => {
            crate::sys::serial::print(b"[HTTPS] tcp_send failed: ");
            crate::sys::serial::println(e.as_bytes());
            cleanup_https();
            finish_with_error("TCP send failed");
            return;
        }
    }

    // Flush the buffered send data immediately so the server sees it
    crate::network::poll_network();

    HTTPS_DEADLINE.store(crate::time::timestamp_millis() + 15000, Ordering::Relaxed);
    set_state(NavState::ReceivingResponse);
}

pub(super) fn poll_receive_response() {
    // Drive the network stack — without this, RX frames sit in the NIC
    // ring buffer and smoltcp never sees them.  poll_tls_handshake already
    // does this; the response-receive path was missing it, causing timeouts
    // under light polling from the UI main loop.
    crate::network::poll_network();

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

    static RX_DBG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let rx_ctr = RX_DBG.fetch_add(1, Ordering::Relaxed);

    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            crate::sys::serial::print(b"[HTTPS-RX] Ready len=");
            crate::sys::serial::print_dec(received.len() as u64);
            if received.len() >= 5 {
                crate::sys::serial::print(b" ct=");
                crate::sys::serial::print_hex(received[0] as u64);
                crate::sys::serial::print(b" ver=");
                crate::sys::serial::print_hex(received[1] as u64);
                crate::sys::serial::print(b",");
                crate::sys::serial::print_hex(received[2] as u64);
                let rec_len = u16::from_be_bytes([received[3], received[4]]);
                crate::sys::serial::print(b" rec_len=");
                crate::sys::serial::print_dec(rec_len as u64);
            }
            crate::sys::serial::println(b"");
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
                // Append new data to the persistent reassembly buffer so that
                // partial TLS records left over from a previous TCP read are
                // completed by bytes arriving in this read.
                let mut reasm = HTTPS_REASSEMBLY_BUF.lock();
                reasm.extend_from_slice(&received);

                let mut tls_guard = HTTPS_TLS.lock();
                let tls = match tls_guard.as_mut() {
                    Some(t) => t,
                    None => {
                        drop(tls_guard);
                        drop(reasm);
                        cleanup_https();
                        finish_with_error("no TLS session");
                        return;
                    }
                };

                let mut offset = 0;
                while offset + 5 <= reasm.len() {
                    let content_type = reasm[offset];
                    let record_len = u16::from_be_bytes([reasm[offset + 3], reasm[offset + 4]]) as usize;

                    if offset + 5 + record_len > reasm.len() {
                        // Incomplete record — wait for more TCP data.
                        break;
                    }

                    let record_data = &reasm[offset + 5..offset + 5 + record_len];

                    if content_type == 0x17 {
                        match tls.decrypt_app(record_data) {
                            Ok(plaintext) => {
                                if !plaintext.is_empty() {
                                    collected_plaintext.extend_from_slice(&plaintext[..plaintext.len().saturating_sub(1)]);
                                }
                            }
                            Err(_e) => {
                                crate::sys::serial::print(b"[HTTPS-RX] decrypt_app FAILED, record_len=");
                                crate::sys::serial::print_dec(record_data.len() as u64);
                                crate::sys::serial::println(b"");
                            }
                        }
                    } else if content_type == 0x15 {
                        got_alert = true;
                        crate::sys::serial::println(b"[HTTPS-RX] got TLS alert");
                        break;
                    } else {
                        crate::sys::serial::print(b"[HTTPS-RX] unknown ct=0x");
                        crate::sys::serial::print_hex(content_type as u64);
                        crate::sys::serial::print(b" len=");
                        crate::sys::serial::print_dec(record_len as u64);
                        crate::sys::serial::println(b"");
                    }

                    offset += 5 + record_len;
                }

                // Drain only the bytes we fully consumed, keeping any
                // incomplete trailing record for the next poll call.
                if offset > 0 {
                    reasm.drain(..offset);
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
        AsyncResult::Pending => {
            if rx_ctr % 2000 == 0 {
                crate::sys::serial::print(b"[HTTPS-RX] Pending #");
                crate::sys::serial::print_dec(rx_ctr as u64);
                crate::sys::serial::println(b"");
            }
        }
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[HTTPS-RX] Error: ");
            crate::sys::serial::println(e.as_bytes());
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
