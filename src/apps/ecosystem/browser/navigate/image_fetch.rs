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

//! Async image fetch pipeline — poll-based, non-blocking.
//!
//! Uses the global TCP/DNS async ops (which are free after navigation
//! completes) plus its own TLS session and reassembly buffer.  One image
//! at a time, driven once per main-loop tick from `poll_navigation()`.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;
use crate::network::stack::async_ops::{
    tcp_start_connect, tcp_poll_connect, tcp_send, tcp_poll_receive, tcp_close,
    dns_start_query, dns_poll, dns_cancel, AsyncResult,
};
use crate::network::onion::tls::TLSConnection;
use crate::network::tcp::TcpSocket as TcpSocketWrapper;
use crate::graphics::window::ecosystem::state as window_state;
use super::response::{find_header_end, is_response_complete};

// ── Image-fetch sub-state machine ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ImgFetchState {
    Idle = 0,
    DnsResolve = 1,
    Connecting = 2,
    TlsHandshake = 3,
    Sending = 4,
    Receiving = 5,
    Decoding = 6,
}

impl ImgFetchState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::DnsResolve,
            2 => Self::Connecting,
            3 => Self::TlsHandshake,
            4 => Self::Sending,
            5 => Self::Receiving,
            6 => Self::Decoding,
            _ => Self::Idle,
        }
    }
}

// ── Statics (separate from navigation — no conflict) ─────────────────

static IMG_STATE: AtomicU8 = AtomicU8::new(0);
static IMG_DEADLINE: AtomicU64 = AtomicU64::new(0);
static IMG_CONN_ID: AtomicU32 = AtomicU32::new(0);
static IMG_TLS: Mutex<Option<TLSConnection>> = Mutex::new(None);
static IMG_REASSEMBLY: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static IMG_RESPONSE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static IMG_HOST: Mutex<Option<String>> = Mutex::new(None);
static IMG_PATH: Mutex<Option<String>> = Mutex::new(None);
static IMG_PORT: Mutex<u16> = Mutex::new(443);
static IMG_IP: Mutex<Option<[u8; 4]>> = Mutex::new(None);
static IMG_IS_HTTPS: AtomicBool = AtomicBool::new(true);

/// Placeholder positions in PAGE_RENDER to patch when this image decodes.
static IMG_TARGETS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

/// Consecutive failure counter — bail after `MAX_IMG_FAILURES`.
static IMG_FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Navigation host + IP saved before cleanup for same-host optimisation.
static IMG_NAV_HOST: Mutex<Option<String>> = Mutex::new(None);
static IMG_NAV_IP: Mutex<Option<[u8; 4]>> = Mutex::new(None);

const MAX_IMG_FAILURES: u32 = 3;
const IMG_TIMEOUT_MS: u64 = 10_000;
const MAX_IMG_RESPONSE: usize = 2 * 1024 * 1024;

// ── Helpers ──────────────────────────────────────────────────────────

fn get_img_state() -> ImgFetchState {
    ImgFetchState::from_u8(IMG_STATE.load(Ordering::Relaxed))
}

fn set_img_state(state: ImgFetchState) {
    IMG_STATE.store(state as u8, Ordering::SeqCst);
}

fn is_timed_out() -> bool {
    let deadline = IMG_DEADLINE.load(Ordering::Relaxed);
    deadline > 0 && crate::time::timestamp_millis() > deadline
}

// ── Public API (called from api.rs / response.rs) ────────────────────

/// Save the navigation host + resolved IP so same-host images skip DNS.
/// Must be called **before** `cleanup_navigation()` clears those statics.
pub(super) fn set_nav_context(host: &str, ip: Option<[u8; 4]>) {
    *IMG_NAV_HOST.lock() = if host.is_empty() { None } else { Some(String::from(host)) };
    *IMG_NAV_IP.lock() = ip;
}

/// Reset all image-fetch state.  Call before starting a new batch.
pub(super) fn reset() {
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

/// Abort an in-progress image fetch and release resources.
pub(super) fn abort() {
    let state = get_img_state();
    match state {
        ImgFetchState::DnsResolve => { dns_cancel(); }
        ImgFetchState::Connecting
        | ImgFetchState::TlsHandshake
        | ImgFetchState::Sending
        | ImgFetchState::Receiving => { img_cleanup(); }
        _ => {}
    }
    reset();
}

/// Main poll entry point — called each tick from `poll_navigation()`
/// when `NavState == LoadingImages`.
pub(super) fn poll_image_fetch() {
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

// ── Internal: cleanup ────────────────────────────────────────────────

fn img_cleanup() {
    tcp_close();
    IMG_CONN_ID.store(0, Ordering::Relaxed);
    *IMG_TLS.lock() = None;
    IMG_REASSEMBLY.lock().clear();
}

fn skip_current_image() {
    IMG_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
    IMG_RESPONSE.lock().clear();
    IMG_TARGETS.lock().clear();
    set_img_state(ImgFetchState::Idle);
}

fn finish_all_images() {
    crate::sys::serial::println(b"[IMG-FETCH] all done");
    super::state::set_state(super::state::NavState::Done);
}

// ── Queue consumer ───────────────────────────────────────────────────

fn start_next_image() {
    if IMG_FAIL_COUNT.load(Ordering::Relaxed) >= MAX_IMG_FAILURES {
        crate::sys::serial::println(b"[IMG-FETCH] too many failures, bailing");
        finish_all_images();
        return;
    }

    let entry = super::state::PENDING_IMAGES.lock().pop();
    let (line_idx, elem_idx, url) = match entry {
        Some(e) => e,
        None => {
            finish_all_images();
            return;
        }
    };

    crate::sys::serial::print(b"[IMG-FETCH] start: ");
    crate::sys::serial::println(url.as_bytes());

    // Dedup: collect all other queue entries with the same URL
    let mut targets = alloc::vec![(line_idx, elem_idx)];
    {
        let mut queue = super::state::PENDING_IMAGES.lock();
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

    // Parse URL → host, port, path, is_https
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

    // Same-host optimisation: reuse already-resolved IP
    let nav_host = IMG_NAV_HOST.lock().clone();
    let nav_ip = *IMG_NAV_IP.lock();

    if Some(&host) == nav_host.as_ref() {
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

    // Different host — need DNS
    *IMG_IP.lock() = None;
    match dns_start_query(&host) {
        Ok(_) => set_img_state(ImgFetchState::DnsResolve),
        Err(e) => {
            crate::sys::serial::print(b"[IMG-FETCH] dns start failed: ");
            crate::sys::serial::println(e.as_bytes());
            skip_current_image();
        }
    }
}

// ── DNS resolve ──────────────────────────────────────────────────────

fn poll_img_dns() {
    if is_timed_out() {
        crate::sys::serial::println(b"[IMG-FETCH] DNS timeout");
        dns_cancel();
        skip_current_image();
        return;
    }

    match dns_poll() {
        AsyncResult::Ready(ip) => {
            crate::sys::serial::print(b"[IMG-FETCH] resolved ");
            crate::sys::serial::print_dec(ip[0] as u64);
            crate::sys::serial::print(b".");
            crate::sys::serial::print_dec(ip[1] as u64);
            crate::sys::serial::print(b".");
            crate::sys::serial::print_dec(ip[2] as u64);
            crate::sys::serial::print(b".");
            crate::sys::serial::print_dec(ip[3] as u64);
            crate::sys::serial::println(b"");

            *IMG_IP.lock() = Some(ip);
            let port = *IMG_PORT.lock();
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
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[IMG-FETCH] DNS error: ");
            crate::sys::serial::println(e.as_bytes());
            skip_current_image();
        }
    }
}

// ── TCP connect ──────────────────────────────────────────────────────

fn poll_img_connect() {
    if is_timed_out() {
        crate::sys::serial::println(b"[IMG-FETCH] connect timeout");
        img_cleanup();
        skip_current_image();
        return;
    }

    match tcp_poll_connect() {
        AsyncResult::Ready(()) => {
            if IMG_IS_HTTPS.load(Ordering::Relaxed) {
                crate::sys::serial::println(b"[IMG-FETCH] connected, starting TLS");
                start_img_tls();
            } else {
                crate::sys::serial::println(b"[IMG-FETCH] connected (HTTP), sending");
                set_img_state(ImgFetchState::Sending);
            }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[IMG-FETCH] connect error: ");
            crate::sys::serial::println(e.as_bytes());
            skip_current_image();
        }
    }
}

// ── TLS handshake ────────────────────────────────────────────────────

fn start_img_tls() {
    let conn_id = IMG_CONN_ID.load(Ordering::Relaxed);
    let host = match IMG_HOST.lock().clone() {
        Some(h) => h,
        None => {
            img_cleanup();
            skip_current_image();
            return;
        }
    };

    let socket = TcpSocketWrapper::from_connection(conn_id);
    let mut tls = TLSConnection::new();

    if let Err(_) = tls.start_handshake(&socket, Some(&host), Some(&["http/1.1"])) {
        crate::sys::serial::println(b"[IMG-FETCH] TLS start failed");
        img_cleanup();
        skip_current_image();
        return;
    }

    *IMG_TLS.lock() = Some(tls);
    set_img_state(ImgFetchState::TlsHandshake);
}

fn poll_img_tls() {
    if is_timed_out() {
        crate::sys::serial::println(b"[IMG-FETCH] TLS timeout");
        img_cleanup();
        skip_current_image();
        return;
    }

    crate::network::poll_network();

    let conn_id = IMG_CONN_ID.load(Ordering::Relaxed);
    let socket = TcpSocketWrapper::from_connection(conn_id);

    let host = match IMG_HOST.lock().clone() {
        Some(h) => h,
        None => {
            img_cleanup();
            skip_current_image();
            return;
        }
    };

    let verifier = crate::network::onion::tls::get_cert_verifier()
        .unwrap_or(&crate::network::onion::tls::HTTPS_CERT_VERIFIER);

    let mut tls_guard = IMG_TLS.lock();
    let tls = match tls_guard.as_mut() {
        Some(t) => t,
        None => {
            drop(tls_guard);
            img_cleanup();
            skip_current_image();
            return;
        }
    };

    match tls.poll_handshake(&socket, Some(&host), verifier) {
        Ok(Some(_)) => {
            drop(tls_guard);
            crate::sys::serial::println(b"[IMG-FETCH] TLS done");
            set_img_state(ImgFetchState::Sending);
        }
        Ok(None) => {}
        Err(_) => {
            drop(tls_guard);
            crate::sys::serial::println(b"[IMG-FETCH] TLS handshake failed");
            img_cleanup();
            skip_current_image();
        }
    }
}

// ── Send HTTP request ────────────────────────────────────────────────

fn poll_img_send() {
    crate::network::poll_network();

    let host = match IMG_HOST.lock().clone() {
        Some(h) => h,
        None => {
            img_cleanup();
            skip_current_image();
            return;
        }
    };

    let path = IMG_PATH.lock().clone().unwrap_or_else(|| String::from("/"));

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NONOS/1.0\r\nAccept: image/*,*/*\r\nConnection: close\r\n\r\n",
        path, host
    );

    if IMG_IS_HTTPS.load(Ordering::Relaxed) {
        let mut tls_guard = IMG_TLS.lock();
        let tls = match tls_guard.as_mut() {
            Some(t) => t,
            None => {
                drop(tls_guard);
                img_cleanup();
                skip_current_image();
                return;
            }
        };

        let encrypted = match tls.encrypt_app(request.as_bytes()) {
            Ok(data) => data,
            Err(_) => {
                drop(tls_guard);
                img_cleanup();
                skip_current_image();
                return;
            }
        };
        drop(tls_guard);

        let wrapped = wrap_tls_record(0x17, &encrypted);
        if let Err(e) = tcp_send(&wrapped) {
            crate::sys::serial::print(b"[IMG-FETCH] send failed: ");
            crate::sys::serial::println(e.as_bytes());
            img_cleanup();
            skip_current_image();
            return;
        }
    } else {
        if let Err(e) = tcp_send(request.as_bytes()) {
            crate::sys::serial::print(b"[IMG-FETCH] send failed: ");
            crate::sys::serial::println(e.as_bytes());
            img_cleanup();
            skip_current_image();
            return;
        }
    }

    crate::sys::serial::println(b"[IMG-FETCH] request sent");
    crate::network::poll_network();
    IMG_DEADLINE.store(crate::time::timestamp_millis() + IMG_TIMEOUT_MS, Ordering::Relaxed);
    set_img_state(ImgFetchState::Receiving);
}

// ── Receive response ─────────────────────────────────────────────────

fn poll_img_receive() {
    crate::network::poll_network();

    if is_timed_out() {
        let has_data = !IMG_RESPONSE.lock().is_empty();
        if has_data {
            crate::sys::serial::println(b"[IMG-FETCH] timeout with partial data");
            img_cleanup();
            set_img_state(ImgFetchState::Decoding);
        } else {
            crate::sys::serial::println(b"[IMG-FETCH] receive timeout");
            img_cleanup();
            skip_current_image();
        }
        return;
    }

    if IMG_IS_HTTPS.load(Ordering::Relaxed) {
        poll_img_receive_https();
    } else {
        poll_img_receive_http();
    }
}

fn poll_img_receive_https() {
    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            if received.is_empty() {
                if !IMG_RESPONSE.lock().is_empty() {
                    img_cleanup();
                    set_img_state(ImgFetchState::Decoding);
                }
                return;
            }

            let mut collected_plaintext: Vec<u8> = Vec::new();
            let mut got_alert = false;

            {
                let mut reasm = IMG_REASSEMBLY.lock();
                reasm.extend_from_slice(&received);

                let mut tls_guard = IMG_TLS.lock();
                let tls = match tls_guard.as_mut() {
                    Some(t) => t,
                    None => {
                        drop(tls_guard);
                        drop(reasm);
                        img_cleanup();
                        skip_current_image();
                        return;
                    }
                };

                let mut offset = 0;
                while offset + 5 <= reasm.len() {
                    let content_type = reasm[offset];
                    let record_len = u16::from_be_bytes([
                        reasm[offset + 3],
                        reasm[offset + 4],
                    ]) as usize;

                    if offset + 5 + record_len > reasm.len() {
                        break; // incomplete record — wait for more
                    }

                    let record_data = &reasm[offset + 5..offset + 5 + record_len];

                    if content_type == 0x17 {
                        match tls.decrypt_app(record_data) {
                            Ok(plaintext) => {
                                if !plaintext.is_empty() {
                                    // TLS 1.3 inner plaintext: data || ct(1) || padding(0+)
                                    let mut end = plaintext.len();
                                    while end > 0 && plaintext[end - 1] == 0 {
                                        end -= 1;
                                    }
                                    if end > 0 {
                                        end -= 1; // content type byte
                                    }
                                    collected_plaintext.extend_from_slice(&plaintext[..end]);
                                }
                            }
                            Err(_) => {
                                crate::sys::serial::println(b"[IMG-FETCH] decrypt failed");
                            }
                        }
                    } else if content_type == 0x15 {
                        got_alert = true;
                        break;
                    }

                    offset += 5 + record_len;
                }

                if offset > 0 {
                    reasm.drain(..offset);
                }
            }

            if !collected_plaintext.is_empty() {
                let mut response = IMG_RESPONSE.lock();
                response.extend_from_slice(&collected_plaintext);

                if response.len() > MAX_IMG_RESPONSE {
                    crate::sys::serial::println(b"[IMG-FETCH] too large");
                    drop(response);
                    img_cleanup();
                    skip_current_image();
                    return;
                }
            }

            if got_alert {
                img_cleanup();
                set_img_state(ImgFetchState::Decoding);
                return;
            }

            let response = IMG_RESPONSE.lock();
            if response.len() > 4 {
                if find_header_end(&response).is_some() {
                    if is_response_complete(&response) || response.len() > MAX_IMG_RESPONSE {
                        drop(response);
                        img_cleanup();
                        set_img_state(ImgFetchState::Decoding);
                        return;
                    }
                }
            }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(_) => {
            if !IMG_RESPONSE.lock().is_empty() {
                img_cleanup();
                set_img_state(ImgFetchState::Decoding);
            } else {
                img_cleanup();
                skip_current_image();
            }
        }
    }
}

fn poll_img_receive_http() {
    match tcp_poll_receive(8192) {
        AsyncResult::Ready(received) => {
            if received.is_empty() {
                if !IMG_RESPONSE.lock().is_empty() {
                    img_cleanup();
                    set_img_state(ImgFetchState::Decoding);
                }
                return;
            }

            let mut response = IMG_RESPONSE.lock();
            response.extend_from_slice(&received);

            if response.len() > MAX_IMG_RESPONSE {
                drop(response);
                img_cleanup();
                skip_current_image();
                return;
            }

            if response.len() > 4 {
                if find_header_end(&response).is_some() {
                    if is_response_complete(&response) {
                        drop(response);
                        img_cleanup();
                        set_img_state(ImgFetchState::Decoding);
                    }
                }
            }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(_) => {
            if !IMG_RESPONSE.lock().is_empty() {
                img_cleanup();
                set_img_state(ImgFetchState::Decoding);
            } else {
                img_cleanup();
                skip_current_image();
            }
        }
    }
}

// ── Decode and patch ─────────────────────────────────────────────────

fn poll_img_decode() {
    use super::super::engine;

    let response_data = IMG_RESPONSE.lock().clone();
    if response_data.is_empty() {
        skip_current_image();
        return;
    }

    let body = extract_img_body(&response_data);
    if body.is_empty() {
        crate::sys::serial::println(b"[IMG-FETCH] empty body");
        skip_current_image();
        return;
    }

    crate::sys::serial::print(b"[IMG-FETCH] decode body=");
    crate::sys::serial::print_dec(body.len() as u64);
    crate::sys::serial::println(b"");

    let format = engine::image_loader::detect_image_format(&body);
    let decoded = match format {
        engine::image_loader::ImageFormat::Jpeg => engine::decode_jpeg(&body),
        engine::image_loader::ImageFormat::Png => engine::decode_png(&body),
        engine::image_loader::ImageFormat::Unknown => {
            crate::sys::serial::println(b"[IMG-FETCH] unknown format");
            None
        }
    };

    match decoded {
        Some(data) => {
            crate::sys::serial::print(b"[IMG-FETCH] decoded ");
            crate::sys::serial::print_dec(data.width as u64);
            crate::sys::serial::print(b"x");
            crate::sys::serial::print_dec(data.height as u64);
            crate::sys::serial::println(b"");

            let targets = IMG_TARGETS.lock().clone();
            let mut page = window_state::PAGE_RENDER.lock();
            if let Some(ref mut ro) = *page {
                for &(line_idx, elem_idx) in &targets {
                    if let Some(line) = ro.lines.get_mut(line_idx) {
                        if let Some(elem) = line.elements.get_mut(elem_idx) {
                            elem.content = engine::RenderContent::DecodedImage {
                                data: data.clone(),
                            };
                        }
                    }
                }
            }
            drop(page);
            window_state::mark_content_changed();

            // Success resets the consecutive failure counter
            IMG_FAIL_COUNT.store(0, Ordering::Relaxed);
        }
        None => {
            crate::sys::serial::println(b"[IMG-FETCH] decode failed");
            IMG_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    IMG_RESPONSE.lock().clear();
    IMG_TARGETS.lock().clear();
    set_img_state(ImgFetchState::Idle);
}

// ── URL parsing ──────────────────────────────────────────────────────

/// Parse an image URL into (host, port, path, is_https).
fn parse_image_url(url: &str) -> Option<(String, u16, String, bool)> {
    let (is_https, rest) = if url.starts_with("https://") {
        (true, &url[8..])
    } else if url.starts_with("http://") {
        (false, &url[7..])
    } else {
        return None;
    };

    let default_port: u16 = if is_https { 443 } else { 80 };

    let (host_port, path) = match rest.find('/') {
        Some(pos) => (&rest[..pos], String::from(&rest[pos..])),
        None => (rest, String::from("/")),
    };

    let (host, port) = match host_port.find(':') {
        Some(pos) => {
            let h = &host_port[..pos];
            let p: u16 = host_port[pos + 1..].parse().ok()?;
            (h, p)
        }
        None => (host_port, default_port),
    };

    Some((String::from(host), port, path, is_https))
}

// ── HTTP body extraction ─────────────────────────────────────────────

fn extract_img_body(data: &[u8]) -> Vec<u8> {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let raw_body = &data[header_end + 4..];
        if is_chunked_img(headers) {
            decode_chunked_img(raw_body)
        } else {
            Vec::from(raw_body)
        }
    } else {
        Vec::from(data)
    }
}

fn is_chunked_img(headers: &[u8]) -> bool {
    let s = match core::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") {
            return lower[18..].trim().contains("chunked");
        }
    }
    false
}

fn decode_chunked_img(mut data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let crlf = match data.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => pos,
            None => break,
        };
        let size_str = match core::str::from_utf8(&data[..crlf]) {
            Ok(s) => s.split(';').next().unwrap_or("").trim(),
            Err(_) => break,
        };
        let chunk_len = match usize::from_str_radix(size_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        if chunk_len == 0 {
            break;
        }
        let chunk_start = crlf + 2;
        let chunk_end = chunk_start + chunk_len;
        if chunk_end > data.len() {
            output.extend_from_slice(&data[chunk_start..]);
            break;
        }
        output.extend_from_slice(&data[chunk_start..chunk_end]);
        let next = chunk_end + 2;
        if next > data.len() {
            break;
        }
        data = &data[next..];
    }
    output
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

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_https_url() {
        let (host, port, path, is_https) =
            parse_image_url("https://www.google.com/images/logo.png").unwrap();
        assert_eq!(host, "www.google.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/images/logo.png");
        assert!(is_https);
    }

    #[test]
    fn test_parse_http_url() {
        let (host, port, path, is_https) =
            parse_image_url("http://example.com/img.jpg").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/img.jpg");
        assert!(!is_https);
    }

    #[test]
    fn test_parse_url_with_port() {
        let (host, port, path, is_https) =
            parse_image_url("https://cdn.example.com:8443/img.png").unwrap();
        assert_eq!(host, "cdn.example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/img.png");
        assert!(is_https);
    }

    #[test]
    fn test_parse_url_no_path() {
        let (host, port, path, is_https) =
            parse_image_url("https://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");
        assert!(is_https);
    }

    #[test]
    fn test_parse_invalid_url() {
        assert!(parse_image_url("ftp://example.com").is_none());
        assert!(parse_image_url("data:image/png;base64,abc").is_none());
        assert!(parse_image_url("").is_none());
    }

    #[test]
    fn test_state_roundtrip() {
        for v in 0..=6u8 {
            let state = ImgFetchState::from_u8(v);
            assert_eq!(state as u8, v);
        }
        assert_eq!(ImgFetchState::from_u8(99), ImgFetchState::Idle);
    }

    #[test]
    fn test_dedup_logic() {
        let url = "https://example.com/a.png";
        let mut queue = alloc::vec![
            (2usize, 3usize, String::from("https://example.com/a.png")),
            (4, 5, String::from("https://example.com/b.png")),
            (6, 7, String::from("https://example.com/a.png")),
        ];

        let mut targets = alloc::vec![(0usize, 1usize)];
        let mut i = 0;
        while i < queue.len() {
            if queue[i].2 == url {
                targets.push((queue[i].0, queue[i].1));
                queue.remove(i);
            } else {
                i += 1;
            }
        }

        assert_eq!(targets.len(), 3);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].2, "https://example.com/b.png");
    }

    #[test]
    fn test_extract_img_body_basic() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 5\r\n\r\nhello";
        let body = extract_img_body(response);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn test_extract_img_body_no_headers() {
        let data = b"\x89PNG raw data";
        let body = extract_img_body(data);
        assert_eq!(body, data);
    }

    #[test]
    fn test_extract_img_body_chunked() {
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let body = extract_img_body(response);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn test_wrap_tls_record() {
        let data = b"hello";
        let record = wrap_tls_record(0x17, data);
        assert_eq!(record[0], 0x17);
        assert_eq!(record[1], 0x03);
        assert_eq!(record[2], 0x03);
        assert_eq!(u16::from_be_bytes([record[3], record[4]]), 5);
        assert_eq!(&record[5..], b"hello");
    }

    #[test]
    fn test_skip_data_uri() {
        assert!(parse_image_url("data:image/png;base64,abc").is_none());
    }

    #[test]
    fn test_skip_empty_src() {
        assert!(parse_image_url("").is_none());
    }
}
