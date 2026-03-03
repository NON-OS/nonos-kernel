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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use spin::Mutex;
use super::AsyncResult;
use super::tcp::{tcp_start_connect, tcp_poll_connect, tcp_send, tcp_poll_receive, tcp_close};
use super::super::device::now_ms;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HttpState {
    Idle,
    Connecting,
    Sending,
    ReceivingHeaders,
    ReceivingBody,
    Done,
    Error,
}

static HTTP_STATE: Mutex<HttpState> = Mutex::new(HttpState::Idle);
static HTTP_START: AtomicU64 = AtomicU64::new(0);
static HTTP_RESPONSE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static HTTP_ERROR: Mutex<Option<&'static str>> = Mutex::new(None);
static HTTP_REQUEST: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static HTTP_SENT: AtomicBool = AtomicBool::new(false);
static HTTP_CONTENT_LENGTH: Mutex<Option<usize>> = Mutex::new(None);
static HTTP_HEADERS_DONE: AtomicBool = AtomicBool::new(false);

pub fn http_start_request(addr: [u8; 4], port: u16, request: Vec<u8>) -> Result<(), &'static str> {
    let state = *HTTP_STATE.lock();
    if state != HttpState::Idle && state != HttpState::Done && state != HttpState::Error {
        return Err("http request already in progress");
    }

    *HTTP_REQUEST.lock() = request;
    *HTTP_RESPONSE.lock() = Vec::new();
    *HTTP_ERROR.lock() = None;
    *HTTP_CONTENT_LENGTH.lock() = None;
    HTTP_SENT.store(false, Ordering::SeqCst);
    HTTP_HEADERS_DONE.store(false, Ordering::SeqCst);
    HTTP_START.store(now_ms(), Ordering::SeqCst);

    tcp_start_connect(addr, port)?;

    *HTTP_STATE.lock() = HttpState::Connecting;
    Ok(())
}

pub fn http_poll() -> AsyncResult<Vec<u8>> {
    let state = *HTTP_STATE.lock();

    let elapsed = now_ms().saturating_sub(HTTP_START.load(Ordering::SeqCst));
    if elapsed > 10000 && state != HttpState::Idle && state != HttpState::Done {
        http_cleanup();
        *HTTP_ERROR.lock() = Some("http timeout");
        return AsyncResult::Error("http timeout");
    }

    match state {
        HttpState::Idle => AsyncResult::Error("no http request"),

        HttpState::Connecting => {
            match tcp_poll_connect() {
                AsyncResult::Ready(()) => {
                    *HTTP_STATE.lock() = HttpState::Sending;
                    AsyncResult::Pending
                }
                AsyncResult::Pending => AsyncResult::Pending,
                AsyncResult::Error(e) => {
                    http_cleanup();
                    *HTTP_ERROR.lock() = Some(e);
                    AsyncResult::Error(e)
                }
            }
        }

        HttpState::Sending => {
            if !HTTP_SENT.load(Ordering::SeqCst) {
                let request = HTTP_REQUEST.lock().clone();
                match tcp_send(&request) {
                    Ok(n) if n == request.len() => {
                        HTTP_SENT.store(true, Ordering::SeqCst);
                        *HTTP_STATE.lock() = HttpState::ReceivingHeaders;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        http_cleanup();
                        *HTTP_ERROR.lock() = Some(e);
                        return AsyncResult::Error(e);
                    }
                }
            } else {
                *HTTP_STATE.lock() = HttpState::ReceivingHeaders;
            }
            AsyncResult::Pending
        }

        HttpState::ReceivingHeaders | HttpState::ReceivingBody => {
            match tcp_poll_receive(4096) {
                AsyncResult::Ready(data) => {
                    if data.is_empty() {
                        let response = HTTP_RESPONSE.lock().clone();
                        http_cleanup();
                        *HTTP_STATE.lock() = HttpState::Done;
                        return AsyncResult::Ready(response);
                    }

                    HTTP_RESPONSE.lock().extend_from_slice(&data);

                    if !HTTP_HEADERS_DONE.load(Ordering::SeqCst) {
                        let response = HTTP_RESPONSE.lock();
                        if let Some(idx) = find_header_end(&response) {
                            let headers = &response[..idx];
                            let cl = parse_content_length(headers);
                            drop(response);
                            if let Some(c) = cl {
                                *HTTP_CONTENT_LENGTH.lock() = Some(c);
                            }
                            HTTP_HEADERS_DONE.store(true, Ordering::SeqCst);
                            *HTTP_STATE.lock() = HttpState::ReceivingBody;
                        }
                    }

                    if HTTP_HEADERS_DONE.load(Ordering::SeqCst) {
                        let response = HTTP_RESPONSE.lock();
                        if let Some(idx) = find_header_end(&response) {
                            let body_len = response.len() - (idx + 4);
                            if let Some(cl) = *HTTP_CONTENT_LENGTH.lock() {
                                if body_len >= cl {
                                    let result = response.clone();
                                    drop(response);
                                    http_cleanup();
                                    *HTTP_STATE.lock() = HttpState::Done;
                                    return AsyncResult::Ready(result);
                                }
                            }
                        }
                    }

                    AsyncResult::Pending
                }
                AsyncResult::Pending => AsyncResult::Pending,
                AsyncResult::Error(e) => {
                    let response = HTTP_RESPONSE.lock().clone();
                    if !response.is_empty() {
                        http_cleanup();
                        *HTTP_STATE.lock() = HttpState::Done;
                        return AsyncResult::Ready(response);
                    }
                    http_cleanup();
                    *HTTP_ERROR.lock() = Some(e);
                    AsyncResult::Error(e)
                }
            }
        }

        HttpState::Done => {
            let response = HTTP_RESPONSE.lock().clone();
            AsyncResult::Ready(response)
        }

        HttpState::Error => {
            let e = HTTP_ERROR.lock().unwrap_or("unknown error");
            AsyncResult::Error(e)
        }
    }
}

fn http_cleanup() {
    tcp_close();
    *HTTP_STATE.lock() = HttpState::Idle;
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"

" {
            return Some(i);
        }
    }
    None
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let val = line[15..].trim();
            return val.parse().ok();
        }
    }
    None
}

pub fn http_cancel() {
    http_cleanup();
}

pub fn http_is_active() -> bool {
    let state = *HTTP_STATE.lock();
    state != HttpState::Idle && state != HttpState::Done && state != HttpState::Error
}
