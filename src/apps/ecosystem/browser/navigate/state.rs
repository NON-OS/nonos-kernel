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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum NavState {
    Idle = 0,
    ResolvingDns = 1,
    Connecting = 2,
    TlsHandshake = 3,
    SendingRequest = 4,
    ReceivingResponse = 5,
    ProcessingResponse = 6,
    Done = 7,
    Error = 8,
    LoadingImages = 9,
}

impl NavState {
    pub(super) fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ResolvingDns,
            2 => Self::Connecting,
            3 => Self::TlsHandshake,
            4 => Self::SendingRequest,
            5 => Self::ReceivingResponse,
            6 => Self::ProcessingResponse,
            7 => Self::Done,
            8 => Self::Error,
            9 => Self::LoadingImages,
            _ => Self::Idle,
        }
    }
}

pub(super) static RUNNING: AtomicBool = AtomicBool::new(false);
pub(super) static NAV_STATE: AtomicU8 = AtomicU8::new(0);
pub(super) static PENDING_URL: Mutex<Option<String>> = Mutex::new(None);
pub(super) static RESOLVED_IP: Mutex<Option<[u8; 4]>> = Mutex::new(None);
pub(super) static PENDING_HOST: Mutex<Option<String>> = Mutex::new(None);
pub(super) static PENDING_PORT: Mutex<u16> = Mutex::new(443);
pub(super) static PENDING_PATH: Mutex<Option<String>> = Mutex::new(None);
pub(super) static PENDING_HTTPS: AtomicBool = AtomicBool::new(true);
pub(super) static PENDING_METHOD: Mutex<Option<String>> = Mutex::new(None);
pub(super) static PENDING_BODY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
pub(super) static PENDING_CONTENT_TYPE: Mutex<Option<String>> = Mutex::new(None);
pub(super) static NAV_ERROR: Mutex<Option<&'static str>> = Mutex::new(None);
pub(super) static RESPONSE_DATA: Mutex<Vec<u8>> = Mutex::new(Vec::new());
pub(super) static HTTPS_CONN_ID: AtomicU32 = AtomicU32::new(0);
pub(super) static HTTPS_TLS: Mutex<Option<crate::network::onion::tls::TLSConnection>> =
    Mutex::new(None);
pub(super) static HTTPS_DEADLINE: AtomicU64 = AtomicU64::new(0);
pub(super) static HTTPS_REASSEMBLY_BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());
pub(super) static REDIRECT_COUNT: AtomicU8 = AtomicU8::new(0);
pub(super) const MAX_REDIRECTS: u8 = 5;
pub(super) const MAX_HTTPS_REASSEMBLY: usize = 64 * 1024;
pub(super) const MAX_HTTPS_RECORD: usize = 17 * 1024;

/// Queue of pending image fetches: (line_idx, elem_idx, absolute_url).
/// Populated after render completes; drained one-per-poll-tick in LoadingImages.
pub(super) static PENDING_IMAGES: Mutex<Vec<(usize, usize, String)>> = Mutex::new(Vec::new());

pub(super) fn get_state() -> NavState {
    NavState::from_u8(NAV_STATE.load(Ordering::Relaxed))
}

pub(super) fn set_state(state: NavState) {
    NAV_STATE.store(state as u8, Ordering::SeqCst);
}

pub(super) fn finish_with_error(e: &'static str) {
    *NAV_ERROR.lock() = Some(e);
    set_state(NavState::Error);
}

pub(super) fn cleanup_navigation() {
    *PENDING_URL.lock() = None;
    *PENDING_HOST.lock() = None;
    *PENDING_PATH.lock() = None;
    *PENDING_METHOD.lock() = None;
    *PENDING_BODY.lock() = None;
    *PENDING_CONTENT_TYPE.lock() = None;
    *RESOLVED_IP.lock() = None;
    *NAV_ERROR.lock() = None;
}

pub(super) fn cleanup_https() {
    crate::network::stack::async_ops::tcp_close();
    HTTPS_CONN_ID.store(0, Ordering::Relaxed);
    *HTTPS_TLS.lock() = None;
    HTTPS_REASSEMBLY_BUF.lock().clear();
}
