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

use crate::network::onion::tls::TLSConnection;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ImgFetchState {
    Idle = 0,
    DnsResolve = 1,
    Connecting = 2,
    TlsHandshake = 3,
    Sending = 4,
    Receiving = 5,
    Decoding = 6,
}

impl ImgFetchState {
    pub(super) fn from_u8(v: u8) -> Self {
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

pub(super) static IMG_STATE: AtomicU8 = AtomicU8::new(0);
pub(super) static IMG_DEADLINE: AtomicU64 = AtomicU64::new(0);
pub(super) static IMG_CONN_ID: AtomicU32 = AtomicU32::new(0);
pub(super) static IMG_TLS: Mutex<Option<TLSConnection>> = Mutex::new(None);
pub(super) static IMG_REASSEMBLY: Mutex<Vec<u8>> = Mutex::new(Vec::new());
pub(super) static IMG_RESPONSE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
pub(super) static IMG_HOST: Mutex<Option<String>> = Mutex::new(None);
pub(super) static IMG_PATH: Mutex<Option<String>> = Mutex::new(None);
pub(super) static IMG_PORT: Mutex<u16> = Mutex::new(443);
pub(super) static IMG_IP: Mutex<Option<[u8; 4]>> = Mutex::new(None);
pub(super) static IMG_IS_HTTPS: AtomicBool = AtomicBool::new(true);
pub(super) static IMG_TARGETS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
pub(super) static IMG_FAIL_COUNT: AtomicU32 = AtomicU32::new(0);
pub(super) static IMG_NAV_HOST: Mutex<Option<String>> = Mutex::new(None);
pub(super) static IMG_NAV_IP: Mutex<Option<[u8; 4]>> = Mutex::new(None);

pub(super) const MAX_IMG_FAILURES: u32 = 3;
pub(super) const IMG_TIMEOUT_MS: u64 = 10_000;
pub(super) const MAX_IMG_RESPONSE: usize = 2 * 1024 * 1024;

pub(super) fn get_img_state() -> ImgFetchState {
    ImgFetchState::from_u8(IMG_STATE.load(Ordering::Relaxed))
}
pub(super) fn set_img_state(state: ImgFetchState) {
    IMG_STATE.store(state as u8, Ordering::SeqCst);
}
pub(super) fn is_timed_out() -> bool {
    let deadline = IMG_DEADLINE.load(Ordering::Relaxed);
    deadline > 0 && crate::time::timestamp_millis() > deadline
}
