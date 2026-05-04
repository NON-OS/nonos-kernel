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

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub(super) struct TlsSession {
    pub id: u32,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub master_secret: [u8; 48],
    pub cipher_suite: u16,
    pub established: bool,
}

static SESSIONS: Mutex<[Option<TlsSession>; 16]> = Mutex::new([const { None }; 16]);
static NEXT_SESSION_ID: AtomicU32 = AtomicU32::new(1);

pub(super) fn create_session() -> u32 {
    let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let mut sessions = SESSIONS.lock();
    for slot in sessions.iter_mut() {
        if slot.is_none() {
            *slot = Some(TlsSession {
                id,
                client_random: [0; 32],
                server_random: [0; 32],
                master_secret: [0; 48],
                cipher_suite: 0,
                established: false,
            });
            return id;
        }
    }
    0
}

pub(super) fn set_randoms(id: u32, client: &[u8; 32], server: &[u8; 32]) -> bool {
    let mut sessions = SESSIONS.lock();
    for slot in sessions.iter_mut() {
        if let Some(session) = slot {
            if session.id == id {
                session.client_random = *client;
                session.server_random = *server;
                return true;
            }
        }
    }
    false
}

pub(super) fn set_master_secret(id: u32, secret: &[u8; 48]) -> bool {
    let mut sessions = SESSIONS.lock();
    for slot in sessions.iter_mut() {
        if let Some(session) = slot {
            if session.id == id {
                session.master_secret = *secret;
                session.established = true;
                return true;
            }
        }
    }
    false
}

pub(super) fn destroy_session(id: u32) -> bool {
    let mut sessions = SESSIONS.lock();
    for slot in sessions.iter_mut() {
        if let Some(session) = slot {
            if session.id == id {
                *slot = None;
                return true;
            }
        }
    }
    false
}

pub(super) fn session_count() -> u8 {
    SESSIONS.lock().iter().filter(|s| s.is_some()).count() as u8
}

pub(super) fn set_cipher_suite(id: u32, suite: u16) -> bool {
    let mut sessions = SESSIONS.lock();
    for slot in sessions.iter_mut() {
        if let Some(session) = slot {
            if session.id == id {
                session.cipher_suite = suite;
                return true;
            }
        }
    }
    false
}
