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
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use super::types::ServerError;
use crate::services::protocol::ServiceResponse;
use crate::services::registry::{register_endpoint, unregister_endpoint};

static PORT_COUNTER: AtomicU32 = AtomicU32::new(1000);

pub struct ServiceServer {
    pub(super) name: String,
    pub(super) port: u32,
    pub(super) caps_required: u64,
    pub(super) running: AtomicBool,
}

impl ServiceServer {
    pub fn new(name: &str, caps: u64) -> Result<Self, ServerError> {
        crate::sys::serial::println(b"[SRVR] new() enter");
        let port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        crate::sys::serial::println(b"[SRVR] got port");
        let pid = crate::process::current_pid().unwrap_or(1);
        crate::sys::serial::println(b"[SRVR] got pid");
        register_endpoint(String::from(name), port, pid, caps)
            .map_err(|_| ServerError::RegistrationFailed)?;
        crate::sys::serial::println(b"[SRVR] registered");
        let name_str = String::from(name);
        crate::sys::serial::println(b"[SRVR] name alloc");
        let server = Self { name: name_str, port, caps_required: caps, running: AtomicBool::new(false) };
        crate::sys::serial::println(b"[SRVR] returning");
        Ok(server)
    }

    pub fn port(&self) -> u32 { self.port }
    pub fn stop(&self) { self.running.store(false, Ordering::SeqCst); }

    pub fn start<F>(&self, mut handler: F) -> Result<(), ServerError>
    where F: FnMut(crate::services::protocol::ServiceRequest) -> ServiceResponse {
        self.running.store(true, Ordering::SeqCst);
        while self.running.load(Ordering::SeqCst) {
            self.poll_once(&mut handler);
            crate::sched::yield_now();
        }
        Ok(())
    }
}

impl Drop for ServiceServer {
    fn drop(&mut self) { unregister_endpoint(&self.name); }
}
