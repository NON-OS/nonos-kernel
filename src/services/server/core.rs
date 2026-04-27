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

use super::types::ServerError;
use crate::services::protocol::ServiceResponse;
use crate::services::registry::{register_endpoint, unregister_endpoint};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const MAX_SERVICE_NAME: usize = 32;
static PORT_COUNTER: AtomicU32 = AtomicU32::new(1000);

pub struct ServiceServer {
    pub(super) name: [u8; MAX_SERVICE_NAME],
    pub(super) name_len: usize,
    pub(super) port: u32,
    pub(super) caps_required: u64,
    pub(super) running: AtomicBool,
}

impl ServiceServer {
    pub fn new(name: &str, caps: u64) -> Result<Self, ServerError> {
        if name.len() > MAX_SERVICE_NAME {
            return Err(ServerError::RegistrationFailed);
        }
        let port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = crate::process::current_pid().unwrap_or(1);
        register_endpoint(name, port, pid, caps).map_err(|_| ServerError::RegistrationFailed)?;
        let mut name_buf = [0u8; MAX_SERVICE_NAME];
        name_buf[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            name: name_buf,
            name_len: name.len(),
            port,
            caps_required: caps,
            running: AtomicBool::new(false),
        })
    }

    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("")
    }

    pub fn port(&self) -> u32 {
        self.port
    }
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn start<F>(&self, mut handler: F) -> Result<(), ServerError>
    where
        F: FnMut(crate::services::protocol::ServiceRequest) -> ServiceResponse,
    {
        self.running.store(true, Ordering::SeqCst);
        while self.running.load(Ordering::SeqCst) {
            self.poll_once(&mut handler);
            crate::sched::yield_now();
        }
        Ok(())
    }
}

impl Drop for ServiceServer {
    fn drop(&mut self) {
        if let Ok(name) = core::str::from_utf8(&self.name[..self.name_len]) {
            let _ = unregister_endpoint(name);
        }
    }
}
