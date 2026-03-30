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
use spin::Mutex;

pub const MAX_SERVICES: usize = 64;

#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    pub name: String,
    pub port: u32,
    pub pid: u32,
    pub caps_required: u64,
}

static ENDPOINTS: Mutex<Vec<ServiceEndpoint>> = Mutex::new(Vec::new());

pub fn register_endpoint(name: String, port: u32, pid: u32, caps: u64) -> Result<(), RegError> {
    crate::sys::serial::println(b"[REG] lock");
    let mut eps = ENDPOINTS.lock();
    crate::sys::serial::println(b"[REG] got lock");
    if eps.len() >= MAX_SERVICES {
        return Err(RegError::Full);
    }
    if eps.iter().any(|e| e.name == name) {
        return Err(RegError::Exists);
    }
    eps.push(ServiceEndpoint { name, port, pid, caps_required: caps });
    crate::sys::serial::println(b"[REG] pushed");
    Ok(())
}

pub fn lookup_service(name: &str) -> Option<ServiceEndpoint> {
    let eps = ENDPOINTS.lock();
    eps.iter().find(|e| e.name == name).cloned()
}

pub fn unregister_endpoint(name: &str) -> bool {
    let mut eps = ENDPOINTS.lock();
    if let Some(idx) = eps.iter().position(|e| e.name == name) {
        eps.remove(idx);
        true
    } else {
        false
    }
}

pub fn list_endpoints() -> Vec<ServiceEndpoint> {
    ENDPOINTS.lock().clone()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegError {
    Full,
    Exists,
    NotFound,
}
