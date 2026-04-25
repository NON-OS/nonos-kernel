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

fn caller_can_register() -> bool {
    match crate::process::current_pid() {
        None => true,
        Some(pid) if pid <= 64 => true,
        Some(_) => {
            let token = crate::syscall::capabilities::current_caps_or_default();
            token.can_register_service() || token.is_admin()
        }
    }
}

pub fn register_endpoint(name: &str, port: u32, pid: u32, caps: u64) -> Result<(), RegError> {
    if !caller_can_register() {
        return Err(RegError::PermissionDenied);
    }
    let mut eps = ENDPOINTS.lock();
    if eps.len() >= MAX_SERVICES {
        return Err(RegError::Full);
    }
    if eps.iter().any(|e| e.name == name) {
        return Err(RegError::Exists);
    }
    eps.push(ServiceEndpoint { name: String::from(name), port, pid, caps_required: caps });
    Ok(())
}

pub fn register_endpoint_simple(name: &'static str, port: u32, pid: u32) {
    if !caller_can_register() {
        return;
    }
    let mut eps = ENDPOINTS.lock();
    if eps.len() < MAX_SERVICES && !eps.iter().any(|e| e.name == name) {
        eps.push(ServiceEndpoint { name: String::from(name), port, pid, caps_required: 0 });
    }
}

pub fn lookup_service(name: &str) -> Option<ServiceEndpoint> {
    ENDPOINTS.lock().iter().find(|e| e.name == name).cloned()
}

pub fn unregister_endpoint(name: &str) -> Result<(), RegError> {
    let caller_pid = crate::process::current_pid();
    let mut eps = ENDPOINTS.lock();
    if let Some(idx) = eps.iter().position(|e| e.name == name) {
        let is_kernel = caller_pid.is_none();
        let is_owner = caller_pid == Some(eps[idx].pid);
        let is_admin = crate::syscall::capabilities::current_caps_or_default().is_admin();
        if !is_kernel && !is_owner && !is_admin {
            return Err(RegError::PermissionDenied);
        }
        eps.remove(idx);
        Ok(())
    } else {
        Err(RegError::NotFound)
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
    PermissionDenied,
}
