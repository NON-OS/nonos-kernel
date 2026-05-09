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

use super::types::ServiceCap;
use crate::process::caps;
use crate::services::registry::lookup_service;

pub fn check_service_cap(svc_name: &str, caller_cap: &ServiceCap) -> Result<(), CapError> {
    let ep = lookup_service(svc_name).ok_or(CapError::ServiceNotFound)?;

    if !caller_cap.has(ep.caps_required) {
        return Err(CapError::InsufficientCaps);
    }

    let now = crate::time::timestamp_millis();
    if caller_cap.is_expired(now) {
        return Err(CapError::Expired);
    }

    Ok(())
}

pub fn verify_caller_cap(caller_pid: u32, required: u64) -> Result<ServiceCap, CapError> {
    if !caps::has(caller_pid, required) {
        return Err(CapError::InsufficientCaps);
    }
    Ok(ServiceCap::new(required, caller_pid))
}

pub fn has_capability(pid: u32, required: u64) -> bool {
    caps::has(pid, required)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    NoCap,
    InsufficientCaps,
    Expired,
    ServiceNotFound,
}
