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

use super::types::ClientError;
use crate::ipc::nonos_inbox;
use crate::services::protocol::{ServiceOp, ServiceRequest, ServiceResponse};
use crate::services::registry::lookup_service;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

static SEQ_COUNTER: AtomicU32 = AtomicU32::new(1);

pub struct ServiceClient {
    pub(super) name: String,
    pub(super) client_id: String,
}

impl ServiceClient {
    pub fn connect(name: &str) -> Result<Self, ClientError> {
        let ep = lookup_service(name).ok_or(ClientError::NotFound)?;
        let pid = crate::process::current_pid().unwrap_or(0);
        if !crate::syscall::microkernel::capability::check_caps_internal(pid, ep.caps_required) {
            return Err(ClientError::CapabilityDenied);
        }
        let client_id =
            alloc::format!("client.{}.{}", pid, SEQ_COUNTER.fetch_add(1, Ordering::Relaxed));
        nonos_inbox::register_inbox(&client_id);
        Ok(Self { name: String::from(name), client_id })
    }

    pub fn call(&self, op: ServiceOp, payload: Vec<u8>) -> Result<ServiceResponse, ClientError> {
        let seq = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed);
        let req = ServiceRequest::new(seq, op, payload);
        super::transport::send_request(self, &req.encode())?;
        super::transport::wait_response(self, seq, 5000)
    }

    pub fn ping(&self) -> Result<(), ClientError> {
        let resp = self.call(ServiceOp::Ping, Vec::new())?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(ClientError::RemoteError(resp.status))
        }
    }
}
