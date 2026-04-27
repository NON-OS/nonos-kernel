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

use super::core::ServiceServer;
use super::parsing::{encode_response, extract_pid, parse_request};
use crate::ipc::nonos_channel::{IpcMessage, IPC_BUS};
use crate::ipc::nonos_inbox;
use crate::services::caps::verify_caller_cap;
use crate::services::protocol::{ServiceRequest, ServiceResponse};
use alloc::string::String;

const ERR_CAPABILITY: i32 = -403;

impl ServiceServer {
    pub fn poll_once<F>(&self, handler: &mut F) -> bool
    where
        F: FnMut(ServiceRequest) -> ServiceResponse,
    {
        if let Some((req, from, caller_pid)) = self.recv_request() {
            let resp = match verify_caller_cap(caller_pid, self.caps_required) {
                Ok(_) => handler(req),
                Err(_) => ServiceResponse::err(req.seq, ERR_CAPABILITY),
            };
            self.send_response(&from, resp);
            true
        } else {
            false
        }
    }

    pub(super) fn recv_request(&self) -> Option<(ServiceRequest, String, u32)> {
        let name = self.name_str();
        let msg = nonos_inbox::try_dequeue(name)?;
        let req = parse_request(&msg.data)?;
        let caller_pid = extract_pid(&msg.from);
        Some((req, msg.from, caller_pid))
    }

    pub(super) fn send_response(&self, to: &str, resp: ServiceResponse) {
        let name = self.name_str();
        let data = encode_response(&resp);
        if let Ok(msg) = IpcMessage::new(name, to, &data) {
            if let Some(ch) = IPC_BUS.find_channel(name, to) {
                let _ = ch.send(msg);
            } else {
                let _ = nonos_inbox::try_enqueue(to, msg);
            }
        }
    }
}
