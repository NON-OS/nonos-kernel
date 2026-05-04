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

use alloc::format;
use alloc::vec::Vec;
use spin::Mutex;

use super::super::error::KeyringCapsuleError;
use super::super::protocol::{decode_response, Response};
use super::super::state;
use crate::ipc::nonos_channel::IpcMessage;
use crate::ipc::nonos_inbox;

// Inbox name derived from KERNEL_REPLY_ENDPOINT (0x1_0000_0002 in
// decimal = 4294967298). Distinct from the ramfs reply inbox so
// concurrent in-flight ramfs and keyring requests cannot cross-route.
pub const REPLY_INBOX: &str = "endpoint.4294967298";
const SENDER_NAME: &str = "kernel.keyring";
const RECV_YIELDS: u32 = 50_000;

static TRANSPORT_LOCK: Mutex<()> = Mutex::new(());

pub struct ResponseBytes {
    pub status: i32,
    pub payload: Vec<u8>,
}

pub(super) fn round_trip(seq: u32, request: Vec<u8>) -> Result<ResponseBytes, KeyringCapsuleError> {
    let _guard = TRANSPORT_LOCK.lock();
    if !state::is_alive() {
        return Err(KeyringCapsuleError::Dead);
    }
    let target = format!("proc.{}", state::pid());
    let msg = IpcMessage::new(SENDER_NAME, &target, &request)
        .map_err(|_| KeyringCapsuleError::TransportFailure)?;
    nonos_inbox::try_enqueue(&target, msg).map_err(|_| KeyringCapsuleError::TransportFailure)?;
    for _ in 0..RECV_YIELDS {
        if !state::is_alive() {
            return Err(KeyringCapsuleError::Dead);
        }
        if let Some(reply) = nonos_inbox::try_dequeue(REPLY_INBOX) {
            let resp = match decode_response(&reply.data) {
                Some(r) => r,
                None => return Err(KeyringCapsuleError::ProtocolMismatch),
            };
            if resp.seq != seq {
                continue;
            }
            return Ok(extract(resp));
        }
        crate::sched::yield_now();
    }
    Err(KeyringCapsuleError::TransportFailure)
}

fn extract(resp: Response<'_>) -> ResponseBytes {
    ResponseBytes { status: resp.status, payload: resp.payload.to_vec() }
}
