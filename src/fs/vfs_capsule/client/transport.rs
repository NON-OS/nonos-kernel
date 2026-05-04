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

use super::super::error::VfsCapsuleError;
use super::super::protocol::{decode_response, DecodedResponse};
use super::super::state;
use crate::ipc::nonos_channel::IpcMessage;
use crate::ipc::nonos_inbox;

// 0x1_0000_0005 = 4294967301. Distinct from ramfs/keyring/entropy/
// crypto reply inboxes.
pub const REPLY_INBOX: &str = "endpoint.4294967301";
const SENDER_NAME: &str = "kernel.vfs";
const RECV_YIELDS: u32 = 50_000;

static TRANSPORT_LOCK: Mutex<()> = Mutex::new(());

pub(super) struct ResponseBytes {
    pub status: i32,
    pub body: Vec<u8>,
}

pub(super) fn round_trip(
    request_id: u32,
    request: Vec<u8>,
) -> Result<ResponseBytes, VfsCapsuleError> {
    let _guard = TRANSPORT_LOCK.lock();
    let gen_at_send = state::generation();
    if !state::is_alive() {
        return Err(VfsCapsuleError::Dead);
    }
    let target = format!("proc.{}", state::pid());
    let msg = IpcMessage::new(SENDER_NAME, &target, &request)
        .map_err(|_| VfsCapsuleError::TransportFailure)?;
    nonos_inbox::try_enqueue(&target, msg).map_err(|_| VfsCapsuleError::TransportFailure)?;
    for _ in 0..RECV_YIELDS {
        if !state::is_alive() {
            return Err(VfsCapsuleError::Dead);
        }
        if state::generation() != gen_at_send {
            return Err(VfsCapsuleError::Stale);
        }
        if let Some(reply) = nonos_inbox::try_dequeue(REPLY_INBOX) {
            if state::generation() != gen_at_send {
                return Err(VfsCapsuleError::Stale);
            }
            let resp = match decode_response(&reply.data) {
                Some(r) => r,
                None => return Err(VfsCapsuleError::ProtocolMismatch),
            };
            if resp.request_id != request_id {
                continue;
            }
            return Ok(extract(resp));
        }
        crate::sched::yield_now();
    }
    Err(VfsCapsuleError::TransportFailure)
}

fn extract(resp: DecodedResponse<'_>) -> ResponseBytes {
    ResponseBytes { status: resp.status, body: resp.body.to_vec() }
}
