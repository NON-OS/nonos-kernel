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

use super::connect::ServiceClient;
use super::types::ClientError;
use crate::ipc::nonos_channel::{IpcMessage, IPC_BUS};
use crate::ipc::nonos_inbox;
use crate::services::protocol::ServiceResponse;

const SPIN_ITERATIONS: usize = 100;

pub(crate) fn send_request(client: &ServiceClient, data: &[u8]) -> Result<(), ClientError> {
    let msg = IpcMessage::new(&client.client_id, &client.name, data)
        .map_err(|_| ClientError::SendFailed)?;
    if let Some(ch) = IPC_BUS.find_channel(&client.client_id, &client.name) {
        ch.send(msg).map_err(|_| ClientError::SendFailed)
    } else {
        nonos_inbox::try_enqueue(&client.name, msg).map_err(|_| ClientError::SendFailed)
    }
}

pub(crate) fn wait_response(
    client: &ServiceClient,
    seq: u32,
    timeout_ms: u64,
) -> Result<ServiceResponse, ClientError> {
    let start = crate::time::timestamp_millis();
    loop {
        if let Some(msg) = nonos_inbox::try_dequeue(&client.client_id) {
            if let Some(resp) = parse_response(&msg.data, seq) {
                return Ok(resp);
            }
            let _ = nonos_inbox::try_enqueue(&client.client_id, msg);
        }
        let elapsed = crate::time::timestamp_millis().saturating_sub(start);
        if elapsed >= timeout_ms {
            return Err(ClientError::Timeout);
        }
        for _ in 0..SPIN_ITERATIONS {
            core::hint::spin_loop();
        }
    }
}

fn parse_response(data: &[u8], expected_seq: u32) -> Option<ServiceResponse> {
    if data.len() < 8 {
        return None;
    }
    let seq = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if seq != expected_seq {
        return None;
    }
    let status = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    Some(ServiceResponse { seq, status, payload: data.get(8..).unwrap_or(&[]).to_vec() })
}
