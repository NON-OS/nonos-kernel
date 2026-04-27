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

use super::flow::FlowControl;
use super::state::StreamState;
use crate::network::nym::error::NymError;
use crate::network::nym::gateway::{get_gateway_pool, recv_message, send_message, GatewayMessage};
use crate::network::nym::route::build_route;
use crate::network::nym::sphinx::build_packet;
use crate::network::nym::types::{NymAddress, NymRoute, NYM_FRAGMENT_SIZE};

pub struct NymStream {
    pub id: u32,
    pub destination: NymAddress,
    pub state: StreamState,
    pub route: NymRoute,
    pub flow: FlowControl,
    seq_send: u64,
    seq_recv: u64,
}

pub fn create_stream(destination: NymAddress) -> Result<NymStream, NymError> {
    let mut manager = super::manager::get_stream_manager().lock();
    let id = manager.create_stream(destination.clone())?;
    manager.get_stream(id).cloned().ok_or(NymError::InternalError)
}

impl NymStream {
    pub fn new(id: u32, destination: NymAddress) -> Result<Self, NymError> {
        let route = build_route(&destination)?;
        Ok(Self {
            id,
            destination,
            state: StreamState::Open,
            route,
            flow: FlowControl::new(),
            seq_send: 0,
            seq_recv: 0,
        })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize, NymError> {
        if self.state != StreamState::Open {
            return Err(NymError::StreamClosed);
        }
        let client_id = crate::network::nym::get_nym_client()?.lock().client_id().clone();
        let mut pool = get_gateway_pool().lock();
        let conn = pool.get_or_connect(&self.route.gateway, &client_id)?;
        let mut total_sent = 0;
        for chunk in data.chunks(NYM_FRAGMENT_SIZE) {
            if !self.flow.can_send() {
                return Ok(total_sent);
            }
            let packet = build_packet(&self.route.mixnodes, &self.destination, chunk)?;
            let msg = GatewayMessage::SphinxPacket(packet.to_bytes());
            send_message(conn, &msg)?;
            self.flow.on_packet_sent();
            self.seq_send = self.seq_send.wrapping_add(1);
            total_sent += chunk.len();
        }
        Ok(total_sent)
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NymError> {
        if self.state != StreamState::Open {
            return Err(NymError::StreamClosed);
        }
        let client_id = crate::network::nym::get_nym_client()?.lock().client_id().clone();
        let mut pool = get_gateway_pool().lock();
        let conn = pool.get_or_connect(&self.route.gateway, &client_id)?;
        match recv_message(conn) {
            Ok(GatewayMessage::SphinxPacket(data)) => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                self.flow.on_packet_received();
                self.seq_recv = self.seq_recv.wrapping_add(1);
                Ok(len)
            }
            Ok(_) => Ok(0),
            Err(e) => Err(e),
        }
    }

    pub fn close(&mut self) {
        self.state = StreamState::Closed;
    }
    pub fn is_open(&self) -> bool {
        self.state == StreamState::Open
    }
}

impl Clone for NymStream {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            destination: self.destination.clone(),
            state: self.state,
            route: self.route.clone(),
            flow: FlowControl::new(),
            seq_send: 0,
            seq_recv: 0,
        }
    }
}
