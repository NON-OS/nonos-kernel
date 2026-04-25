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

use super::cover::{start_cover_traffic, stop_cover_traffic};
use super::directory::fetch_topology;
use super::error::NymError;
use super::gateway::connect_to_gateway;
use super::stream::{create_stream, NymStream};
use super::types::{ClientId, Gateway, GatewayId, NymAddress, NymStats};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};

static NYM_CLIENT: Once<Mutex<NymClient>> = Once::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct NymClient {
    client_id: ClientId,
    gateway_id: Option<GatewayId>,
    self_address: Option<NymAddress>,
    stats: NymStats,
}

pub fn init_nym_client() -> Result<(), NymError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(NymError::AlreadyInitialized);
    }
    fetch_topology()?;
    let client = NymClient::new()?;
    NYM_CLIENT.call_once(|| Mutex::new(client));
    crate::log::info!("[NYM] Mixnet client initialized");
    Ok(())
}

pub fn get_nym_client() -> Result<&'static Mutex<NymClient>, NymError> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err(NymError::NotInitialized);
    }
    NYM_CLIENT.get().ok_or(NymError::NotInitialized)
}

impl NymClient {
    pub fn new() -> Result<Self, NymError> {
        let mut client_id_bytes = [0u8; 32];
        let _ = crate::crypto::random::fill_bytes(&mut client_id_bytes);
        Ok(Self {
            client_id: ClientId(client_id_bytes),
            gateway_id: None,
            self_address: None,
            stats: NymStats::default(),
        })
    }

    pub fn connect(&mut self, gateway: &Gateway) -> Result<(), NymError> {
        let _conn = connect_to_gateway(gateway, &self.client_id)?;
        self.gateway_id = Some(gateway.id);
        self.self_address = Some(NymAddress::new(gateway.id, self.client_id));
        if let Some(addr) = &self.self_address {
            start_cover_traffic(addr.clone());
        }
        Ok(())
    }

    pub fn disconnect(&mut self) {
        stop_cover_traffic();
        self.gateway_id = None;
        self.self_address = None;
    }

    pub fn create_stream(&mut self, destination: NymAddress) -> Result<NymStream, NymError> {
        create_stream(destination)
    }

    pub fn send(&mut self, stream: &mut NymStream, data: &[u8]) -> Result<usize, NymError> {
        let sent = stream.send(data)?;
        self.stats.record_packet_sent(sent, false);
        Ok(sent)
    }

    pub fn recv(&mut self, stream: &mut NymStream, buf: &mut [u8]) -> Result<usize, NymError> {
        let received = stream.recv(buf)?;
        self.stats.record_packet_received(received);
        Ok(received)
    }

    pub fn self_address(&self) -> Option<&NymAddress> {
        self.self_address.as_ref()
    }
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }
    pub fn stats(&self) -> &NymStats {
        &self.stats
    }
    pub fn is_connected(&self) -> bool {
        self.gateway_id.is_some()
    }

    pub fn process_pending(&mut self) {
        if let Some(addr) = &self.self_address {
            super::cover::tick_cover_traffic(addr);
        }
    }
}
