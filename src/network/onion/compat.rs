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

use super::OnionError;

pub type CircuitId = u32;

pub fn init_onion_router() -> Result<(), OnionError> {
    crate::network::nym::init_nym_client().map_err(|_| OnionError::NetworkError)
}

pub fn create_circuit() -> Result<CircuitId, OnionError> {
    if crate::network::nym::get_nym_client().is_ok() {
        Ok(1)
    } else {
        Err(OnionError::NotInitialized)
    }
}

pub fn send_data(data: &[u8]) -> Result<usize, OnionError> {
    let client = crate::network::nym::get_nym_client().map_err(|_| OnionError::NotInitialized)?;
    let mut client = client.lock();
    let dest =
        crate::network::nym::NymAddress::from_bytes(&[0u8; 64]).ok_or(OnionError::NetworkError)?;
    let mut stream = client.create_stream(dest).map_err(|_| OnionError::StreamFailed)?;
    client.send(&mut stream, data).map_err(|_| OnionError::NetworkError)
}

pub fn recv_data(buf: &mut [u8]) -> Result<usize, OnionError> {
    let client = crate::network::nym::get_nym_client().map_err(|_| OnionError::NotInitialized)?;
    let mut client = client.lock();
    let dest =
        crate::network::nym::NymAddress::from_bytes(&[0u8; 64]).ok_or(OnionError::NetworkError)?;
    let mut stream = client.create_stream(dest).map_err(|_| OnionError::StreamFailed)?;
    client.recv(&mut stream, buf).map_err(|_| OnionError::NetworkError)
}

pub fn process_circuit_maintenance() {
    if let Ok(client) = crate::network::nym::get_nym_client() {
        let mut client = client.lock();
        client.process_pending();
    }
}
