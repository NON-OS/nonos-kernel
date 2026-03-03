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


use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::network::onion::circuit::CircuitId;
use crate::network::onion::stream::StreamId;
use crate::network::onion::security;

use super::core::OnionRouter;
use super::error::OnionError;

static ONION_ROUTER: Mutex<Option<OnionRouter>> = Mutex::new(None);

pub fn init_onion_router() -> Result<(), OnionError> {
    let mut router = OnionRouter::new();
    router.init()?;
    *ONION_ROUTER.lock() = Some(router);
    Ok(())
}

pub fn get_onion_router() -> &'static Mutex<Option<OnionRouter>> {
    &ONION_ROUTER
}

pub fn create_circuit(exit_policy: Option<String>) -> Result<CircuitId, OnionError> {
    if !crate::sys::settings::anyone_enabled() {
        return Err(OnionError::Disabled);
    }

    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.create_circuit(exit_policy)
}

pub fn create_stream(circuit_id: CircuitId, target: String, port: u16) -> Result<StreamId, OnionError> {
    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.create_stream(circuit_id, target, port)
}

pub fn send_onion_data(stream_id: StreamId, data: Vec<u8>) -> Result<(), OnionError> {
    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.send_data(stream_id, data)
}

pub fn recv_onion_data(stream_id: StreamId) -> Result<Vec<u8>, OnionError> {
    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.recv_data(stream_id)
}

pub fn process_circuit_maintenance() {
    if let Some(mut router) = ONION_ROUTER.try_lock() {
        if let Some(router) = router.as_mut() {
            router.circuit_manager.cleanup_expired_circuits(30000);
            if security::check_client_security([127, 0, 0, 1], 0).is_err() {
                crate::log_warn!("Circuit maintenance: security violation detected");
            }
        }
    }
}
