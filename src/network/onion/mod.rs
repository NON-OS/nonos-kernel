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

#![allow(clippy::result_large_err)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub mod tls;
pub mod nonos_crypto;

pub use tls::{TLSConnection, TLSState, X509Certificate};
pub use nonos_crypto::{RealCurve25519, RealDH, RealEd25519, RealRSA, RSAKeyPair};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnionError {
    NotInitialized,
    NetworkError,
    CircuitFailed,
    StreamFailed,
    Timeout,
    CryptoError,
    CertificateVerificationFailed,
    InvalidState,
    AuthenticationFailed,
    CertificateError,
    InvalidCell,
    ProtocolError,
    BufferTooSmall,
    InvalidParameter,
}

pub type CircuitId = u32;

static ONION_ROUTER: Mutex<Option<OnionRouterCompat>> = Mutex::new(None);

pub struct OnionRouterCompat;

pub fn get_onion_router() -> &'static Mutex<Option<OnionRouterCompat>> {
    &ONION_ROUTER
}

pub fn init_onion_router() -> Result<(), OnionError> {
    crate::network::nym::init_nym_client().map_err(|_| OnionError::NetworkError)?;
    *ONION_ROUTER.lock() = Some(OnionRouterCompat);
    Ok(())
}

pub fn get_anyone_network() -> Option<()> {
    if crate::network::nym::get_nym_client().is_ok() { Some(()) } else { None }
}

pub fn init_anyone_network() -> Result<(), OnionError> { init_onion_router() }

pub fn create_circuit(_target: Option<String>) -> Result<u32, OnionError> { Ok(1) }

pub fn create_stream(_cid: u32, _host: String, _port: u16) -> Result<u32, OnionError> { Ok(1) }

pub fn process_circuit_maintenance() {}

pub fn send_onion_data(_stream_id: u32, data: Vec<u8>) -> Result<(), OnionError> {
    let client = crate::network::nym::get_nym_client().map_err(|_| OnionError::NotInitialized)?;
    let mut client = client.lock();
    let dest = crate::network::nym::NymAddress::from_bytes(&[0u8; 64])
        .ok_or(OnionError::NetworkError)?;
    let mut stream = client.create_stream(dest).map_err(|_| OnionError::StreamFailed)?;
    client.send(&mut stream, &data).map_err(|_| OnionError::NetworkError)?;
    Ok(())
}

pub fn recv_onion_data(_stream_id: u32) -> Result<Vec<u8>, OnionError> { Ok(Vec::new()) }
