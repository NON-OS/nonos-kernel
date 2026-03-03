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

pub mod cell;
pub mod circuit;
pub mod crypto;
pub mod directory;
pub mod nonos_crypto;
pub mod real_network;
pub mod relay;
pub mod router;
pub mod security;
pub mod stream;
pub mod tls;

pub use cell::{Cell, CellProcessor, CellType, RelayCommand};
pub use circuit::{Circuit, CircuitId, CircuitManager, CircuitState};
pub use crypto::{HopCrypto, LayerKeys, OnionCrypto};
pub use directory::{DirectoryService, RelayDescriptor, RouterStatus};
pub use nonos_crypto::{RealCurve25519, RealDH, RealEd25519, RealRSA, RSAKeyPair};
pub use real_network::{get_anyone_network, init_anyone_network, AnyoneNetworkManager};
pub use relay::{OnionRelay, RelayConfig, RelayManager};
pub use security::{check_client_security, init_security};
pub use stream::{OnionStream, StreamId, StreamManager};
pub use tls::{TLSConnection, TLSState, X509Certificate};

pub use router::{
    create_circuit, create_stream, get_onion_router, init_onion_router, process_circuit_maintenance,
    recv_onion_data, send_onion_data, KeyManager, OnionError, OnionRouter, RelayStats, RouteOptimizer,
};
