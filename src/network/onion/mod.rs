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

pub mod tls;
pub mod compat;
pub mod nonos_crypto;

pub use tls::{TLSConnection, TLSState};
pub use nonos_crypto::X509Certificate;
pub use compat::{CircuitId, init_onion_router, create_circuit, send_data, recv_data, process_circuit_maintenance};

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
    CertificateExpired,
    CertificateNoTrustedRoot,
    CertificateHostnameMismatch,
    CertificatePolicyFailed,
    CertificateSignatureFailed,
    UnsupportedSignatureAlgorithm,
    SystemClockNotSet,
    InvalidCell,
    ProtocolError,
    BufferTooSmall,
    InvalidParameter,
    RateLimited,
}
