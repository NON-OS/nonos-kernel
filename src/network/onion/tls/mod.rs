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


mod aead;
mod connection;
mod crypto_provider;
mod io;
mod keys;
mod protocol;
mod transcript;
mod types;
mod verify;

pub use connection::TLSConnection;
pub use crypto_provider::{init_tls_crypto, KernelTlsCrypto, TlsCrypto, KERNEL_TLS_CRYPTO};
pub use types::{CipherSuite, TlsSessionInfo, TLSState, PublicKeyKind};
pub use verify::{
    init_tls_cert_verifier, init_tls_stack_production, get_cert_verifier,
    CertVerifier, StrictTorLinkVerifier, HttpsCertVerifier,
    X509, STRICT_TOR_LINK_VERIFIER, HTTPS_CERT_VERIFIER,
};

pub use crate::network::onion::nonos_crypto::X509Certificate;
