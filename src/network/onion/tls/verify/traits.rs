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

use crate::network::onion::OnionError;
use alloc::vec::Vec;
use spin::Once;

pub trait CertVerifier: Sync + Send {
    fn verify(&self, chain_der: &[Vec<u8>], sni: &str) -> Result<(), OnionError>;
}

static CERT_VERIFIER: Once<&'static dyn CertVerifier> = Once::new();

pub fn init_tls_cert_verifier(v: &'static dyn CertVerifier) {
    CERT_VERIFIER.call_once(|| v);
}

pub fn get_cert_verifier() -> Option<&'static dyn CertVerifier> {
    CERT_VERIFIER.get().copied()
}
