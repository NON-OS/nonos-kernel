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

use super::traits::CertVerifier;
use super::x509_wrap::X509;
use crate::network::onion::OnionError;
use alloc::vec::Vec;

pub struct StrictTorLinkVerifier;
pub static STRICT_TOR_LINK_VERIFIER: StrictTorLinkVerifier = StrictTorLinkVerifier;

impl CertVerifier for StrictTorLinkVerifier {
    fn verify(&self, chain_der: &[Vec<u8>], _sni: &str) -> Result<(), OnionError> {
        if chain_der.len() != 1 {
            return Err(OnionError::AuthenticationFailed);
        }
        let cert = X509::parse_der(&chain_der[0])?;
        X509::verify_self_signed(&cert)?;
        X509::check_basic_constraints_end_entity(&cert)?;
        let now_ms = crate::time::unix_timestamp() * 1000;
        X509::check_time_validity(&cert, now_ms)?;
        Ok(())
    }
}
