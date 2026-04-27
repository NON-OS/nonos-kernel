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

use super::super::types::X509Certificate;
use super::super::x509_time::check_time_validity;
use super::super::x509_verify::{
    check_basic_constraints_end_entity, verify_chain, verify_self_signed, verify_signature,
};
use super::x509::X509;
use crate::network::onion::OnionError;

impl X509 {
    pub fn verify_self_signed(cert: &X509Certificate) -> Result<(), OnionError> {
        verify_self_signed(cert)
    }

    pub fn verify_signature(
        cert: &X509Certificate,
        issuer: &X509Certificate,
    ) -> Result<(), OnionError> {
        verify_signature(cert, issuer)
    }

    pub fn verify_chain(chain: &[X509Certificate], now_ms: u64) -> Result<(), OnionError> {
        verify_chain(chain, now_ms)
    }

    pub fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
        check_basic_constraints_end_entity(cert)
    }

    pub fn check_time_validity(cert: &X509Certificate, now_ms: u64) -> Result<(), OnionError> {
        check_time_validity(cert, now_ms)
    }
}
