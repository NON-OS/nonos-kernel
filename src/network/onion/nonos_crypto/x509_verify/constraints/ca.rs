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

use super::super::super::types::{X509Certificate, KU_KEY_CERT_SIGN};
use crate::network::onion::OnionError;
use crate::sys::serial;

pub(crate) fn check_ca_constraints(
    cert: &X509Certificate,
    cert_index: usize,
) -> Result<(), OnionError> {
    if !cert.extensions.basic_constraints.ca {
        serial::print(b"[X509] cert ");
        serial::print_dec(cert_index as u64);
        serial::println(b" is intermediate but BasicConstraints.ca=false");
        return Err(OnionError::CertificateError);
    }
    if cert.extensions.key_usage != 0 && (cert.extensions.key_usage & KU_KEY_CERT_SIGN) == 0 {
        serial::print(b"[X509] cert ");
        serial::print_dec(cert_index as u64);
        serial::println(b" is CA but missing keyCertSign in KeyUsage");
        return Err(OnionError::CertificateError);
    }
    Ok(())
}
