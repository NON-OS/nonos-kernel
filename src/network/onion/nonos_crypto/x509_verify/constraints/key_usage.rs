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

use super::super::super::types::{X509Certificate, KU_DIGITAL_SIGNATURE, KU_KEY_ENCIPHERMENT};
use crate::network::onion::OnionError;
use crate::sys::serial;

pub(crate) fn check_leaf_key_usage(cert: &X509Certificate) -> Result<(), OnionError> {
    if cert.extensions.key_usage == 0 {
        return Ok(());
    }
    if (cert.extensions.key_usage & (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT)) != 0 {
        return Ok(());
    }
    serial::println(b"[X509] leaf cert KU present but missing digitalSignature/keyEncipherment");
    Err(OnionError::CertificateError)
}
