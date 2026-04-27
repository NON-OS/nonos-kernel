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

use super::super::super::types::X509Certificate;
use crate::network::onion::OnionError;

pub(crate) fn check_basic_constraints_end_entity(cert: &X509Certificate) -> Result<(), OnionError> {
    if cert.extensions.basic_constraints.ca {
        return Err(OnionError::CertificateError);
    }
    Ok(())
}
