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
use crate::sys::serial;

pub(crate) fn check_path_len_constraints(chain: &[X509Certificate]) -> Result<(), OnionError> {
    for i in 1..chain.len() {
        if let Some(max_path) = chain[i].extensions.basic_constraints.path_len_constraint {
            let ca_certs_below = (i - 1) as u8;
            if ca_certs_below > max_path {
                serial::print(b"[X509] pathLenConstraint violated at cert ");
                serial::print_dec(i as u64);
                serial::print(b": ");
                serial::print_dec(ca_certs_below as u64);
                serial::print(b" CAs below, max ");
                serial::print_dec(max_path as u64);
                serial::println(b"");
                return Err(OnionError::CertificateError);
            }
        }
    }
    Ok(())
}
