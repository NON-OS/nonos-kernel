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

use core::fmt;

use crate::error::variants::SignError;

pub(super) fn try_fmt(e: &SignError, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    use SignError::*;
    Some(match e {
        TaKeyCount(n) => write!(f, "trust-anchor key count {} not in 1..=4", n),
        TaPubkeyLen { alg, expected, got } => {
            write!(f, "trust-anchor {} pubkey len {} != {}", alg, got, expected)
        }
        TaValidFromZero => write!(f, "trust-anchor key valid_from_ms must be != 0"),
        TaValidWindow { from, until } => {
            write!(f, "trust-anchor key valid_until {} must be 0 or > valid_from {}", until, from)
        }
        TaRevokedCertSerialCount(n) => write!(f, "revoked cert serial count {} > 256", n),
        TaRevokedNonosIdCount(n) => write!(f, "revoked nonos_id count {} > 64", n),
        TaRevokedPublisherKeyIdCount(n) => write!(f, "revoked publisher_key_id count {} > 256", n),
        _ => return None,
    })
}
