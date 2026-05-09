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
        CertNamespaceGlobCount(n) => write!(f, "cert namespace_glob_count {} not in 1..=8", n),
        CertNamespaceGlobLen(n) => write!(f, "cert namespace_glob len {} not in 1..=96", n),
        CertMetadataLen(n) => write!(f, "cert metadata len {} > 256", n),
        CertValidWindow { from, until } => {
            write!(f, "cert valid window invalid: from={} until={}", from, until)
        }
        CertPublisherKeyCount(n) => write!(f, "cert publisher_key_count {} not in 1..=4", n),
        CertPubkeyLen { alg, expected, got } => {
            write!(f, "cert {} pubkey len {} != {}", alg, got, expected)
        }
        CertKeysPerAlg(a) => write!(f, "cert too many keys for {} (>2)", a),
        CertTrustAnchorSigCount(n) => {
            write!(f, "cert trust_anchor_signature_count {} not in 1..=4", n)
        }
        CertSigLen { alg, expected, got } => {
            write!(f, "cert {} sig len {} != {}", alg, got, expected)
        }
        _ => return None,
    })
}
