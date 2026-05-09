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
        ManifestNamespaceLen(n) => write!(f, "manifest namespace len {} not in 1..=96", n),
        ManifestTargetTripleLen(n) => write!(f, "manifest target_triple len {} not in 1..=64", n),
        ManifestOverlappingCaps => write!(f, "manifest required & optional caps overlap"),
        ManifestEndpointCount(n) => write!(f, "manifest endpoint count {} > 16", n),
        ManifestEndpointNameLen(n) => write!(f, "manifest endpoint name len {} not in 1..=48", n),
        ManifestDuplicateEndpoint(n) => write!(f, "manifest duplicate endpoint `{}`", n),
        ManifestPublisherSigCount(n) => {
            write!(f, "manifest publisher_signature_count {} not in 1..=4", n)
        }
        ManifestSigLen { alg, expected, got } => {
            write!(f, "manifest {} sig len {} != {}", alg, got, expected)
        }
        _ => return None,
    })
}
