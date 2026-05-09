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
        UnknownAlgId(b) => write!(f, "unknown AlgId 0x{:02x}", b),
        UnsupportedAlg(s) => write!(f, "unsupported algorithm `{}`", s),
        SeedKeygenUnsupported(a) => write!(f, "seed-driven keygen not supported for {}", a),
        PqcleanFailed(s) => write!(f, "pqclean failed: {}", s),
        PubkeyDecode => write!(f, "pubkey decode failed"),
        InvalidSeedLength { alg, expected, actual } => {
            write!(f, "invalid {} seed length {} (expected {})", alg, actual, expected)
        }
        InvalidPubkeyLength { alg, expected, actual } => {
            write!(f, "invalid {} pubkey length {} (expected {})", alg, actual, expected)
        }
        InvalidSignatureLength { alg, expected, actual } => {
            write!(f, "invalid {} signature length {} (expected {})", alg, actual, expected)
        }
        _ => return None,
    })
}
