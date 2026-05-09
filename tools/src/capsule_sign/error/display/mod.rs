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

mod alg;
mod derive;
mod encode_cert;
mod encode_manifest;
mod encode_ta;
mod io;
mod keys;
mod verify;

use core::fmt;

use super::variants::SignError;

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(r) = io::try_fmt(self, f) { return r; }
        if let Some(r) = alg::try_fmt(self, f) { return r; }
        if let Some(r) = derive::try_fmt(self, f) { return r; }
        if let Some(r) = encode_ta::try_fmt(self, f) { return r; }
        if let Some(r) = encode_cert::try_fmt(self, f) { return r; }
        if let Some(r) = encode_manifest::try_fmt(self, f) { return r; }
        if let Some(r) = keys::try_fmt(self, f) { return r; }
        if let Some(r) = verify::try_fmt(self, f) { return r; }
        unreachable!("SignError variant not covered by any display category")
    }
}
