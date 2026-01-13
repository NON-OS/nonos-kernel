// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groth16Error {
    Deserialize(&'static str),
    SizeLimit(&'static str),
    InvalidPublicInput,
    VerifyFailed,
}

impl fmt::Display for Groth16Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Groth16Error::Deserialize(m) => write!(f, "deserialize error: {}", m),
            Groth16Error::SizeLimit(m) => write!(f, "size exceeds limit: {}", m),
            Groth16Error::InvalidPublicInput => write!(f, "invalid public input"),
            Groth16Error::VerifyFailed => write!(f, "proof verification failed"),
        }
    }
}
