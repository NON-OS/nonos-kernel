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

mod lengths;
mod types;
mod verify;

pub use lengths::{
    pubkey_len, sig_len, ED25519_PUBKEY_BYTES, ED25519_SIG_BYTES, MAX_PUBKEY_BYTES, MAX_SIG_BYTES,
    MLDSA44_PUBKEY_BYTES, MLDSA44_SIG_BYTES, MLDSA65_PUBKEY_BYTES, MLDSA65_SIG_BYTES,
    MLDSA87_PUBKEY_BYTES, MLDSA87_SIG_BYTES,
};
pub use types::{AlgId, AlgIdError};
pub use verify::verify;
