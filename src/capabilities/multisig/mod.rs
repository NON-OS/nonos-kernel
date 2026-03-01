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

mod constants;
mod create;
mod error;
mod material;
mod sign;
mod token;
mod verify;

pub use constants::{max_signers, max_threshold, MAX_SIGNERS, MAX_THRESHOLD, SIGNATURE_SIZE};
pub use create::{create_multisig_token, create_multisig_token_with_nonce};
pub use error::MultiSigError;
pub use material::{compute_signature, signature_material};
pub use sign::{add_signature, clear_signatures, remove_signature};
pub use token::MultiSigToken;
pub use verify::{count_valid_signatures, verify_multisig, verify_multisig_strict};
