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

extern crate alloc;

mod field;
mod scalar;
mod point;
mod ecdsa;

pub use field::FieldElement;
pub use scalar::Scalar;
pub use point::{AffinePoint, ProjectivePoint};
pub use ecdsa::{generate_keypair, public_key_from_secret, sign, verify, recover_public_key, eth_address};

pub type SecretKey = [u8; 32];
pub type PublicKey = [u8; 65];
pub type CompressedPublicKey = [u8; 33];
pub type Signature = [u8; 64];
pub type RecoverableSignature = [u8; 65];
