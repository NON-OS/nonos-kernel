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

#![cfg(feature = "zk-groth16")]

pub mod deserialize;
pub mod error;
pub mod params;
mod verifier;

#[cfg(test)]
mod tests;

pub const MAX_VK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 1 * 1024 * 1024;
pub const MAX_PUBLIC_INPUTS: usize = 262_000;

pub use error::Groth16Error;
pub use verifier::{groth16_verify_bn254, Groth16Verifier};
