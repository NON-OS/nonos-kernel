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

//! Production Groth16 zk-SNARK Implementation for NONOS
//!
//! Real implementation of Groth16 proving system with:
//! - Proper BN254 elliptic curve arithmetic
//! - Optimized field operations using Montgomery form
//! - Efficient pairing computation
//! - Constant-time operations for security
//! - Production-grade random number generation

mod field;
mod g1;
mod g2;
mod gt;
mod pairing;
mod prover;
mod keys;
mod proof;

pub use field::*;
pub use g1::*;
pub use g2::*;
pub use gt::*;
pub use pairing::*;
pub use prover::*;
pub use keys::*;
pub use proof::*;
