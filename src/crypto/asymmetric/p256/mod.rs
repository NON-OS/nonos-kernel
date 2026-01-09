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

mod field;
mod scalar;
mod point;
mod ecdsa;

#[cfg(test)]
mod tests;

pub use field::FieldElement;
pub use scalar::Scalar;
pub use point::{AffinePoint, ProjectivePoint};
pub use ecdsa::{
    generate_keypair, public_key_from_secret, sign, verify,
    sign_message, verify_message, P256KeyPair,
};

pub(crate) const P256_P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

pub(crate) const P256_N: [u64; 4] = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];

pub(crate) const P256_GX: [u64; 4] = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

pub(crate) const P256_GY: [u64; 4] = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

pub(crate) const P256_A: [u64; 4] = [
    0xFFFFFFFFFFFFFFFC,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

pub(crate) const P256_B: [u64; 4] = [
    0x3BCE3C3E27D2604B,
    0x651D06B0CC53B0F6,
    0xB3EBBD55769886BC,
    0x5AC635D8AA3A93E7,
];

pub type SecretKey = [u8; 32];
pub type PublicKey = [u8; 65];
pub type CompressedPublicKey = [u8; 33];
pub type Signature = [u8; 64];
