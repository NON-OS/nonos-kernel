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

use alloc::vec::Vec;
use crate::crypto::asymmetric::p256::{FieldElement, Scalar, AffinePoint, ProjectivePoint};
use super::super::super::error::WifiError;
use super::super::crypto::hmac_sha256;

pub(crate) fn sae_derive_pwe(password: &[u8], aa: &[u8; 6], spa: &[u8; 6]) -> Result<ProjectivePoint, WifiError> {
    let (id1, id2) = if spa < aa {
        (spa.as_slice(), aa.as_slice())
    } else {
        (aa.as_slice(), spa.as_slice())
    };

    for counter in 1u8..=255 {
        let seed = sae_pwd_seed(password, id1, id2, counter);
        let value = sae_pwd_value(&seed);

        if let Some(point) = sae_try_point(&value) {
            return Ok(point.to_projective());
        }
    }

    Err(WifiError::AuthenticationFailed)
}

pub(crate) fn sae_pwd_seed(password: &[u8], id1: &[u8], id2: &[u8], counter: u8) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + 12 + 1);
    input.extend_from_slice(id1);
    input.extend_from_slice(id2);
    input.extend_from_slice(password);
    input.push(counter);

    hmac_sha256(b"SAE Hunting and Pecking", &input)
}

pub(crate) fn sae_pwd_value(seed: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(seed, b"SAE pwd-value")
}

pub(crate) fn sae_try_point(value: &[u8; 32]) -> Option<AffinePoint> {
    let x = FieldElement::from_bytes(value)?;

    let x2 = x.square();
    let x3 = x2.mul(&x);

    let ax = x.mul(&FieldElement([
        0xFFFFFFFFFFFFFFFC,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ]));

    let b = FieldElement([
        0x3BCE3C3E27D2604B,
        0x651D06B0CC53B0F6,
        0xB3EBBD55769886BC,
        0x5AC635D8AA3A93E7,
    ]);

    let y_squared = x3.add(&ax).add(&b);

    let y = y_squared.sqrt()?;

    let y = if y.is_even() { y } else { y.negate() };

    Some(AffinePoint {
        x,
        y,
        infinity: false,
    })
}

pub(crate) fn sae_generate_random_scalar() -> Result<Scalar, WifiError> {
    let mut bytes = [0u8; 32];
    crate::crypto::fill_random_bytes(&mut bytes);

    let mut scalar = Scalar::from_bytes_reduce(&bytes);

    if scalar.0[0] < 2 && scalar.0[1] == 0 && scalar.0[2] == 0 && scalar.0[3] == 0 {
        scalar = scalar.add(&Scalar([2, 0, 0, 0]));
    }

    Ok(scalar)
}

pub fn sae_derive_pwd_seed(password: &[u8], aa: &[u8; 6], spa: &[u8; 6]) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + 12);
    if spa < aa {
        input.extend_from_slice(spa);
        input.extend_from_slice(aa);
    } else {
        input.extend_from_slice(aa);
        input.extend_from_slice(spa);
    }
    input.extend_from_slice(password);

    hmac_sha256(b"SAE pwd-seed", &input)
}
