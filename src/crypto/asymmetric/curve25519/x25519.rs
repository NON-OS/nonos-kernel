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

use super::FieldElement;
use crate::crypto::entropy::get_entropy;
use crate::crypto::CryptoResult;

pub type X25519PrivateKey = [u8; 32];
pub type X25519PublicKey = [u8; 32];
pub type X25519SharedSecret = [u8; 32];

const X25519_BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn x25519_clamp(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

#[cfg(feature = "crypto-curve25519")]
pub fn x25519_keypair() -> CryptoResult<(X25519PublicKey, X25519PrivateKey)> {
    let entropy = get_entropy(32);
    let mut private = [0u8; 32];
    private.copy_from_slice(&entropy);
    let secret = x25519_dalek::StaticSecret::from(private);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((public.to_bytes(), private))
}

#[cfg(not(feature = "crypto-curve25519"))]
pub fn x25519_keypair() -> CryptoResult<(X25519PublicKey, X25519PrivateKey)> {
    let entropy = get_entropy(32);
    let mut private = [0u8; 32];
    private.copy_from_slice(&entropy);
    x25519_clamp(&mut private);
    let public = x25519_base(&private);
    Ok((public, private))
}

#[cfg(feature = "crypto-curve25519")]
pub fn x25519_base(scalar: &X25519PrivateKey) -> X25519PublicKey {
    let secret = x25519_dalek::StaticSecret::from(*scalar);
    let public = x25519_dalek::PublicKey::from(&secret);
    public.to_bytes()
}

#[cfg(not(feature = "crypto-curve25519"))]
pub fn x25519_base(scalar: &X25519PrivateKey) -> X25519PublicKey {
    x25519(scalar, &X25519_BASEPOINT)
}

#[cfg(feature = "crypto-curve25519")]
pub fn x25519(scalar: &X25519PrivateKey, point: &X25519PublicKey) -> X25519SharedSecret {
    let secret = x25519_dalek::StaticSecret::from(*scalar);
    let public = x25519_dalek::PublicKey::from(*point);
    secret.diffie_hellman(&public).to_bytes()
}

#[cfg(not(feature = "crypto-curve25519"))]
pub fn x25519(scalar: &X25519PrivateKey, point: &X25519PublicKey) -> X25519SharedSecret {
    let mut k = *scalar;
    x25519_clamp(&mut k);
    let u = FieldElement::from_bytes(point);
    let x_1 = u;
    let mut x_2 = FieldElement::one();
    let mut z_2 = FieldElement::zero();
    let mut x_3 = u;
    let mut z_3 = FieldElement::one();
    let mut swap: u8 = 0;
    for i in (0..255).rev() {
        let bit = ((k[i / 8] >> (i % 8)) & 1) as u8;
        swap ^= bit;
        FieldElement::conditional_swap(swap, &mut x_2, &mut x_3);
        FieldElement::conditional_swap(swap, &mut z_2, &mut z_3);
        swap = bit;
        let a = x_2.add(&z_2);
        let aa = a.square();
        let b = x_2.sub(&z_2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x_3.add(&z_3);
        let d = x_3.sub(&z_3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x_3 = da.add(&cb).square();
        z_3 = x_1.mul(&da.sub(&cb).square());
        x_2 = aa.mul(&bb);
        z_2 = e.mul(&aa.add(&e.mul121666()));
    }
    FieldElement::conditional_swap(swap, &mut x_2, &mut x_3);
    FieldElement::conditional_swap(swap, &mut z_2, &mut z_3);
    x_2.mul(&z_2.invert()).to_bytes()
}

pub fn compute_shared_secret(
    private: &X25519PrivateKey,
    public: &X25519PublicKey,
) -> X25519SharedSecret {
    x25519(private, public)
}

pub fn derive_public_key(private: &X25519PrivateKey) -> X25519PublicKey {
    x25519_base(private)
}
