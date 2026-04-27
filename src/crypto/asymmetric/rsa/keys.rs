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

use crate::crypto::entropy::get_entropy;
use crate::crypto::util::bigint::{BigUint, LIMB_BITS};
use crate::crypto::CryptoError;

use super::{RSA_2048, RSA_4096};

#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
    pub bits: usize,
}

#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub dp: BigUint,
    pub dq: BigUint,
    pub qinv: BigUint,
    pub bits: usize,
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        // Note: BigUint from util::bigint already implements secure zeroization
        // in its Drop impl using volatile writes. No additional zeroization needed.
    }
}

pub fn generate_keypair() -> Result<(RsaPublicKey, RsaPrivateKey), CryptoError> {
    generate_keypair_with_bits(RSA_2048)
}

pub fn generate_keypair_with_bits(bits: usize) -> Result<(RsaPublicKey, RsaPrivateKey), CryptoError> {
    if bits < 1024 || bits % 8 != 0 {
        return Err(CryptoError::InvalidLength);
    }

    let prime_bits = bits / 2;

    let p = generate_prime(prime_bits)?;
    let q = generate_prime(prime_bits)?;

    // Ensure p != q
    if p == q {
        return generate_keypair_with_bits(bits);
    }

    let n = &p * &q;

    let one = BigUint::one();
    let p_minus_1 = &p - &one;
    let q_minus_1 = &q - &one;
    let phi_n = &p_minus_1 * &q_minus_1;

    let e = BigUint::from_u64(65537);

    let d = e.mod_inverse(&phi_n).ok_or(CryptoError::SigError)?;

    let dp = &d % &p_minus_1;
    let dq = &d % &q_minus_1;
    let qinv = q.mod_inverse(&p).ok_or(CryptoError::SigError)?;

    let public_key = RsaPublicKey {
        n: n.clone(),
        e: e.clone(),
        bits,
    };

    let private_key = RsaPrivateKey {
        n,
        e,
        d,
        p,
        q,
        dp,
        dq,
        qinv,
        bits,
    };

    Ok((public_key, private_key))
}

fn generate_prime(bits: usize) -> Result<BigUint, CryptoError> {
    if bits < 16 {
        return Err(CryptoError::InvalidLength);
    }

    let bytes = (bits + 7) / 8;

    for _ in 0..1000 {
        let mut candidate_bytes = get_entropy(bytes);

        // Set MSB to ensure correct bit length
        candidate_bytes[0] |= 0x80;
        // Set LSB to ensure odd number
        candidate_bytes[bytes - 1] |= 0x01;

        let candidate = BigUint::from_bytes_be(&candidate_bytes);

        // Use 64 rounds for cryptographic security
        if candidate.is_probably_prime(64) {
            return Ok(candidate);
        }
    }

    Err(CryptoError::SigError)
}

pub fn extract_public_key(private: &RsaPrivateKey) -> RsaPublicKey {
    RsaPublicKey {
        n: private.n.clone(),
        e: BigUint::from_u64(65537),
        bits: private.bits,
    }
}

pub fn create_public_key(n_bytes: Vec<u8>, e_bytes: Vec<u8>) -> RsaPublicKey {
    // DER integers have a leading 0x00 when the MSB is set; strip it
    // so that `bits` reflects the true modulus size (e.g. 2048 not 2056).
    let n_trimmed = match n_bytes.first() {
        Some(0) if n_bytes.len() > 1 => &n_bytes[1..],
        _ => &n_bytes,
    };
    RsaPublicKey {
        n: BigUint::from_bytes_be(&n_bytes),
        e: BigUint::from_bytes_be(&e_bytes),
        bits: n_trimmed.len() * 8,
    }
}

/// RSA private key operation using CRT optimization
pub(crate) fn rsa_private_operation(
    message: &BigUint,
    private_key: &RsaPrivateKey,
) -> Result<BigUint, CryptoError> {
    // CRT optimization: compute m1 = m^dp mod p, m2 = m^dq mod q
    let m1 = message
        .mod_pow(&private_key.dp, &private_key.p)
        .ok_or(CryptoError::SigError)?;
    let m2 = message
        .mod_pow(&private_key.dq, &private_key.q)
        .ok_or(CryptoError::SigError)?;

    // h = qinv * (m1 - m2) mod p
    let diff = if m1 >= m2 {
        &m1 - &m2
    } else {
        &(&private_key.p + &m1) - &m2
    };

    let h = &(&private_key.qinv * &diff) % &private_key.p;

    // result = m2 + h * q
    let result = &m2 + &(&h * &private_key.q);

    Ok(result)
}

/// RSA public key operation
pub(crate) fn rsa_public_operation(
    ciphertext: &BigUint,
    public_key: &RsaPublicKey,
) -> Result<BigUint, CryptoError> {
    if public_key.bits > RSA_4096 {
        return Err(CryptoError::InvalidLength);
    }
    if is_fermat_65537(&public_key.e) && public_key.n.is_odd() {
        return Ok(rsa_public_operation_65537(ciphertext, &public_key.n));
    }
    ciphertext
        .mod_pow(&public_key.e, &public_key.n)
        .ok_or(CryptoError::SigError)
}

fn is_fermat_65537(exp: &BigUint) -> bool {
    exp.limbs.len() == 1 && exp.limbs[0] == 65537
}

fn rsa_public_operation_65537(ciphertext: &BigUint, modulus: &BigUint) -> BigUint {
    let n = modulus.limbs.len();
    let r_bits = n * LIMB_BITS;
    let r = BigUint::one().shl_bits(r_bits) % modulus;
    let r2 = r.square() % modulus;
    let m_inv = BigUint::montgomery_inverse(modulus.limbs[0]);
    let base = ciphertext % modulus;
    let base_m = BigUint::montgomery_reduce(&(&base * &r2), modulus, m_inv);
    let mut acc = base_m.clone();
    for _ in 0..16 {
        acc = BigUint::montgomery_reduce(&acc.square(), modulus, m_inv);
    }
    acc = BigUint::montgomery_reduce(&(&acc * &base_m), modulus, m_inv);
    BigUint::montgomery_reduce(&acc, modulus, m_inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_public_operation_65537_matches_generic_mod_pow() {
        let message = BigUint::from_u64(42);
        let exponent = BigUint::from_u64(65537);
        let modulus = BigUint::from_u64(3233);
        let expected = message.mod_pow(&exponent, &modulus).unwrap();

        assert_eq!(rsa_public_operation_65537(&message, &modulus), expected);
    }
}
