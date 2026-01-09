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

use super::{NtruCiphertext, NtruSecretKey, NTRU_SHARED_SECRET_BYTES};
use super::poly::{Polynomial, hash_to_shared_secret};

pub fn ntru_decaps(ct: &NtruCiphertext, sk: &NtruSecretKey) -> Result<[u8; NTRU_SHARED_SECRET_BYTES], &'static str> {
    let c = Polynomial::from_coeffs(ct.c.clone());
    let f = Polynomial::from_coeffs(sk.f.clone());
    let fp = Polynomial::from_coeffs(sk.fp.clone());

    let mut a = f.multiply(&c);
    a.reduce_mod_q();

    a.reduce_mod_3();

    let mut m = fp.multiply(&a);
    m.reduce_mod_3();

    let shared_secret = hash_to_shared_secret(&m.coeffs);

    Ok(shared_secret)
}
