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

use super::{NtruPublicKey, NtruCiphertext, NTRU_WEIGHT, NTRU_SHARED_SECRET_BYTES};
use super::poly::{Polynomial, sample_ternary, hash_to_shared_secret};

pub fn ntru_encaps(pk: &NtruPublicKey) -> Result<(NtruCiphertext, [u8; NTRU_SHARED_SECRET_BYTES]), &'static str> {
    let m = sample_ternary(NTRU_WEIGHT / 2, NTRU_WEIGHT / 2);
    let r = sample_ternary(NTRU_WEIGHT / 2, NTRU_WEIGHT / 2);
    let h = Polynomial::from_coeffs(pk.h.clone());
    let rh = r.multiply(&h);
    let mut c = rh.add(&m);
    c.reduce_mod_q();

    let shared_secret = hash_to_shared_secret(&m.coeffs);

    Ok((NtruCiphertext { c: c.coeffs }, shared_secret))
}
