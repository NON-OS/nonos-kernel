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

use super::{NtruKeyPair, NtruPublicKey, NtruSecretKey, NTRU_WEIGHT};
use super::poly::{sample_ternary, poly_inverse_mod_3, poly_inverse_mod_q};

pub fn ntru_keygen() -> Result<NtruKeyPair, &'static str> {
    let (f, fp, fq) = loop {
        let f = sample_ternary(NTRU_WEIGHT / 2, NTRU_WEIGHT / 2);
        let fp = match poly_inverse_mod_3(&f) {
            Some(inv) => inv,
            None => continue,
        };

        let fq = match poly_inverse_mod_q(&f) {
            Some(inv) => inv,
            None => continue,
        };

        break (f, fp, fq);
    };

    let g = sample_ternary(NTRU_WEIGHT / 2, NTRU_WEIGHT / 2);
    let pfq = fq.scale(3);
    let mut h = pfq.multiply(&g);
    h.reduce_mod_q();
    let h_coeffs = h.coeffs;
    Ok(NtruKeyPair {
        public_key: NtruPublicKey { h: h_coeffs.clone() },
        secret_key: NtruSecretKey {
            f: f.coeffs,
            fp: fp.coeffs,
            pk: NtruPublicKey { h: h_coeffs },
        },
    })
}
