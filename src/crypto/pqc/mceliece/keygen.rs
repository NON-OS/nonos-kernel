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

use super::goppa::{
    generate_goppa_polynomial, generate_support, generate_permutation,
    compute_parity_check_matrix, to_systematic_form,
};
use super::{McElieceKeyPair, McEliecePublicKey, McElieceSecretKey};

pub fn mceliece_keygen() -> Result<McElieceKeyPair, &'static str> {
    let goppa = generate_goppa_polynomial();
    let support = generate_support();
    let permutation = generate_permutation();
    let h = compute_parity_check_matrix(&goppa, &support);
    let t_matrix = to_systematic_form(&h).ok_or("Failed to compute systematic form")?;

    Ok(McElieceKeyPair {
        public_key: McEliecePublicKey { t_matrix: t_matrix.clone() },
        secret_key: McElieceSecretKey {
            goppa_poly: goppa,
            support,
            permutation,
            pk: McEliecePublicKey { t_matrix },
        },
    })
}
