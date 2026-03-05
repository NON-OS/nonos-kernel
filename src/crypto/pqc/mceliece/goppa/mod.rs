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

mod poly;
mod generate;
mod matrix;
mod decode;

pub(super) use poly::poly_eval;
pub(super) use generate::{generate_goppa_polynomial, generate_support, generate_permutation};
pub(super) use matrix::{compute_parity_check_matrix, to_systematic_form};
pub(super) use decode::{berlekamp_massey, chien_search};

pub(super) fn is_irreducible(polynomial: &[u16]) -> bool {
    let deg = poly::poly_degree(polynomial);
    if deg <= 1 {
        return true;
    }
    poly::is_likely_irreducible(polynomial)
}

pub(super) fn polynomial_gcd(a: &[u16], b: &[u16]) -> usize {
    let gcd = poly::poly_gcd(a, b);
    poly::poly_degree(&gcd)
}
