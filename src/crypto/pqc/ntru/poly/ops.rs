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

use super::super::NTRU_N;
use super::types::Polynomial;

impl Polynomial {
    // SECURITY: Constant-time polynomial multiplication to prevent timing attacks.
    pub(crate) fn multiply(&self, other: &Polynomial) -> Polynomial {
        let mut result = Polynomial::new();

        for i in 0..NTRU_N {
            for j in 0..NTRU_N {
                let k = (i + j) % NTRU_N;
                result.coeffs[k] = result.coeffs[k].wrapping_add(
                    self.coeffs[i].wrapping_mul(other.coeffs[j])
                );
            }
        }

        result
    }

    pub(crate) fn add(&self, other: &Polynomial) -> Polynomial {
        let mut result = Polynomial::new();
        for i in 0..NTRU_N {
            result.coeffs[i] = self.coeffs[i].wrapping_add(other.coeffs[i]);
        }
        result
    }

    pub(crate) fn scale(&self, s: i16) -> Polynomial {
        let mut result = Polynomial::new();
        for i in 0..NTRU_N {
            result.coeffs[i] = self.coeffs[i].wrapping_mul(s);
        }
        result
    }
}
