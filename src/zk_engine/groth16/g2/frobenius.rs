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

use super::field_element::G2FieldElement;
use crate::zk_engine::groth16::field::FieldElement;

impl G2FieldElement {
    pub fn frobenius_coeff_x_1() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([
                0x99e39557176f553d,
                0xb78cc310c2c3330c,
                0x4c0bec3cf559b143,
                0x2fb347984f7911f7,
            ]),
            c1: FieldElement::from_limbs([
                0x1665d51c640fcba2,
                0x32ae2a1d0b7c9dce,
                0x4ba4cc8bd75a0794,
                0x16c9e55061ebae20,
            ]),
        }
    }
    pub fn frobenius_coeff_x_2() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([
                0x5033a4b3d8d18c8c,
                0x285c512fe7e6c4b9,
                0xf1495f6b8b30ba53,
                0x30644e72e131a028,
            ]),
            c1: FieldElement::zero(),
        }
    }
    pub fn frobenius_coeff_y_1() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([
                0xc3d91224a3c3c88,
                0x35f93c7f4a91f5a3,
                0x7f4a62d86f9c4c30,
                0x14e56d3f1564853a,
            ]),
            c1: FieldElement::from_limbs([
                0x9e95df4e3c3c5d4,
                0x8c9c5dccbb7c3dbb,
                0x1606b7fe9b9a34c4,
                0x23f61f8ab6f91f1f,
            ]),
        }
    }
    pub fn frobenius_coeff_y_2() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x59e26bcea0d48bac, 0x0, 0x0, 0x0]),
            c1: FieldElement::zero(),
        }
    }
    pub fn frobenius_coeff_fp12() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([
                0x856e078b755ef0a,
                0x8c2734e1d7c5ce4a,
                0x572cb8e7e5c79a9f,
                0x2c145edbe7fd8aee,
            ]),
            c1: FieldElement::from_limbs([
                0x6a3e5dd97bb1bb77,
                0xa6d38c2eb0d7c7c8,
                0x8c4fae6e7c1b3de6,
                0x26a6e7e5e7c0f5db,
            ]),
        }
    }
    pub fn frobenius_coeff_fp12_sq() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x30644e72e131a029, 0x0, 0x0, 0x0]),
            c1: FieldElement::zero(),
        }
    }
    pub fn frobenius_coeff_fp12_cub() -> Self {
        G2FieldElement {
            c0: FieldElement::from_limbs([0x59e26bcea0d48ba6, 0x0, 0x0, 0x0]),
            c1: FieldElement::from_limbs([0x0, 0x0, 0x0, 0x0]),
        }
    }
}
