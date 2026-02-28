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

mod types;
mod arithmetic;
mod power;
mod serialize;
mod compare;

pub(crate) use types::{Fe, fe_copy};
pub(crate) use arithmetic::{fe_add, fe_sub, fe_mul, fe_sq};
pub(crate) use power::{fe_invert, fe_pow2523};
pub(crate) use serialize::{fe_tobytes, fe_frombytes, load3, load4};
pub(crate) use compare::{fe_is_odd, fe_equal, ct_eq_32, fe_cmov, fe_is_zero};
