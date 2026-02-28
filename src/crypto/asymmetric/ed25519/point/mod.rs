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
mod ops;
mod pack;
mod precomp;
mod scalarmult;

pub(crate) use types::{GeP3, GeP2, GeCached, GeP1P1, D, D2};
pub(crate) use ops::{ge_identity, ge_to_cached, ge_add, ge_double, ge_p1p1_to_p3, ge_p1p1_to_p2};
pub(crate) use pack::{ge_pack, ge_unpack, ge_basepoint};
pub(crate) use precomp::{Precomp, PRECOMP, ensure_precomp};
pub(crate) use scalarmult::{
    ge_scalarmult_base_ct, ge_scalarmult_ct, ct_byte_mask, ge_cmov,
    ge_scalarmult_vartime, ge_scalarmult_point, ge_has_large_order
};
