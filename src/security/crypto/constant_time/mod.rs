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
mod core;
mod ops;
mod memory;
mod tests;
mod ed25519;
mod x25519;
mod aes;
mod init;

pub use types::{CtVerifyResult, TimingMode, SelfTestResult};
pub use self::core::{
    ct_compare, ct_verify, ct_select_u8, ct_select_u32, ct_select_u64,
    ct_select_slice, ct_swap_slices,
};
pub use ops::{
    ct_lt_u32, ct_lt_u64, ct_gt_u32, ct_eq_u32, ct_eq_u64,
    ct_min_u32, ct_max_u32, ct_copy_bounded,
};
pub use memory::{ct_zero, ct_zero_u64, ct_hmac_verify, ct_signature_verify};
pub use tests::run_self_tests;
pub use init::init;

pub mod ed25519_ct {
    pub use super::ed25519::*;
}

pub mod x25519_ct {
    pub use super::x25519::*;
}

pub mod aes_ct {
    pub use super::aes::*;
}
