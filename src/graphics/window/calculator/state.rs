// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU8};

pub(crate) static CALC_DISPLAY: AtomicI64 = AtomicI64::new(0);
pub(crate) static CALC_OPERAND: AtomicI64 = AtomicI64::new(0);
pub(crate) static CALC_OPERATOR: AtomicU8 = AtomicU8::new(0);
pub(crate) static CALC_NEW_INPUT: AtomicBool = AtomicBool::new(true);
pub(crate) static CALC_EXPR_OP: AtomicU8 = AtomicU8::new(0);
pub(crate) static CALC_EXPR_VAL: AtomicI64 = AtomicI64::new(0);
pub(crate) static CALC_DECIMAL_POS: AtomicU8 = AtomicU8::new(0);
