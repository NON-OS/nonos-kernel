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

use crate::arch::aarch64::exceptions::frame::ExceptionFrame;
use crate::arch::trap::contract::{TrapCause, TrapFrame as ContractFrame};

use super::cause;

impl ContractFrame for ExceptionFrame {
    fn instruction_pointer(&self) -> u64 {
        self.elr
    }

    fn stack_pointer(&self) -> u64 {
        self.sp
    }

    fn from_user(&self) -> bool {
        self.is_from_el0()
    }

    fn cause(&self) -> TrapCause {
        cause::project(self)
    }
}
