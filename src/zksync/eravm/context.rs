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

use super::memory::VmMemory;
use crate::zksync::types::{Address, Gas, U256};

pub struct ExecutionContext {
    pub caller: Address,
    pub address: Address,
    pub value: U256,
    pub gas_limit: Gas,
    pub gas_used: Gas,
    pub memory: VmMemory,
    pub pc: usize,
    pub return_data: Option<alloc::vec::Vec<u8>>,
    pub reverted: bool,
}

impl ExecutionContext {
    pub fn new(caller: Address, address: Address, value: U256, gas_limit: Gas) -> Self {
        Self {
            caller,
            address,
            value,
            gas_limit,
            gas_used: Gas(0),
            memory: VmMemory::new(),
            pc: 0,
            return_data: None,
            reverted: false,
        }
    }

    pub fn consume_gas(&mut self, amount: u64) -> bool {
        let new_used = self.gas_used.0.saturating_add(amount);
        if new_used > self.gas_limit.0 {
            return false;
        }
        self.gas_used.0 = new_used;
        true
    }

    pub fn remaining_gas(&self) -> u64 {
        self.gas_limit.0.saturating_sub(self.gas_used.0)
    }

    pub fn revert(&mut self, data: alloc::vec::Vec<u8>) {
        self.reverted = true;
        self.return_data = Some(data);
    }

    pub fn finish(&mut self, data: alloc::vec::Vec<u8>) {
        self.return_data = Some(data);
    }

    pub fn is_finished(&self) -> bool {
        self.return_data.is_some()
    }
}
