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

extern crate alloc;

use crate::test::framework::TestResult;
use crate::zksync::eravm::*;
use crate::zksync::types::*;

pub(crate) fn test_vm_memory_new() -> TestResult {
    let mem = VmMemory::new();
    if mem.size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_default() -> TestResult {
    let mem: VmMemory = Default::default();
    if mem.size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_with_capacity() -> TestResult {
    let mem = VmMemory::with_capacity(1024);
    if mem.size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_store_load() -> TestResult {
    let mut mem = VmMemory::new();
    let data = [1u8, 2, 3, 4, 5];
    mem.store(0, &data);
    let loaded = mem.load(0, 5);
    if loaded != &data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_store_expands() -> TestResult {
    let mut mem = VmMemory::new();
    if mem.size() != 0 {
        return TestResult::Fail;
    }
    mem.store(0, &[1, 2, 3, 4]);
    if mem.size() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_load_expands() -> TestResult {
    let mut mem = VmMemory::new();
    let _ = mem.load(100, 10);
    if mem.size() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_store_at_offset() -> TestResult {
    let mut mem = VmMemory::new();
    mem.store(100, &[0xAA, 0xBB, 0xCC]);
    let loaded = mem.load(100, 3);
    if loaded != &[0xAA, 0xBB, 0xCC] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_load_u256() -> TestResult {
    let mut mem = VmMemory::new();
    let data = [0x12u8; 32];
    mem.store(0, &data);
    let loaded = mem.load_u256(0);
    if loaded != data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_store_u256() -> TestResult {
    let mut mem = VmMemory::new();
    let data = [0x34u8; 32];
    mem.store_u256(0, &data);
    let loaded = mem.load_u256(0);
    if loaded != data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_load_u256_zeros() -> TestResult {
    let mut mem = VmMemory::new();
    let loaded = mem.load_u256(0);
    if loaded != [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_clear() -> TestResult {
    let mut mem = VmMemory::new();
    mem.store(0, &[1, 2, 3, 4]);
    if mem.size() <= 0 {
        return TestResult::Fail;
    }
    mem.clear();
    if mem.size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_page_alignment() -> TestResult {
    let mut mem = VmMemory::new();
    mem.store(0, &[1]);
    if mem.size() < 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_multiple_stores() -> TestResult {
    let mut mem = VmMemory::new();
    mem.store(0, &[0xAA; 16]);
    mem.store(16, &[0xBB; 16]);
    mem.store(32, &[0xCC; 16]);
    if mem.load(0, 16) != &[0xAA; 16] {
        return TestResult::Fail;
    }
    if mem.load(16, 16) != &[0xBB; 16] {
        return TestResult::Fail;
    }
    if mem.load(32, 16) != &[0xCC; 16] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vm_memory_overwrite() -> TestResult {
    let mut mem = VmMemory::new();
    mem.store(0, &[0xAA; 8]);
    mem.store(0, &[0xBB; 8]);
    if mem.load(0, 8) != &[0xBB; 8] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_new() -> TestResult {
    let caller = Address::from_slice(&[1u8; 20]);
    let address = Address::from_slice(&[2u8; 20]);
    let value = U256::from_u64(1000);
    let gas_limit = Gas(100000);
    let ctx = ExecutionContext::new(caller, address, value, gas_limit);
    if ctx.caller != caller {
        return TestResult::Fail;
    }
    if ctx.address != address {
        return TestResult::Fail;
    }
    if ctx.value != value {
        return TestResult::Fail;
    }
    if ctx.gas_limit != gas_limit {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_initial_state() -> TestResult {
    let ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(100000));
    if ctx.gas_used.0 != 0 {
        return TestResult::Fail;
    }
    if ctx.pc != 0 {
        return TestResult::Fail;
    }
    if ctx.return_data.is_some() {
        return TestResult::Fail;
    }
    if ctx.reverted {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_consume_gas() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    if !ctx.consume_gas(500) {
        return TestResult::Fail;
    }
    if ctx.gas_used.0 != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_consume_gas_exceeds_limit() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    if ctx.consume_gas(1500) {
        return TestResult::Fail;
    }
    if ctx.gas_used.0 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_consume_gas_exact_limit() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    if !ctx.consume_gas(1000) {
        return TestResult::Fail;
    }
    if ctx.gas_used.0 != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_remaining_gas() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    if ctx.remaining_gas() != 1000 {
        return TestResult::Fail;
    }
    ctx.consume_gas(300);
    if ctx.remaining_gas() != 700 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_revert() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    ctx.revert(alloc::vec![1, 2, 3, 4]);
    if !ctx.reverted {
        return TestResult::Fail;
    }
    if ctx.return_data.is_none() {
        return TestResult::Fail;
    }
    if ctx.return_data.as_ref().unwrap() != &[1, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_finish() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    ctx.finish(alloc::vec![0xAB, 0xCD]);
    if ctx.reverted {
        return TestResult::Fail;
    }
    if ctx.return_data.is_none() {
        return TestResult::Fail;
    }
    if ctx.return_data.as_ref().unwrap() != &[0xAB, 0xCD] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_is_finished_false() -> TestResult {
    let ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    if ctx.is_finished() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_is_finished_after_finish() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    ctx.finish(alloc::vec![]);
    if !ctx.is_finished() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_is_finished_after_revert() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    ctx.revert(alloc::vec![]);
    if !ctx.is_finished() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_memory_access() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    ctx.memory.store(0, &[0xFF; 32]);
    let data = ctx.memory.load_u256(0);
    if data != [0xFF; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_multiple_gas_consumption() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    if !ctx.consume_gas(100) {
        return TestResult::Fail;
    }
    if !ctx.consume_gas(200) {
        return TestResult::Fail;
    }
    if !ctx.consume_gas(300) {
        return TestResult::Fail;
    }
    if ctx.gas_used.0 != 600 {
        return TestResult::Fail;
    }
    if ctx.remaining_gas() != 400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execution_context_gas_consumption_fails_mid_execution() -> TestResult {
    let mut ctx = ExecutionContext::new(Address::ZERO, Address::ZERO, U256::ZERO, Gas(1000));
    if !ctx.consume_gas(500) {
        return TestResult::Fail;
    }
    if !ctx.consume_gas(400) {
        return TestResult::Fail;
    }
    if ctx.consume_gas(200) {
        return TestResult::Fail;
    }
    if ctx.gas_used.0 != 900 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
