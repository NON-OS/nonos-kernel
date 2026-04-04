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

use crate::zksync::eravm::*;
use crate::zksync::types::*;

#[test]
fn test_vm_memory_new() {
    let mem = VmMemory::new();
    assert_eq!(mem.size(), 0);
}

#[test]
fn test_vm_memory_default() {
    let mem: VmMemory = Default::default();
    assert_eq!(mem.size(), 0);
}

#[test]
fn test_vm_memory_with_capacity() {
    let mem = VmMemory::with_capacity(1024);
    assert_eq!(mem.size(), 0);
}

#[test]
fn test_vm_memory_store_load() {
    let mut mem = VmMemory::new();
    let data = [1u8, 2, 3, 4, 5];
    mem.store(0, &data);
    let loaded = mem.load(0, 5);
    assert_eq!(loaded, &data);
}

#[test]
fn test_vm_memory_store_expands() {
    let mut mem = VmMemory::new();
    assert_eq!(mem.size(), 0);
    mem.store(0, &[1, 2, 3, 4]);
    assert!(mem.size() > 0);
}

#[test]
fn test_vm_memory_load_expands() {
    let mut mem = VmMemory::new();
    let _ = mem.load(100, 10);
    assert!(mem.size() > 0);
}

#[test]
fn test_vm_memory_store_at_offset() {
    let mut mem = VmMemory::new();
    mem.store(100, &[0xAA, 0xBB, 0xCC]);
    let loaded = mem.load(100, 3);
    assert_eq!(loaded, &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn test_vm_memory_load_u256() {
    let mut mem = VmMemory::new();
    let data = [0x12u8; 32];
    mem.store(0, &data);
    let loaded = mem.load_u256(0);
    assert_eq!(loaded, data);
}

#[test]
fn test_vm_memory_store_u256() {
    let mut mem = VmMemory::new();
    let data = [0x34u8; 32];
    mem.store_u256(0, &data);
    let loaded = mem.load_u256(0);
    assert_eq!(loaded, data);
}

#[test]
fn test_vm_memory_load_u256_zeros() {
    let mut mem = VmMemory::new();
    let loaded = mem.load_u256(0);
    assert_eq!(loaded, [0u8; 32]);
}

#[test]
fn test_vm_memory_clear() {
    let mut mem = VmMemory::new();
    mem.store(0, &[1, 2, 3, 4]);
    assert!(mem.size() > 0);
    mem.clear();
    assert_eq!(mem.size(), 0);
}

#[test]
fn test_vm_memory_page_alignment() {
    let mut mem = VmMemory::new();
    mem.store(0, &[1]);
    assert!(mem.size() >= 4096);
}

#[test]
fn test_vm_memory_multiple_stores() {
    let mut mem = VmMemory::new();
    mem.store(0, &[0xAA; 16]);
    mem.store(16, &[0xBB; 16]);
    mem.store(32, &[0xCC; 16]);
    assert_eq!(mem.load(0, 16), &[0xAA; 16]);
    assert_eq!(mem.load(16, 16), &[0xBB; 16]);
    assert_eq!(mem.load(32, 16), &[0xCC; 16]);
}

#[test]
fn test_vm_memory_overwrite() {
    let mut mem = VmMemory::new();
    mem.store(0, &[0xAA; 8]);
    mem.store(0, &[0xBB; 8]);
    assert_eq!(mem.load(0, 8), &[0xBB; 8]);
}

#[test]
fn test_execution_context_new() {
    let caller = Address::from_slice(&[1u8; 20]);
    let address = Address::from_slice(&[2u8; 20]);
    let value = U256::from_u64(1000);
    let gas_limit = Gas(100000);
    let ctx = ExecutionContext::new(caller, address, value, gas_limit);
    assert_eq!(ctx.caller, caller);
    assert_eq!(ctx.address, address);
    assert_eq!(ctx.value, value);
    assert_eq!(ctx.gas_limit, gas_limit);
}

#[test]
fn test_execution_context_initial_state() {
    let ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(100000),
    );
    assert_eq!(ctx.gas_used.0, 0);
    assert_eq!(ctx.pc, 0);
    assert!(ctx.return_data.is_none());
    assert!(!ctx.reverted);
}

#[test]
fn test_execution_context_consume_gas() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    assert!(ctx.consume_gas(500));
    assert_eq!(ctx.gas_used.0, 500);
}

#[test]
fn test_execution_context_consume_gas_exceeds_limit() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    assert!(!ctx.consume_gas(1500));
    assert_eq!(ctx.gas_used.0, 0);
}

#[test]
fn test_execution_context_consume_gas_exact_limit() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    assert!(ctx.consume_gas(1000));
    assert_eq!(ctx.gas_used.0, 1000);
}

#[test]
fn test_execution_context_remaining_gas() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    assert_eq!(ctx.remaining_gas(), 1000);
    ctx.consume_gas(300);
    assert_eq!(ctx.remaining_gas(), 700);
}

#[test]
fn test_execution_context_revert() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    ctx.revert(alloc::vec![1, 2, 3, 4]);
    assert!(ctx.reverted);
    assert!(ctx.return_data.is_some());
    assert_eq!(ctx.return_data.as_ref().unwrap(), &[1, 2, 3, 4]);
}

#[test]
fn test_execution_context_finish() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    ctx.finish(alloc::vec![0xAB, 0xCD]);
    assert!(!ctx.reverted);
    assert!(ctx.return_data.is_some());
    assert_eq!(ctx.return_data.as_ref().unwrap(), &[0xAB, 0xCD]);
}

#[test]
fn test_execution_context_is_finished_false() {
    let ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    assert!(!ctx.is_finished());
}

#[test]
fn test_execution_context_is_finished_after_finish() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    ctx.finish(alloc::vec![]);
    assert!(ctx.is_finished());
}

#[test]
fn test_execution_context_is_finished_after_revert() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    ctx.revert(alloc::vec![]);
    assert!(ctx.is_finished());
}

#[test]
fn test_execution_context_memory_access() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    ctx.memory.store(0, &[0xFF; 32]);
    let data = ctx.memory.load_u256(0);
    assert_eq!(data, [0xFF; 32]);
}

#[test]
fn test_execution_context_multiple_gas_consumption() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    assert!(ctx.consume_gas(100));
    assert!(ctx.consume_gas(200));
    assert!(ctx.consume_gas(300));
    assert_eq!(ctx.gas_used.0, 600);
    assert_eq!(ctx.remaining_gas(), 400);
}

#[test]
fn test_execution_context_gas_consumption_fails_mid_execution() {
    let mut ctx = ExecutionContext::new(
        Address::ZERO,
        Address::ZERO,
        U256::ZERO,
        Gas(1000),
    );
    assert!(ctx.consume_gas(500));
    assert!(ctx.consume_gas(400));
    assert!(!ctx.consume_gas(200));
    assert_eq!(ctx.gas_used.0, 900);
}
