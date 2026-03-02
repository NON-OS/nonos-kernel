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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;
use super::constants::*;
use super::error::{RunnerError, RunnerResult};
use super::types::{ExecutionContext, ExecutionState, FaultInfo, FaultPolicy, RunnerConfig};
use super::helpers::{
    allocate_module_stack, allocate_module_heap, deallocate_module_memory,
    erase_module_memory, resolve_module_entry, execute_module_startup,
    execute_module_shutdown, get_current_time, calculate_backoff, spin_delay,
};

static EXECUTOR_INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static RUNNING_COUNT: AtomicU64 = AtomicU64::new(0);
pub static CONTEXTS: RwLock<BTreeMap<u64, ExecutionContext>> = RwLock::new(BTreeMap::new());

pub fn init_executor() {
    EXECUTOR_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn is_executor_ready() -> bool {
    EXECUTOR_INITIALIZED.load(Ordering::SeqCst)
}

pub fn start_module(module_id: u64) -> RunnerResult<()> {
    start_module_with_config(module_id, RunnerConfig::default())
}

pub fn start_module_with_config(module_id: u64, config: RunnerConfig) -> RunnerResult<()> {
    if RUNNING_COUNT.load(Ordering::SeqCst) >= MAX_CONCURRENT_MODULES as u64 {
        return Err(RunnerError::ResourceExhausted);
    }

    {
        let contexts = CONTEXTS.read();
        if let Some(ctx) = contexts.get(&module_id) {
            if ctx.state.is_active() {
                return Err(RunnerError::AlreadyRunning);
            }
        }
    }

    let mut context = ExecutionContext::new(module_id, config);

    let stack_base = allocate_module_stack(context.config.stack_size)?;
    let heap_base = allocate_module_heap(context.config.heap_size)?;
    let entry_point = resolve_module_entry(module_id)?;

    context.set_memory_regions(stack_base, heap_base, entry_point);

    let stack_size = context.config.stack_size;
    let heap_size = context.config.heap_size;

    if !context.transition_to(ExecutionState::Starting) {
        deallocate_module_memory(stack_base, stack_size, heap_base, heap_size);
        return Err(RunnerError::InvalidState);
    }

    let startup_result = execute_module_startup(&mut context);

    if startup_result.is_err() {
        context.transition_to(ExecutionState::Faulted);
        deallocate_module_memory(stack_base, stack_size, heap_base, heap_size);
        return Err(RunnerError::StartupFailed);
    }

    if !context.transition_to(ExecutionState::Running) {
        deallocate_module_memory(stack_base, stack_size, heap_base, heap_size);
        return Err(RunnerError::InvalidState);
    }

    context.start_time = get_current_time();
    context.update_heartbeat(context.start_time);

    RUNNING_COUNT.fetch_add(1, Ordering::SeqCst);

    {
        let mut contexts = CONTEXTS.write();
        contexts.insert(module_id, context);
    }

    super::super::registry::set_module_state(module_id, super::super::registry::ModuleState::Running)
        .ok();

    Ok(())
}

pub fn stop_module(module_id: u64) -> RunnerResult<()> {
    let mut context = {
        let mut contexts = CONTEXTS.write();
        contexts.remove(&module_id).ok_or(RunnerError::ModuleNotFound)?
    };

    if !context.state.can_stop() {
        let mut contexts = CONTEXTS.write();
        contexts.insert(module_id, context);
        return Err(RunnerError::NotRunning);
    }

    context.transition_to(ExecutionState::Stopping);

    let shutdown_result = execute_module_shutdown(&mut context);

    erase_module_memory(context.stack_base, context.config.stack_size);
    erase_module_memory(context.heap_base, context.config.heap_size);

    deallocate_module_memory(
        context.stack_base,
        context.config.stack_size,
        context.heap_base,
        context.config.heap_size,
    );

    context.transition_to(ExecutionState::Stopped);

    RUNNING_COUNT.fetch_sub(1, Ordering::SeqCst);

    super::super::registry::set_module_state(module_id, super::super::registry::ModuleState::Stopped)
        .ok();

    context.erase();

    if shutdown_result.is_err() {
        return Err(RunnerError::ShutdownFailed);
    }

    Ok(())
}

pub fn pause_module(module_id: u64) -> RunnerResult<()> {
    let mut contexts = CONTEXTS.write();
    let context = contexts.get_mut(&module_id).ok_or(RunnerError::ModuleNotFound)?;

    if context.state != ExecutionState::Running {
        return Err(RunnerError::InvalidState);
    }

    if !context.transition_to(ExecutionState::Paused) {
        return Err(RunnerError::InvalidState);
    }

    super::super::registry::set_module_state(module_id, super::super::registry::ModuleState::Paused)
        .ok();

    Ok(())
}

pub fn resume_module(module_id: u64) -> RunnerResult<()> {
    let mut contexts = CONTEXTS.write();
    let context = contexts.get_mut(&module_id).ok_or(RunnerError::ModuleNotFound)?;

    if context.state != ExecutionState::Paused {
        return Err(RunnerError::InvalidState);
    }

    if !context.transition_to(ExecutionState::Running) {
        return Err(RunnerError::InvalidState);
    }

    context.update_heartbeat(get_current_time());

    super::super::registry::set_module_state(module_id, super::super::registry::ModuleState::Running)
        .ok();

    Ok(())
}

pub fn handle_module_fault(module_id: u64, fault: FaultInfo) -> RunnerResult<()> {
    let mut contexts = CONTEXTS.write();
    let context = contexts.get_mut(&module_id).ok_or(RunnerError::ModuleNotFound)?;

    context.record_fault(fault);

    match context.config.fault_policy {
        FaultPolicy::Ignore => {
            context.clear_fault();
            context.transition_to(ExecutionState::Running);
            Ok(())
        }
        FaultPolicy::Restart | FaultPolicy::RestartWithBackoff => {
            if context.should_restart() {
                drop(contexts);
                restart_module(module_id)
            } else {
                context.transition_to(ExecutionState::Terminated);
                Err(RunnerError::FaultLimitExceeded)
            }
        }
        FaultPolicy::Terminate => {
            context.transition_to(ExecutionState::Terminated);
            Ok(())
        }
        FaultPolicy::Panic => {
            panic!("Module {} fault with panic policy: {:?}", module_id, context.fault_info);
        }
    }
}

pub fn restart_module(module_id: u64) -> RunnerResult<()> {
    let config = {
        let contexts = CONTEXTS.read();
        contexts.get(&module_id)
            .map(|c| c.config.clone())
            .unwrap_or_default()
    };

    stop_module(module_id).ok();

    if config.fault_policy == FaultPolicy::RestartWithBackoff {
        let backoff = calculate_backoff(module_id);
        spin_delay(backoff);
    }

    start_module_with_config(module_id, config)
}

pub fn get_module_state(module_id: u64) -> RunnerResult<ExecutionState> {
    let contexts = CONTEXTS.read();
    contexts.get(&module_id)
        .map(|c| c.state)
        .ok_or(RunnerError::ModuleNotFound)
}
