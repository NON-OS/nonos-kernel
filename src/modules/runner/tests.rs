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

use super::*;

#[test]
fn test_execution_state_is_active() {
    assert!(!ExecutionState::Pending.is_active());
    assert!(ExecutionState::Starting.is_active());
    assert!(ExecutionState::Running.is_active());
    assert!(ExecutionState::Paused.is_active());
    assert!(!ExecutionState::Stopping.is_active());
    assert!(!ExecutionState::Stopped.is_active());
    assert!(!ExecutionState::Faulted.is_active());
    assert!(!ExecutionState::Terminated.is_active());
}

#[test]
fn test_execution_state_is_terminal() {
    assert!(!ExecutionState::Pending.is_terminal());
    assert!(!ExecutionState::Running.is_terminal());
    assert!(ExecutionState::Stopped.is_terminal());
    assert!(ExecutionState::Faulted.is_terminal());
    assert!(ExecutionState::Terminated.is_terminal());
}

#[test]
fn test_execution_state_can_start() {
    assert!(ExecutionState::Pending.can_start());
    assert!(ExecutionState::Stopped.can_start());
    assert!(!ExecutionState::Running.can_start());
    assert!(!ExecutionState::Faulted.can_start());
}

#[test]
fn test_execution_state_can_stop() {
    assert!(ExecutionState::Running.can_stop());
    assert!(ExecutionState::Paused.can_stop());
    assert!(ExecutionState::Faulted.can_stop());
    assert!(!ExecutionState::Pending.can_stop());
    assert!(!ExecutionState::Stopped.can_stop());
}

#[test]
fn test_fault_policy_default() {
    assert_eq!(FaultPolicy::default(), FaultPolicy::RestartWithBackoff);
}

#[test]
fn test_fault_info_creation() {
    let fault = FaultInfo::new(FaultType::MemoryViolation, 0x1000);
    assert_eq!(fault.fault_type, FaultType::MemoryViolation);
    assert_eq!(fault.instruction_pointer, 0x1000);
    assert_eq!(fault.fault_count, 1);
    assert!(fault.address.is_none());
}

#[test]
fn test_fault_info_with_address() {
    let fault = FaultInfo::new(FaultType::StackOverflow, 0x2000)
        .with_address(0xDEADBEEF);
    assert_eq!(fault.address, Some(0xDEADBEEF));
}

#[test]
fn test_fault_info_increment() {
    let mut fault = FaultInfo::new(FaultType::DivisionByZero, 0x3000);
    assert_eq!(fault.fault_count, 1);
    fault.increment_count();
    assert_eq!(fault.fault_count, 2);
    fault.increment_count();
    assert_eq!(fault.fault_count, 3);
}

#[test]
fn test_runner_config_default() {
    let config = RunnerConfig::default();
    assert_eq!(config.stack_size, MODULE_STACK_SIZE);
    assert_eq!(config.heap_size, MODULE_HEAP_SIZE);
    assert_eq!(config.fault_policy, FaultPolicy::RestartWithBackoff);
    assert!(config.watchdog_enabled);
}

#[test]
fn test_runner_config_builder() {
    let config = RunnerConfig::new()
        .with_stack_size(128 * 1024)
        .with_heap_size(2 * 1024 * 1024)
        .with_fault_policy(FaultPolicy::Terminate)
        .with_watchdog(false, 5000)
        .with_priority(200);

    assert_eq!(config.stack_size, 128 * 1024);
    assert_eq!(config.heap_size, 2 * 1024 * 1024);
    assert_eq!(config.fault_policy, FaultPolicy::Terminate);
    assert!(!config.watchdog_enabled);
    assert_eq!(config.priority, 200);
}

#[test]
fn test_execution_context_creation() {
    let config = RunnerConfig::default();
    let context = ExecutionContext::new(42, config);
    assert_eq!(context.module_id, 42);
    assert_eq!(context.state, ExecutionState::Pending);
    assert!(context.fault_info.is_none());
}

#[test]
fn test_execution_context_state_transitions() {
    let config = RunnerConfig::default();
    let mut context = ExecutionContext::new(1, config);

    assert!(context.transition_to(ExecutionState::Starting));
    assert_eq!(context.state, ExecutionState::Starting);

    assert!(context.transition_to(ExecutionState::Running));
    assert_eq!(context.state, ExecutionState::Running);

    assert!(context.transition_to(ExecutionState::Paused));
    assert_eq!(context.state, ExecutionState::Paused);

    assert!(context.transition_to(ExecutionState::Running));
    assert_eq!(context.state, ExecutionState::Running);

    assert!(context.transition_to(ExecutionState::Stopping));
    assert_eq!(context.state, ExecutionState::Stopping);

    assert!(context.transition_to(ExecutionState::Stopped));
    assert_eq!(context.state, ExecutionState::Stopped);
}

#[test]
fn test_execution_context_invalid_transition() {
    let config = RunnerConfig::default();
    let mut context = ExecutionContext::new(1, config);

    assert!(!context.transition_to(ExecutionState::Running));
    assert_eq!(context.state, ExecutionState::Pending);

    assert!(!context.transition_to(ExecutionState::Stopped));
    assert_eq!(context.state, ExecutionState::Pending);
}

#[test]
fn test_execution_context_record_fault() {
    let config = RunnerConfig::default();
    let mut context = ExecutionContext::new(1, config);
    context.transition_to(ExecutionState::Starting);
    context.transition_to(ExecutionState::Running);

    let fault = FaultInfo::new(FaultType::MemoryViolation, 0x1000);
    context.record_fault(fault);

    assert_eq!(context.state, ExecutionState::Faulted);
    assert!(context.fault_info.is_some());
}

#[test]
fn test_execution_context_should_restart() {
    let config = RunnerConfig::new()
        .with_fault_policy(FaultPolicy::RestartWithBackoff);
    let mut context = ExecutionContext::new(1, config);
    context.transition_to(ExecutionState::Starting);
    context.transition_to(ExecutionState::Running);

    let fault = FaultInfo::new(FaultType::Timeout, 0x2000);
    context.record_fault(fault);

    assert!(context.should_restart());
}

#[test]
fn test_execution_context_no_restart_on_terminate_policy() {
    let config = RunnerConfig::new()
        .with_fault_policy(FaultPolicy::Terminate);
    let mut context = ExecutionContext::new(1, config);
    context.transition_to(ExecutionState::Starting);
    context.transition_to(ExecutionState::Running);

    let fault = FaultInfo::new(FaultType::SecurityBreach, 0x3000);
    context.record_fault(fault);

    assert!(!context.should_restart());
}

#[test]
fn test_runner_error_errno() {
    assert_eq!(RunnerError::ModuleNotFound.to_errno(), -2);
    assert_eq!(RunnerError::AlreadyRunning.to_errno(), -16);
    assert_eq!(RunnerError::ResourceExhausted.to_errno(), -12);
    assert_eq!(RunnerError::StartupTimeout.to_errno(), -110);
}
