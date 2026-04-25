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

use super::types::{FirmwareError, ErrorCategory};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStrategy { Retry, Fallback, Ignore, Reset, Abort }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryResult { Success, PartialSuccess, Failed, NotApplicable }

#[derive(Debug, Clone)]
pub struct ErrorRecovery { strategy: RecoveryStrategy, max_retries: u8, fallback_options: u8, recovery_timeout: u32 }

pub fn attempt_error_recovery(error: &FirmwareError, recovery: &ErrorRecovery) -> RecoveryResult {
    if !error.is_recoverable() { return RecoveryResult::NotApplicable; }
    match recovery.strategy { RecoveryStrategy::Retry => attempt_retry(error, recovery.max_retries), RecoveryStrategy::Fallback => attempt_fallback(error, recovery.fallback_options), RecoveryStrategy::Ignore => RecoveryResult::Success, RecoveryStrategy::Reset => attempt_reset(error), RecoveryStrategy::Abort => RecoveryResult::Failed }
}

impl Default for ErrorRecovery {
    fn default() -> Self { Self { strategy: RecoveryStrategy::Retry, max_retries: 3, fallback_options: 2, recovery_timeout: 5000 } }
}

impl ErrorRecovery {
    pub fn new(strategy: RecoveryStrategy) -> Self { Self { strategy, max_retries: 3, fallback_options: 2, recovery_timeout: 5000 } }
    pub fn with_retries(mut self, max_retries: u8) -> Self { self.max_retries = max_retries; self }
    pub fn with_timeout(mut self, timeout_ms: u32) -> Self { self.recovery_timeout = timeout_ms; self }
    pub fn with_fallback_count(mut self, count: u8) -> Self { self.fallback_options = count; self }
}

fn attempt_retry(error: &FirmwareError, max_retries: u8) -> RecoveryResult {
    for retry in 0..max_retries { if simulate_operation(error.category) { return if retry == 0 { RecoveryResult::Success } else { RecoveryResult::PartialSuccess }; } if retry < max_retries - 1 { exponential_backoff(retry); } }
    RecoveryResult::Failed
}

fn attempt_fallback(error: &FirmwareError, fallback_options: u8) -> RecoveryResult {
    for option in 0..fallback_options { if apply_fallback_strategy(error.category, option) { return if option == 0 { RecoveryResult::Success } else { RecoveryResult::PartialSuccess }; } }
    RecoveryResult::Failed
}

fn attempt_reset(error: &FirmwareError) -> RecoveryResult {
    match error.category { ErrorCategory::Hardware => if reset_hardware() { RecoveryResult::Success } else { RecoveryResult::Failed }, ErrorCategory::Memory => if reset_memory_state() { RecoveryResult::Success } else { RecoveryResult::Failed }, ErrorCategory::Loading => if reload_firmware() { RecoveryResult::PartialSuccess } else { RecoveryResult::Failed }, _ => RecoveryResult::NotApplicable }
}

fn simulate_operation(category: ErrorCategory) -> bool { matches!(category, ErrorCategory::Loading | ErrorCategory::Validation) }
fn apply_fallback_strategy(category: ErrorCategory, option: u8) -> bool { category == ErrorCategory::Loading && option < 2 }
fn exponential_backoff(retry: u8) { let delay = 1u32 << retry; for _ in 0..delay * 1000 { core::hint::spin_loop(); } }
fn reset_hardware() -> bool { true }
fn reset_memory_state() -> bool { true }
fn reload_firmware() -> bool { true }