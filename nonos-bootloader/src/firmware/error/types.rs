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

use crate::firmware::types::FirmwareType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity { Info, Warning, Error, Critical, Fatal }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory { Loading, Validation, Security, Compatibility, Hardware, Memory, Network, Storage }

#[derive(Debug, Clone)]
pub struct FirmwareError { pub category: ErrorCategory, pub severity: ErrorSeverity, pub code: u32, pub firmware_type: FirmwareType, pub message: [u8; 128], pub context: ErrorContext, pub timestamp: u64 }

#[derive(Debug, Clone, Copy)]
pub struct ErrorContext { pub file_line: u32, pub function_id: u16, pub thread_id: u8, pub additional_data: u64 }

impl FirmwareError {
    pub fn new(category: ErrorCategory, severity: ErrorSeverity, code: u32, firmware_type: FirmwareType) -> Self {
        Self { category, severity, code, firmware_type, message: [0; 128], context: ErrorContext::default(), timestamp: get_system_time() }
    }
    pub fn with_message(mut self, message: &str) -> Self { let msg_bytes = message.as_bytes(); let len = core::cmp::min(msg_bytes.len(), 127); self.message[..len].copy_from_slice(&msg_bytes[..len]); self }
    pub fn with_context(mut self, context: ErrorContext) -> Self { self.context = context; self }
    pub fn is_recoverable(&self) -> bool { !matches!(self.severity, ErrorSeverity::Fatal) }
    pub fn requires_immediate_action(&self) -> bool { matches!(self.severity, ErrorSeverity::Critical | ErrorSeverity::Fatal) }
    pub fn get_message(&self) -> &str { let end = self.message.iter().position(|&b| b == 0).unwrap_or(128); core::str::from_utf8(&self.message[..end]).unwrap_or("invalid utf8") }
}

impl Default for ErrorContext {
    fn default() -> Self { Self { file_line: 0, function_id: 0, thread_id: 0, additional_data: 0 } }
}

impl core::fmt::Display for FirmwareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{:?}] {:?}: {} (code: {}, firmware: {:?})", self.severity, self.category, self.get_message(), self.code, self.firmware_type)
    }
}

fn get_system_time() -> u64 { static mut COUNTER: u64 = 0; unsafe { COUNTER += 1; COUNTER } }