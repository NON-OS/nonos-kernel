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

use alloc::string::String;
use core::fmt;
use super::error_code::InputErrorCode;
use super::get_timestamp;

#[derive(Debug, Clone)]
pub struct InputError {
    code: InputErrorCode,
    context: Option<String>,
    event_type: Option<&'static str>,
    timestamp: u64,
}

impl InputError {
    pub fn new(code: InputErrorCode) -> Self {
        Self { code, context: None, event_type: None, timestamp: get_timestamp() }
    }

    pub fn with_context(code: InputErrorCode, context: impl Into<String>) -> Self {
        Self { code, context: Some(context.into()), event_type: None, timestamp: get_timestamp() }
    }

    pub fn with_event_type(mut self, event_type: &'static str) -> Self {
        self.event_type = Some(event_type);
        self
    }

    pub const fn code(&self) -> InputErrorCode { self.code }
    pub fn context(&self) -> Option<&str> { self.context.as_deref() }
    pub const fn timestamp(&self) -> u64 { self.timestamp }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(ref ctx) = self.context { write!(f, ": {}", ctx)?; }
        if let Some(event_type) = self.event_type { write!(f, " [event: {}]", event_type)?; }
        Ok(())
    }
}

pub type InputResult<T> = Result<T, InputError>;
