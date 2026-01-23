// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::get_timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InputErrorCode {
    QueueFull = 1,
    QueueEmpty = 2,
    InvalidEvent = 3,
    InvalidConfig = 4,
    DeviceNotFound = 5,
    Timeout = 6,
    InternalError = 7,
    QueueShutdown = 8,
    FilterRejected = 9,
    ResourceExhausted = 10,
}

impl InputErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "input queue is full",
            Self::QueueEmpty => "input queue is empty",
            Self::InvalidEvent => "invalid event data",
            Self::InvalidConfig => "invalid configuration parameter",
            Self::DeviceNotFound => "input device not found",
            Self::Timeout => "operation timed out",
            Self::InternalError => "internal error",
            Self::QueueShutdown => "queue has been shutdown",
            Self::FilterRejected => "event rejected by filter",
            Self::ResourceExhausted => "resource exhausted",
        }
    }

    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone)]
pub struct InputError {
    code: InputErrorCode,
    context: Option<String>,
    event_type: Option<&'static str>,
    timestamp: u64,
}

impl InputError {
    pub fn new(code: InputErrorCode) -> Self {
        Self {
            code,
            context: None,
            event_type: None,
            timestamp: get_timestamp(),
        }
    }

    pub fn with_context(code: InputErrorCode, context: impl Into<String>) -> Self {
        Self {
            code,
            context: Some(context.into()),
            event_type: None,
            timestamp: get_timestamp(),
        }
    }

    pub fn with_event_type(mut self, event_type: &'static str) -> Self {
        self.event_type = Some(event_type);
        self
    }

    pub const fn code(&self) -> InputErrorCode {
        self.code
    }

    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn log(&self) {
        use core::fmt::Write;

        const LOG_BUFFER_SIZE: usize = 256;
        struct LogBuffer {
            data: [u8; LOG_BUFFER_SIZE],
            pos: usize,
        }

        impl LogBuffer {
            const fn new() -> Self {
                Self {
                    data: [0u8; LOG_BUFFER_SIZE],
                    pos: 0,
                }
            }

            fn as_str(&self) -> &str {
                // SAFETY: we only write valid UTF-8 via fmt::Write
                unsafe { core::str::from_utf8_unchecked(&self.data[..self.pos]) }
            }
        }

        impl core::fmt::Write for LogBuffer {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let remaining = LOG_BUFFER_SIZE - self.pos;
                let to_write = bytes.len().min(remaining);
                if to_write > 0 {
                    self.data[self.pos..self.pos + to_write].copy_from_slice(&bytes[..to_write]);
                    self.pos += to_write;
                }
                Ok(())
            }
        }

        let mut buf = LogBuffer::new();
        let _ = write!(buf, "[INPUT ERR] {}", self.code.as_str());
        if let Some(ref ctx) = self.context {
            let _ = write!(buf, ": {}", ctx);
        }
        if let Some(event_type) = self.event_type {
            let _ = write!(buf, " [{}]", event_type);
        }
        let _ = write!(buf, " @{}\n", self.timestamp);

        crate::arch::x86_64::serial::write_str(buf.as_str());
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(ref ctx) = self.context {
            write!(f, ": {}", ctx)?;
        }
        if let Some(event_type) = self.event_type {
            write!(f, " [event: {}]", event_type)?;
        }
        Ok(())
    }
}

pub type InputResult<T> = Result<T, InputError>;
