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

//! Envelope builder.

extern crate alloc;

use alloc::{string::String, vec::Vec};

use super::envelope::IpcEnvelope;
use super::types::{MessageError, MessageType, SecurityLevel};

/// Builder for constructing IPC envelopes
pub struct EnvelopeBuilder {
    from: String,
    to: String,
    message_type: MessageType,
    data: Vec<u8>,
    session_id: Option<u64>,
    sec_level: SecurityLevel,
}

impl EnvelopeBuilder {
    /// Create a new builder
    pub fn new(from: &str, to: &str) -> Self {
        Self {
            from: String::from(from),
            to: String::from(to),
            message_type: MessageType::Data,
            data: Vec::new(),
            session_id: None,
            sec_level: SecurityLevel::None,
        }
    }

    /// Set message type
    pub fn message_type(mut self, msg_type: MessageType) -> Self {
        self.message_type = msg_type;
        self
    }

    /// Set payload data
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Set payload from bytes
    pub fn data_from_slice(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Set session ID
    pub fn session_id(mut self, id: u64) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Set security level
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.sec_level = level;
        self
    }

    /// Build the envelope
    pub fn build(self) -> IpcEnvelope {
        IpcEnvelope {
            from: self.from,
            to: self.to,
            message_type: self.message_type,
            data: self.data,
            timestamp: crate::time::timestamp_millis(),
            session_id: self.session_id,
            sec_level: self.sec_level,
        }
    }

    /// Build and validate the envelope
    pub fn build_validated(self) -> Result<IpcEnvelope, MessageError> {
        let envelope = self.build();
        envelope.validate()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_builder() {
        let env = EnvelopeBuilder::new("a", "b")
            .message_type(MessageType::Request)
            .data(alloc::vec![42])
            .session_id(123)
            .security_level(SecurityLevel::Signed)
            .build();

        assert_eq!(env.from, "a");
        assert_eq!(env.to, "b");
        assert_eq!(env.message_type, MessageType::Request);
        assert_eq!(env.data, alloc::vec![42]);
        assert_eq!(env.session_id, Some(123));
        assert_eq!(env.sec_level, SecurityLevel::Signed);
    }
}
