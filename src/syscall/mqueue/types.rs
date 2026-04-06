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

use alloc::vec::Vec;

pub const MQ_PRIO_MAX: u32 = 32768;
pub const MQ_MAXMSG_DEFAULT: i64 = 10;
pub const MQ_MSGSIZE_DEFAULT: i64 = 8192;
pub const MQ_MAXMSG_LIMIT: i64 = 65536;
pub const MQ_MSGSIZE_LIMIT: i64 = 16777216;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MqAttr {
    pub mq_flags: i64,
    pub mq_maxmsg: i64,
    pub mq_msgsize: i64,
    pub mq_curmsgs: i64,
    pub __reserved: [i64; 4],
}

#[derive(Debug, Clone)]
pub struct MqMessage {
    pub data: Vec<u8>,
    pub priority: u32,
}

impl MqAttr {
    pub fn new(maxmsg: i64, msgsize: i64) -> Self {
        Self {
            mq_flags: 0,
            mq_maxmsg: maxmsg,
            mq_msgsize: msgsize,
            mq_curmsgs: 0,
            __reserved: [0; 4],
        }
    }

    pub fn validate(&self) -> Result<(), i32> {
        if self.mq_maxmsg <= 0 || self.mq_maxmsg > MQ_MAXMSG_LIMIT {
            return Err(22);
        }
        if self.mq_msgsize <= 0 || self.mq_msgsize > MQ_MSGSIZE_LIMIT {
            return Err(22);
        }
        Ok(())
    }
}

impl MqMessage {
    pub fn new(data: Vec<u8>, priority: u32) -> Self {
        Self { data, priority }
    }
}

impl Ord for MqMessage {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other.priority.cmp(&self.priority)
    }
}

impl PartialOrd for MqMessage {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MqMessage {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for MqMessage {}
