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


pub const TCP_SYN: u8 = 0x02;

pub const TCP_ACK: u8 = 0x10;

pub const TCP_FIN: u8 = 0x01;

pub const TCP_RST: u8 = 0x04;

pub const TCP_PSH: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    pub fn is_established(&self) -> bool {
        *self == TcpState::Established
    }

    pub fn is_closed(&self) -> bool {
        *self == TcpState::Closed
    }
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub const MIN_SIZE: usize = 20;

    pub fn is_syn(&self) -> bool {
        self.flags & TCP_SYN != 0
    }

    pub fn is_ack(&self) -> bool {
        self.flags & TCP_ACK != 0
    }

    pub fn is_fin(&self) -> bool {
        self.flags & TCP_FIN != 0
    }

    pub fn is_rst(&self) -> bool {
        self.flags & TCP_RST != 0
    }
}

#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_addr: [u8; 4],
}

impl TcpConnection {
    pub fn new() -> Self {
        Self {
            state: TcpState::Closed,
            local_port: 0,
            remote_port: 0,
            remote_addr: [0; 4],
        }
    }
}

impl Default for TcpConnection {
    fn default() -> Self {
        Self::new()
    }
}
