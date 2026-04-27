extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    ReservedLocal,
    ReservedRemote,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

pub struct Stream {
    pub id: u32,
    pub state: StreamState,
    pub send_window: i32,
    pub recv_window: i32,
    pub recv_data: Vec<u8>,
    pub recv_headers: Vec<(alloc::string::String, alloc::string::String)>,
}

impl Stream {
    pub fn new(id: u32, initial_window: i32) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            send_window: initial_window,
            recv_window: initial_window,
            recv_data: Vec::new(),
            recv_headers: Vec::new(),
        }
    }

    pub fn open(&mut self) {
        self.state = StreamState::Open;
    }

    pub fn half_close_local(&mut self) {
        if self.state == StreamState::Open {
            self.state = StreamState::HalfClosedLocal;
        } else if self.state == StreamState::HalfClosedRemote {
            self.state = StreamState::Closed;
        }
    }

    pub fn half_close_remote(&mut self) {
        if self.state == StreamState::Open {
            self.state = StreamState::HalfClosedRemote;
        } else if self.state == StreamState::HalfClosedLocal {
            self.state = StreamState::Closed;
        }
    }

    pub fn reset(&mut self) {
        self.state = StreamState::Closed;
    }

    pub fn consume_send_window(&mut self, amount: i32) -> bool {
        if self.send_window >= amount {
            self.send_window -= amount;
            true
        } else {
            false
        }
    }

    pub fn update_recv_window(&mut self, increment: i32) {
        self.recv_window += increment;
    }
}
