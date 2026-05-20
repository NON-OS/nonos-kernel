use crate::protocol::{TRANSFER_READ_MAX, TRANSFER_WRITE_MAX};

#[derive(Clone, Copy)]
pub enum TransferError {
    Busy,
    Timeout,
    Nack,
    Invalid,
}

pub const FLAG_RESTART_ON_READ: u16 = 1 << 0;

pub struct TransferRequest<'a> {
    pub addr: u8,
    pub flags: u16,
    pub write: &'a [u8],
    pub read_len: usize,
}

pub struct TransferResult {
    pub read: [u8; TRANSFER_READ_MAX],
    pub read_len: usize,
    pub abort_source: u32,
}

impl TransferResult {
    pub const fn empty() -> Self {
        Self { read: [0; TRANSFER_READ_MAX], read_len: 0, abort_source: 0 }
    }
}

pub fn valid_lengths(write_len: usize, read_len: usize) -> bool {
    write_len <= TRANSFER_WRITE_MAX && read_len <= TRANSFER_READ_MAX
}
