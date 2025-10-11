//! TCP public types; by smoltcp in nonos_stack

#![no_std]

#[derive(Debug, Clone)]
pub struct TcpSocket {
    id: u32,
    pub remote_port: u16,
}

impl TcpSocket {
    pub fn new() -> Self {
        Self { id: next_id(), remote_port: 0 }
    }
    pub fn connection_id(&self) -> u32 { self.id }
    pub fn from_connection(id: u32) -> Self { Self { id, remote_port: 0 } }
}

use core::sync::atomic::{AtomicU32, Ordering};
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
fn next_id() -> u32 { NEXT_ID.fetch_add(1, Ordering::SeqCst) }

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}
pub const TCP_SYN: u8 = 0x02;

#[derive(Debug)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    Established,
}

#[derive(Debug, Clone)]
pub struct TcpConnection;
