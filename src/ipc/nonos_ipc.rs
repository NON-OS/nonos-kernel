//! NonosOS specific IPC implementation

use alloc::vec::Vec;

pub enum NonosMessageType {
    Data,
    Control,
}

pub fn send_ipc_message(
    _dest_process_id: u64,
    _channel_id: u32,
    _message: &[u8],
    _message_type: NonosMessageType,
) -> Result<(), &'static str> {
    // Stub implementation
    Ok(())
}

pub fn receive_ipc_message(
    _process_id: u64,
    _channel_id: u32,
) -> Result<Vec<u8>, &'static str> {
    // Stub implementation
    Ok(Vec::new())
}
