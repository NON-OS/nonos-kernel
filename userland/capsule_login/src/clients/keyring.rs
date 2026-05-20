use alloc::vec;
use alloc::vec::Vec;

use nonos_libc::mk_ipc_call;

const HDR_LEN: usize = 8;
const STATUS_LEN: usize = 4;
const OP_LOCK: u16 = 4;
const OP_UNLOCK: u16 = 5;

fn call(port: u32, op: u16, request_id: u32, caller_pid: u32, key_id: u32) -> Result<i32, i32> {
    let mut tx = Vec::with_capacity(HDR_LEN + 8);
    tx.extend_from_slice(&request_id.to_le_bytes());
    tx.extend_from_slice(&op.to_le_bytes());
    tx.extend_from_slice(&0u16.to_le_bytes());
    tx.extend_from_slice(&caller_pid.to_le_bytes());
    tx.extend_from_slice(&key_id.to_le_bytes());

    let mut rx = vec![0u8; HDR_LEN + STATUS_LEN];
    let rc = mk_ipc_call(port as u64, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
    if rc < (HDR_LEN + STATUS_LEN) as i64 {
        return Err(-11);
    }
    Ok(i32::from_le_bytes(rx[4..8].try_into().map_err(|_| -11)?))
}

pub fn unlock(port: u32, request_id: u32, caller_pid: u32, key_id: u32) -> Result<(), i32> {
    let status = call(port, OP_UNLOCK, request_id, caller_pid, key_id)?;
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}

pub fn lock(port: u32, request_id: u32, caller_pid: u32, key_id: u32) -> Result<(), i32> {
    let status = call(port, OP_LOCK, request_id, caller_pid, key_id)?;
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}
