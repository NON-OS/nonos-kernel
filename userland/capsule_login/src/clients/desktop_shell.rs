use alloc::vec;
use alloc::vec::Vec;

use nonos_libc::mk_ipc_call;

const MAGIC: u32 = 0x4E44_5348;
const VERSION: u16 = 1;
const HDR_LEN: usize = 20;
const OP_NOTIFY: u16 = 0x0005;
const NOTIFY_BODY_MAX: usize = 128;
const NOTIFY_REQ_LEN: usize = 8 + NOTIFY_BODY_MAX;

pub fn notify_info(port: u32, request_id: u32, msg: &[u8]) -> Result<(), i32> {
    let mut body = [0u8; NOTIFY_REQ_LEN];
    let n = core::cmp::min(msg.len(), NOTIFY_BODY_MAX);
    body[0..4].copy_from_slice(&0u32.to_le_bytes());
    body[4..8].copy_from_slice(&(n as u32).to_le_bytes());
    body[8..8 + n].copy_from_slice(&msg[..n]);

    let mut tx = Vec::with_capacity(HDR_LEN + NOTIFY_REQ_LEN);
    tx.extend_from_slice(&MAGIC.to_le_bytes());
    tx.extend_from_slice(&VERSION.to_le_bytes());
    tx.extend_from_slice(&OP_NOTIFY.to_le_bytes());
    tx.extend_from_slice(&0u16.to_le_bytes());
    tx.extend_from_slice(&0u16.to_le_bytes());
    tx.extend_from_slice(&request_id.to_le_bytes());
    tx.extend_from_slice(&(NOTIFY_REQ_LEN as u32).to_le_bytes());
    tx.extend_from_slice(&body);

    let mut rx = vec![0u8; HDR_LEN + 4];
    let rc = mk_ipc_call(port as u64, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
    if rc < (HDR_LEN + 4) as i64 {
        return Err(-11);
    }
    let status = i32::from_le_bytes(rx[HDR_LEN..HDR_LEN + 4].try_into().map_err(|_| -11)?);
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}
