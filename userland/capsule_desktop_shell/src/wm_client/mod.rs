use alloc::vec;
use alloc::vec::Vec;

use nonos_libc::mk_ipc_call;

const MAGIC: u32 = 0x4E57_4D50;
const VERSION: u16 = 1;
const HDR_LEN: usize = 20;
const STATUS_LEN: usize = 4;
const OP_HEALTHCHECK: u16 = 0x0001;

pub fn healthcheck(port: u32, request_id: u32) -> Result<i32, &'static str> {
    let mut tx = Vec::with_capacity(HDR_LEN);
    tx.extend_from_slice(&MAGIC.to_le_bytes());
    tx.extend_from_slice(&VERSION.to_le_bytes());
    tx.extend_from_slice(&OP_HEALTHCHECK.to_le_bytes());
    tx.extend_from_slice(&0u16.to_le_bytes());
    tx.extend_from_slice(&0u16.to_le_bytes());
    tx.extend_from_slice(&request_id.to_le_bytes());
    tx.extend_from_slice(&0u32.to_le_bytes());

    let mut rx = vec![0u8; HDR_LEN + STATUS_LEN];
    let rc = mk_ipc_call(port as u64, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
    if rc < (HDR_LEN + STATUS_LEN) as i64 {
        return Err("wm call failed");
    }
    Ok(i32::from_le_bytes(
        rx[HDR_LEN..HDR_LEN + STATUS_LEN].try_into().map_err(|_| "wm short response")?,
    ))
}
