use alloc::vec;
use alloc::vec::Vec;

use nonos_libc::mk_ipc_call;

const MAGIC: u32 = 0x4E43_4D50;
const VERSION: u16 = 1;
const HDR_LEN: usize = 20;
const OP_DAMAGE_COMMIT: u16 = 0x0003;
const DAMAGE_REQ_LEN: usize = 16;

pub fn ping_damage(port: u32, request_id: u32) -> Result<(), i32> {
    let mut tx = Vec::with_capacity(HDR_LEN + DAMAGE_REQ_LEN);
    tx.extend_from_slice(&MAGIC.to_le_bytes());
    tx.extend_from_slice(&VERSION.to_le_bytes());
    tx.extend_from_slice(&OP_DAMAGE_COMMIT.to_le_bytes());
    tx.extend_from_slice(&0u16.to_le_bytes());
    tx.extend_from_slice(&0u16.to_le_bytes());
    tx.extend_from_slice(&request_id.to_le_bytes());
    tx.extend_from_slice(&(DAMAGE_REQ_LEN as u32).to_le_bytes());
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.extend_from_slice(&1u32.to_le_bytes());
    tx.extend_from_slice(&1u32.to_le_bytes());

    let mut rx = vec![0u8; HDR_LEN + 4];
    let rc = mk_ipc_call(port as u64, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
    if rc < (HDR_LEN + 4) as i64 {
        return Err(-11);
    }
    let status = i32::from_le_bytes(rx[HDR_LEN..HDR_LEN + 4].try_into().unwrap());
    if status == 0 {
        Ok(())
    } else {
        Err(status)
    }
}
