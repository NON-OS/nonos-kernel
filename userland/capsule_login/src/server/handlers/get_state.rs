use crate::protocol::{Request, HDR_LEN, STATE_PAYLOAD_LEN, STATUS_LEN};
use crate::server::respond;
use crate::state::Context;

pub fn handle(ctx: &Context, sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let (state, owner_pid, key_token) = ctx.state_words();
    let off = HDR_LEN + STATUS_LEN;
    tx[off..off + 4].copy_from_slice(&state.to_le_bytes());
    tx[off + 4..off + 8].copy_from_slice(&owner_pid.to_le_bytes());
    tx[off + 8..off + 12].copy_from_slice(&key_token.to_le_bytes());
    let _ = respond::payload(sender_pid, req, STATE_PAYLOAD_LEN, tx);
}
