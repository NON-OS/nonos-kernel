use crate::clients::{compositor, desktop_shell, keyring};
use crate::protocol::{Request, E_INVAL, E_NOTREADY, START_SESSION_REQ_LEN};
use crate::render;
use crate::server::respond;
use crate::state::Context;

const MSG_UNLOCKED: &[u8] = b"login:session_unlocked";

pub fn handle(ctx: &mut Context, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != START_SESSION_REQ_LEN {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let Some(key_id) =
        body.get(0..4).and_then(|bytes| bytes.try_into().ok()).map(u32::from_le_bytes)
    else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    if let Err(errno) = keyring::unlock(ctx.keyring_port, req.request_id, sender_pid, key_id) {
        let _ = respond::status(sender_pid, req, errno, tx);
        return;
    }
    let serial = match ctx.start_session(sender_pid, key_id) {
        Ok(v) => v,
        Err(errno) => {
            let _ = respond::status(sender_pid, req, errno, tx);
            return;
        }
    };
    if desktop_shell::notify_info(ctx.desktop_shell_port, req.request_id ^ serial, MSG_UNLOCKED)
        .is_err()
    {
        let _ = ctx.end_session(sender_pid);
        let _ = keyring::lock(ctx.keyring_port, req.request_id ^ serial, sender_pid, key_id);
        let _ = respond::status(sender_pid, req, E_NOTREADY, tx);
        return;
    }
    render::paint_unlocked(ctx);
    if compositor::ping_damage(ctx.compositor_port, req.request_id ^ serial).is_err() {
        let _ = ctx.end_session(sender_pid);
        let _ = keyring::lock(ctx.keyring_port, req.request_id ^ serial, sender_pid, key_id);
        let _ = respond::status(sender_pid, req, E_NOTREADY, tx);
        return;
    }
    let _ = respond::status(sender_pid, req, 0, tx);
}
