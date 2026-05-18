use crate::clients::{compositor, desktop_shell, keyring};
use crate::protocol::{Request, E_NOTREADY};
use crate::render;
use crate::server::respond;
use crate::state::Context;

const MSG_LOCKED: &[u8] = b"login:session_locked";

pub fn handle(ctx: &mut Context, sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let key_id = ctx.current_key_id();
    if let Err(errno) = ctx.end_session(sender_pid) {
        let _ = respond::status(sender_pid, req, errno, tx);
        return;
    }
    if let Some(id) = key_id {
        let _ = keyring::lock(ctx.keyring_port, req.request_id, sender_pid, id);
    }
    if desktop_shell::notify_info(ctx.desktop_shell_port, req.request_id, MSG_LOCKED).is_err() {
        let _ = respond::status(sender_pid, req, E_NOTREADY, tx);
        return;
    }
    render::paint_locked(ctx);
    if compositor::ping_damage(ctx.compositor_port, req.request_id).is_err() {
        let _ = respond::status(sender_pid, req, E_NOTREADY, tx);
        return;
    }
    let _ = respond::status(sender_pid, req, 0, tx);
}
