use alloc::vec;

use nonos_libc::{mk_ipc_recv_from, mk_yield};

use crate::protocol::{
    parse, E_BAD_OP, E_INVAL, HDR_LEN, IPC_PAYLOAD_MAX, MAX_DEPTH, MAX_TOTAL_BYTES,
    OP_CLEAR, OP_COPY, OP_HEALTHCHECK, OP_HISTORY_GET, OP_HISTORY_LIST, OP_PASTE,
};
use crate::server::{handlers, respond};
use crate::state::Clipboard;

const SERVICE_INBOX: u64 = 0;
const RECV_NOWAIT: u64 = 1;

pub fn run() -> ! {
    let mut state = Clipboard::new(MAX_DEPTH, MAX_TOTAL_BYTES);
    let mut rx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut tx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    loop {
        if !drain(&mut state, &mut rx, &mut tx) {
            let _ = mk_yield();
        }
    }
}

fn drain(state: &mut Clipboard, rx: &mut [u8], tx: &mut [u8]) -> bool {
    let mut did = false;
    loop {
        let mut sender_pid = 0u32;
        let n = mk_ipc_recv_from(SERVICE_INBOX, rx.as_mut_ptr(), rx.len(), RECV_NOWAIT, &mut sender_pid);
        if n <= 0 || sender_pid == 0 {
            return did;
        }
        did = true;
        let (req, body) = match parse(&rx[..n as usize]) {
            Ok(v) => v,
            Err((req, errno)) => { let _ = respond::status(sender_pid, &req, errno, tx); continue; }
        };
        match req.op {
            OP_HEALTHCHECK if body.is_empty() => handlers::health::handle(sender_pid, &req, tx),
            OP_COPY => handlers::copy::handle(state, sender_pid, &req, body, tx),
            OP_PASTE => handlers::paste::handle(state, sender_pid, &req, body, tx),
            OP_HISTORY_LIST => handlers::history_list::handle(state, sender_pid, &req, body, tx),
            OP_HISTORY_GET => handlers::history_get::handle(state, sender_pid, &req, body, tx),
            OP_CLEAR => handlers::clear::handle(state, sender_pid, &req, body, tx),
            _ if body.is_empty() => { let _ = respond::status(sender_pid, &req, E_BAD_OP, tx); }
            _ => { let _ = respond::status(sender_pid, &req, E_INVAL, tx); }
        }
    }
}
