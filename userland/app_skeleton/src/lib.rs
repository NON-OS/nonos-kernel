#![no_std]

use nonos_libc::{mk_debug, mk_exit, mk_ipc_call, mk_ipc_recv, mk_yield};

const ENOTSUP: i64 = -95;

pub fn run(marker_prefix: &[u8], app_endpoint: u64, toolkit_endpoint: u64, ui_op: u8) -> ! {
    marker(marker_prefix, b"app ui owner");
    let req = [ui_op];
    let mut resp = [0u8; 16];
    let _ = mk_ipc_call(toolkit_endpoint, req.as_ptr(), req.len(), resp.as_mut_ptr(), resp.len());
    marker(marker_prefix, b"toolkit ui route");
    let mut msg = [0u8; 256];
    loop {
        let rc = mk_ipc_recv(app_endpoint, msg.as_mut_ptr(), msg.len(), 0);
        if rc == ENOTSUP {
            marker(marker_prefix, b"ipc parked");
            mk_exit(0);
        }
        if rc < 0 {
            let _ = mk_yield();
            continue;
        }
        let _ = mk_yield();
    }
}

fn marker(prefix: &[u8], stage: &[u8]) {
    let mut buf = [0u8; 96];
    let mut n = 0usize;
    for &b in prefix.iter().chain(stage.iter()) {
        if n >= buf.len() - 1 {
            break;
        }
        buf[n] = b;
        n += 1;
    }
    buf[n] = b'\n';
    n += 1;
    let _ = mk_debug(buf.as_ptr(), n);
}
