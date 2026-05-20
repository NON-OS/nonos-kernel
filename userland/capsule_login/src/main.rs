#![no_std]
#![no_main]

extern crate alloc;

mod clients;
mod debug;
mod protocol;
mod render;
mod server;
mod setup;
mod state;

use nonos_libc::{heap_init, mk_exit, mk_yield};

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    if heap_init().is_err() {
        mk_exit(1);
    }
    debug::marker(b"boot");
    let ctx = wait_for_setup();
    debug::marker(b"setup complete");
    server::run(ctx);
}

fn wait_for_setup() -> crate::state::Context {
    let mut reported = false;
    loop {
        if let Ok(ctx) = setup::run() {
            return ctx;
        }
        if !reported {
            debug::marker(b"setup waiting");
            reported = true;
        }
        for _ in 0..64 {
            mk_yield();
        }
    }
}
