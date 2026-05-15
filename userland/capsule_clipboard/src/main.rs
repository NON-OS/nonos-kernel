#![no_std]
#![no_main]

extern crate alloc;

mod protocol;
mod server;
mod state;

use nonos_libc::{heap_init, mk_exit};

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    if heap_init().is_err() {
        mk_exit(1);
    }
    server::run();
}
