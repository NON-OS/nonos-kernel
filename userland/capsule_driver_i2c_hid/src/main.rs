#![no_std]
#![no_main]

extern crate alloc;

use nonos_libc::{heap_init, mk_exit};

mod hid;
mod i2c_client;
mod protocol;
mod server;
mod setup;
mod state;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if heap_init().is_err() {
        mk_exit(1);
    }
    match setup::run() {
        Ok(state) => server::run(state),
        Err(_) => mk_exit(1),
    }
}
