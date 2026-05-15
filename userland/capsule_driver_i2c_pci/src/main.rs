#![no_std]
#![no_main]

extern crate alloc;

use nonos_libc::{heap_init, mk_exit};

mod constants;
mod discover;
mod driver;
mod init;
mod protocol;
mod regs;
mod server;
mod setup;
mod transaction;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let _ = heap_init();
    match setup::run() {
        Ok(driver) => server::run(driver),
        Err(_) => mk_exit(1),
    }
}
