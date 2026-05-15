#![no_std]
#![no_main]

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    nonos_app_skeleton::run(b"[settings] ", 4728, 4610, 6)
}
