#![no_std]
#![no_main]

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    nonos_app_skeleton::run(b"[calculator] ", 4720, 4610, 2)
}
