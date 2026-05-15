#![no_std]
#![no_main]

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    nonos_app_skeleton::run(b"[text_editor] ", 4726, 4610, 5)
}
