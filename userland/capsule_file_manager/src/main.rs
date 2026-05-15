#![no_std]
#![no_main]

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    nonos_app_skeleton::run(b"[file_manager] ", 4724, 4610, 4)
}
