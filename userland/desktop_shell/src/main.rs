#![no_std]
#![no_main]

use nonos_libc::{mk_exit, mk_ipc_call, mk_ipc_recv};

pub const SHELL_OP_WALLPAPER_POLICY: u16 = 0x0201;
pub const SHELL_OP_DOCK_POLICY: u16 = 0x0202;
pub const SHELL_OP_MENUBAR_POLICY: u16 = 0x0203;
pub const SHELL_OP_TRAY_POLICY: u16 = 0x0204;
pub const SHELL_OP_SPOTLIGHT_POLICY: u16 = 0x0205;
pub const DESKTOP_SHELL_ENDPOINT: u64 = 0;
pub const COMPOSITOR_ENDPOINT: u64 = 0;

pub const POLICY_MARKER_WALLPAPER: &str = "wallpaper policy owner";
pub const POLICY_MARKER_DOCK: &str = "dock policy owner";
pub const POLICY_MARKER_MENUBAR: &str = "menubar policy owner";
pub const POLICY_MARKER_TRAY: &str = "tray policy owner";
pub const POLICY_MARKER_SPOTLIGHT: &str = "spotlight policy owner";
pub const RENDER_MARKER: &str = "compositor ipc route";

fn _render_via_compositor() {
    let tx = [0u8; 0];
    let mut rx = [0u8; 1];
    let _ = mk_ipc_call(COMPOSITOR_ENDPOINT, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
}

fn _recv_shell_endpoint() {
    let mut buf = [0u8; 1];
    let _ = mk_ipc_recv(DESKTOP_SHELL_ENDPOINT, buf.as_mut_ptr(), buf.len());
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    mk_exit(0);
}
