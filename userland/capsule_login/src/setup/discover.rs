use nonos_libc::mk_service_lookup;

const KEYRING_SERVICE: &[u8] = b"keyring";
const DESKTOP_SHELL_SERVICE: &[u8] = b"desktop_shell";
const COMPOSITOR_SERVICE: &[u8] = b"compositor";

fn lookup_port(name: &[u8]) -> Result<u32, &'static str> {
    let mut pid: u32 = 0;
    let mut port: u32 = 0;
    let rc = mk_service_lookup(
        name.as_ptr(),
        name.len(),
        &mut port as *mut u32,
        &mut pid as *mut u32,
    );
    if rc < 0 || pid == 0 || port == 0 {
        return Err("service lookup failed");
    }
    Ok(port)
}

pub fn lookup_keyring_port() -> Result<u32, &'static str> {
    lookup_port(KEYRING_SERVICE)
}

pub fn lookup_desktop_shell_port() -> Result<u32, &'static str> {
    lookup_port(DESKTOP_SHELL_SERVICE)
}

pub fn lookup_compositor_port() -> Result<u32, &'static str> {
    lookup_port(COMPOSITOR_SERVICE)
}
