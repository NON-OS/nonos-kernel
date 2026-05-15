use nonos_libc::mk_service_lookup;

pub fn resolve() -> Option<(u32, u32)> {
    let name = b"driver.i2c_pci0";
    let mut port = 0u32;
    let mut pid = 0u32;
    let r = mk_service_lookup(name.as_ptr(), name.len(), &mut port, &mut pid);
    if r < 0 || port == 0 || pid == 0 {
        None
    } else {
        Some((port, pid))
    }
}

