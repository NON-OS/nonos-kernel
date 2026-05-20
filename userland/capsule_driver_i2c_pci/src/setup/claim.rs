use nonos_libc::mk_device_claim;

pub fn claim(device_id: u64) -> Result<u64, &'static str> {
    let epoch = mk_device_claim(device_id);
    if epoch <= 0 {
        Err("i2c-pci: device claim failed")
    } else {
        Ok(epoch as u64)
    }
}
