use nonos_libc::{mk_device_release, mk_irq_bind, mk_mmio_unmap, IrqBindOut, MmioMapOut};

use crate::discover::Found;

pub fn bind(dev: Found, claim_epoch: u64, mmio: &MmioMapOut) -> Result<IrqBindOut, &'static str> {
    let mut out = IrqBindOut { grant_id: 0, vector: 0 };
    let r = mk_irq_bind(dev.device_id, claim_epoch, dev.irq_line as u32, 0, 0, &mut out);
    if r < 0 {
        let _ = mk_mmio_unmap(mmio.grant_id);
        let _ = mk_device_release(dev.device_id);
        Err("i2c-pci: irq bind failed")
    } else {
        Ok(out)
    }
}

