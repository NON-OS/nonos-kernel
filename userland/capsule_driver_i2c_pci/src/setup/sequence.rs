use nonos_libc::mk_irq_ack;

use super::{claim, irq, mmio};
use crate::discover::find_controller;
use crate::driver::Driver;
use crate::init::bring_up;
use crate::regs::Regs;

pub fn run() -> Result<Driver, &'static str> {
    let dev = find_controller().ok_or("i2c-pci: controller not found")?;
    let claim_epoch = claim::claim(dev.device_id)?;
    let mmio = mmio::map(dev, claim_epoch)?;
    let irq = irq::bind(dev, claim_epoch, &mmio)?;
    let regs = Regs::new(mmio.user_va);
    let init = bring_up(regs)?;
    let _ = mk_irq_ack(irq.grant_id);
    Ok(Driver {
        device_id: dev.device_id,
        pci_device: dev.pci_device,
        claim_epoch,
        mmio_grant: mmio.grant_id,
        irq_grant: irq.grant_id,
        irq_vector: irq.vector,
        clock_hz: dev.clock_hz,
        family: dev.family,
        comp_type: init.comp_type,
        comp_param: init.comp_param,
        enabled: init.enabled,
        status: init.status,
        regs,
    })
}
