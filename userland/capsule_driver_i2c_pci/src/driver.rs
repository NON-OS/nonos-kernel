use crate::regs::Regs;

pub struct Driver {
    pub device_id: u64,
    pub pci_device: u16,
    pub claim_epoch: u64,
    pub mmio_grant: u64,
    pub irq_grant: u64,
    pub irq_vector: u64,
    pub clock_hz: u32,
    pub family: &'static str,
    pub comp_type: u32,
    pub comp_param: u32,
    pub enabled: u32,
    pub status: u32,
    pub regs: Regs,
}
