//! 8259A PIC (legacy)

#![no_std]

use x86_64::instructions::port::Port;

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;

const ICW4_8086: u8 = 0x01;

const MASTER_VECTOR_BASE: u8 = 0x20; // 32
const SLAVE_VECTOR_BASE: u8 = 0x28;  // 40

/// Initialize and remap the PIC to vectors 0x20..0x2F, all IRQs masked initially.
pub fn init() {
    unsafe {
        let mut pic1_cmd = Port::<u8>::new(PIC1_CMD);
        let mut pic1_data = Port::<u8>::new(PIC1_DATA);
        let mut pic2_cmd = Port::<u8>::new(PIC2_CMD);
        let mut pic2_data = Port::<u8>::new(PIC2_DATA);

        // Save masks
        let a1 = pic1_data.read();
        let a2 = pic2_data.read();

        // Start initialization
        pic1_cmd.write(ICW1_INIT | ICW1_ICW4);
        pic2_cmd.write(ICW1_INIT | ICW1_ICW4);

        // Set vector offsets
        pic1_data.write(MASTER_VECTOR_BASE);
        pic2_data.write(SLAVE_VECTOR_BASE);

        // Tell Master about Slave at IRQ2 (0000 0100)
        pic1_data.write(0x04);
        // Tell Slave its cascade identity (0000 0010)
        pic2_data.write(0x02);

        // 8086/88 (MCS-80/85) mode
        pic1_data.write(ICW4_8086);
        pic2_data.write(ICW4_8086);

        // Restore masks 
        pic1_data.write(a1);
        pic2_data.write(a2);
    }
}

/// Send End-Of-Interrupt to the PIC for a given IRQ line (0..15).
#[inline]
pub fn eoi(irq: u8) {
    unsafe {
        let mut pic1_cmd = Port::<u8>::new(PIC1_CMD);
        let mut pic2_cmd = Port::<u8>::new(PIC2_CMD);
        if irq >= 8 {
            pic2_cmd.write(0x20);
        }
        pic1_cmd.write(0x20);
    }
}

/// Mask a specific IRQ line (0..15).
pub fn mask_irq(irq: u8) {
    unsafe {
        if irq < 8 {
            let mut data = Port::<u8>::new(PIC1_DATA);
            let cur = data.read();
            data.write(cur | (1 << irq));
        } else {
            let mut data = Port::<u8>::new(PIC2_DATA);
            let cur = data.read();
            data.write(cur | (1 << (irq - 8)));
        }
    }
}

/// Unmask a specific IRQ line (0..15).
pub fn unmask_irq(irq: u8) {
    unsafe {
        if irq < 8 {
            let mut data = Port::<u8>::new(PIC1_DATA);
            let cur = data.read();
            data.write(cur & !(1 << irq));
        } else {
            let mut data = Port::<u8>::new(PIC2_DATA);
            let cur = data.read();
            data.write(cur & !(1 << (irq - 8)));
        }
    }
}

/// Mask all IRQ lines on both PICs.
pub fn mask_all() {
    unsafe {
        Port::<u8>::new(PIC1_DATA).write(0xFF);
        Port::<u8>::new(PIC2_DATA).write(0xFF);
    }
}
