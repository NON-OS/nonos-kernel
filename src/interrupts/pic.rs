//! 8259 PIC (Programmable Interrupt Controller) Driver
//!
//! Manages hardware interrupts from legacy devices

use x86_64::instructions::port::Port;

/// PIC ports
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// PIC commands
const PIC_EOI: u8 = 0x20;
const ICW1_ICW4: u8 = 0x01;
const ICW1_SINGLE: u8 = 0x02;
const ICW1_INTERVAL4: u8 = 0x04;
const ICW1_LEVEL: u8 = 0x08;
const ICW1_INIT: u8 = 0x10;

const ICW4_8086: u8 = 0x01;
const ICW4_AUTO: u8 = 0x02;
const ICW4_BUF_SLAVE: u8 = 0x08;
const ICW4_BUF_MASTER: u8 = 0x0C;
const ICW4_SFNM: u8 = 0x10;

/// PIC controller structure
pub struct Pic {
    offset: u8,
    command: Port<u8>,
    data: Port<u8>,
}

impl Pic {
    const fn new(offset: u8, command_port: u16, data_port: u16) -> Pic {
        Pic { offset, command: Port::new(command_port), data: Port::new(data_port) }
    }

    /// Check if this PIC handles the given interrupt
    fn handles_interrupt(&self, interrupt_id: u8) -> bool {
        interrupt_id >= self.offset && interrupt_id < self.offset + 8
    }

    /// Send end-of-interrupt signal
    fn end_of_interrupt(&mut self) {
        unsafe {
            self.command.write(PIC_EOI);
        }
    }

    /// Read interrupt mask
    fn read_mask(&mut self) -> u8 {
        unsafe { self.data.read() }
    }

    /// Write interrupt mask
    fn write_mask(&mut self, mask: u8) {
        unsafe {
            self.data.write(mask);
        }
    }
}

/// Chained PIC configuration
pub struct ChainedPics {
    pics: [Pic; 2],
}

impl ChainedPics {
    /// Create new chained PIC configuration
    pub const fn new(offset1: u8, offset2: u8) -> ChainedPics {
        ChainedPics {
            pics: [
                Pic::new(offset1, PIC1_COMMAND, PIC1_DATA),
                Pic::new(offset2, PIC2_COMMAND, PIC2_DATA),
            ],
        }
    }

    /// Initialize the PICs
    pub fn initialize(&mut self) {
        unsafe {
            // Save masks
            let mask1 = self.pics[0].data.read();
            let mask2 = self.pics[1].data.read();

            // Start initialization sequence
            self.pics[0].command.write(ICW1_INIT | ICW1_ICW4);
            io_wait();
            self.pics[1].command.write(ICW1_INIT | ICW1_ICW4);
            io_wait();

            // Set vector offsets
            self.pics[0].data.write(self.pics[0].offset);
            io_wait();
            self.pics[1].data.write(self.pics[1].offset);
            io_wait();

            // Configure cascade
            self.pics[0].data.write(4); // PIC2 at IRQ2
            io_wait();
            self.pics[1].data.write(2); // Cascade identity
            io_wait();

            // Set 8086 mode
            self.pics[0].data.write(ICW4_8086);
            io_wait();
            self.pics[1].data.write(ICW4_8086);
            io_wait();

            // Restore masks
            self.pics[0].data.write(mask1);
            self.pics[1].data.write(mask2);
        }
    }

    /// Disable all interrupts
    pub fn disable_all(&mut self) {
        unsafe {
            self.pics[0].data.write(0xFF);
            self.pics[1].data.write(0xFF);
        }
    }

    /// Enable specific interrupt
    pub fn enable_interrupt(&mut self, interrupt_id: u8) {
        if self.pics[0].handles_interrupt(interrupt_id) {
            let irq = interrupt_id - self.pics[0].offset;
            let mask = self.pics[0].read_mask() & !(1 << irq);
            self.pics[0].write_mask(mask);
        } else if self.pics[1].handles_interrupt(interrupt_id) {
            let irq = interrupt_id - self.pics[1].offset;
            let mask = self.pics[1].read_mask() & !(1 << irq);
            self.pics[1].write_mask(mask);
        }
    }

    /// Disable specific interrupt
    pub fn disable_interrupt(&mut self, interrupt_id: u8) {
        if self.pics[0].handles_interrupt(interrupt_id) {
            let irq = interrupt_id - self.pics[0].offset;
            let mask = self.pics[0].read_mask() | (1 << irq);
            self.pics[0].write_mask(mask);
        } else if self.pics[1].handles_interrupt(interrupt_id) {
            let irq = interrupt_id - self.pics[1].offset;
            let mask = self.pics[1].read_mask() | (1 << irq);
            self.pics[1].write_mask(mask);
        }
    }

    /// Send end-of-interrupt
    pub fn notify_end_of_interrupt(&mut self, interrupt_id: u8) {
        if self.pics[1].handles_interrupt(interrupt_id) {
            self.pics[1].end_of_interrupt();
        }
        if self.pics[0].handles_interrupt(interrupt_id) {
            self.pics[0].end_of_interrupt();
        }
    }
}

static mut PICS: ChainedPics = ChainedPics::new(0x20, 0x28);

/// Initialize PIC
pub fn init() {
    unsafe {
        PICS.initialize();

        // Enable timer and keyboard interrupts initially
        PICS.enable_interrupt(0x20); // Timer
        PICS.enable_interrupt(0x21); // Keyboard
    }
}

/// Send end-of-interrupt signal
pub fn end_of_interrupt(interrupt_id: u8) {
    unsafe {
        PICS.notify_end_of_interrupt(interrupt_id);
    }
}

/// Enable interrupt
pub fn enable_interrupt(interrupt_id: u8) {
    unsafe {
        PICS.enable_interrupt(interrupt_id);
    }
}

/// Disable interrupt
pub fn disable_interrupt(interrupt_id: u8) {
    unsafe {
        PICS.disable_interrupt(interrupt_id);
    }
}

/// I/O wait function for timing
fn io_wait() {
    unsafe {
        Port::new(0x80).write(0u8);
    }
}
