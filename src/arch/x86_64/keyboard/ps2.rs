//! PS/2 Keyboard Controller Support 

use crate::arch::x86_64::port::{inb, outb};
use crate::arch::x86_64::keyboard::input::{push_event, InputEvent};
use crate::arch::x86_64::keyboard::mod::{handle_keyboard_interrupt};

/// PS/2 controller ports
const PS2_DATA_PORT: u16 = 0x60;
const PS2_STATUS_PORT: u16 = 0x64;
const PS2_CMD_PORT: u16 = 0x64;

/// Initialize PS/2 controller and enable keyboard IRQ.
pub fn init_ps2() {
    unsafe {
        // Enable keyboard IRQ (IRQ1) in PIC
        let mut mask = inb(0x21);
        mask &= !0x02;
        outb(0x21, mask);

        // Enable PS/2 interface (write command 0xAE to command port)
        outb(PS2_CMD_PORT, 0xAE);
    }
}

/// Handle PS/2 keyboard interrupt (IRQ1).
pub fn handle_ps2_interrupt() {
    let scan_code = unsafe { inb(PS2_DATA_PORT) };

    // Call the generic keyboard handler for scan code translation and event publishing.
    handle_keyboard_interrupt();

    // Push raw scan code event for low-level diagnostics.
    push_event(InputEvent::KeyPress(scan_code));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_ps2_no_panic() {
        // Test checks that init_ps2 does not panic.
        init_ps2();
    }

    #[test]
    fn test_handle_ps2_interrupt_no_panic() {
        // Checks that handle_ps2_interrupt does not panic.
        handle_ps2_interrupt();
    }
}
