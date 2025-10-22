//! PS/2 Keyboard Driver 

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::hint::spin_loop;

// Ports
const KBD_DATA: u16 = 0x60;
const KBD_STATUS: u16 = 0x64;
const KBD_CMD: u16 = 0x64;

// Commands
const CMD_READ_CFG: u8 = 0x20;
const CMD_WRITE_CFG: u8 = 0x60;

// Keyboard device commands (send to 0x60)
const KBD_ENABLE_SCANNING: u8 = 0xF4;
const KBD_SET_LEDS: u8 = 0xED;

// IRQ1 vector (typical PIC remap to 0x20..0x2F => 0x21 for IRQ1)
const KBD_VECTOR: u8 = 0x21;

// Modifiers
static SHIFT: AtomicBool = AtomicBool::new(false);
static CTRL: AtomicBool = AtomicBool::new(false);
static ALT: AtomicBool = AtomicBool::new(false);
static CAPS: AtomicBool = AtomicBool::new(false);

// Extended prefix
const SC_EXT_E0: u8 = 0xE0;
const SC_EXT_E1: u8 = 0xE1;
static EXTENDED: AtomicBool = AtomicBool::new(false);

// Lock-free SPSC ring buffer (power-of-two size)
struct SpscU8Ring<const N: usize> {
    buf: [u8; N],
    head: AtomicUsize,
    tail: AtomicUsize,
}
impl<const N: usize> SpscU8Ring<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }
    #[inline]
    fn mask() -> usize {
        N - 1
    }
    #[inline]
    fn push(&self, byte: u8) {
        let head = self.head.load(Ordering::Relaxed);
        let next = (head.wrapping_add(1)) & Self::mask();
        let tail = self.tail.load(Ordering::Acquire);
        if next == tail {
            // Full: drop oldest by advancing tail
            self.tail.store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        }
        self.buf[head] = byte;
        self.head.store(next, Ordering::Release);
    }
    #[inline]
    fn pop(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let byte = self.buf[tail];
        self.tail.store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        Some(byte)
    }
    #[inline]
    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Relaxed)
    }
}

// Events: minimal set for extended keys
#[derive(Clone, Copy)]
pub enum KeyEvent {
    Up,
    Down,
    Left,
    Right,
}

// Separate ring for events (small)
struct SpscEvtRing<const N: usize> {
    buf: [u8; N],
    head: AtomicUsize,
    tail: AtomicUsize,
}
impl<const N: usize> SpscEvtRing<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }
    #[inline] fn mask() -> usize { N - 1 }
    #[inline]
    fn push_evt(&self, e: KeyEvent) {
        let code = match e {
            KeyEvent::Up => 1,
            KeyEvent::Down => 2,
            KeyEvent::Left => 3,
            KeyEvent::Right => 4,
        };
        let head = self.head.load(Ordering::Relaxed);
        let next = (head.wrapping_add(1)) & Self::mask();
        let tail = self.tail.load(Ordering::Acquire);
        if next == tail {
            self.tail.store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        }
        self.buf[head] = code;
        self.head.store(next, Ordering::Release);
    }
    #[inline]
    fn pop_evt(&self) -> Option<KeyEvent> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head { return None; }
        let code = self.buf[tail];
        self.tail.store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        match code {
            1 => Some(KeyEvent::Up),
            2 => Some(KeyEvent::Down),
            3 => Some(KeyEvent::Left),
            4 => Some(KeyEvent::Right),
            _ => None,
        }
    }
    #[inline]
    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Relaxed)
    }
}

// Global rings
const RING_SIZE: usize = 1024; // must be power of two
static CHAR_RING: SpscU8Ring<RING_SIZE> = SpscU8Ring::new();
static EVT_RING: SpscEvtRing<64> = SpscEvtRing::new();

// IO helpers
#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags));
    v
}
#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

// Wait while input buffer full or until output buffer ready (with small spin)
fn wait_input_empty() {
    for _ in 0..10000 {
        let s = unsafe { inb(KBD_STATUS) };
        if (s & 0x02) == 0 {
            break;
        }
        spin_loop();
    }
}
fn wait_output_full() -> bool {
    for _ in 0..10000 {
        let s = unsafe { inb(KBD_STATUS) };
        if (s & 0x01) != 0 {
            return true;
        }
        spin_loop();
    }
    false
}

// Minimal i8042 bring-up (non-blocking, tolerant)
fn i8042_init_best_effort() {
    // Flush any pending output
    while unsafe { inb(KBD_STATUS) } & 1 != 0 {
        let _ = unsafe { inb(KBD_DATA) };
    }

    // Enable scanning on the device (keyboard cmd 0xF4)
    wait_input_empty();
    unsafe { outb(KBD_DATA, KBD_ENABLE_SCANNING) };
    // The keyboard should respond 0xFA (ACK); we ignore if absent to stay non-blocking
    if wait_output_full() {
        let _ = unsafe { inb(KBD_DATA) };
    }
}

// LED update (Caps only here)
fn update_leds() {
    let caps_on = CAPS.load(Ordering::Relaxed);
    // Send ED, then LED bitmask: bit1=Num, bit0=Scroll, bit2=Caps
    wait_input_empty();
    unsafe { outb(KBD_DATA, KBD_SET_LEDS) };
    if wait_output_full() {
        let _ = unsafe { inb(KBD_DATA) }; // ACK
    }
    wait_input_empty();
    let mask = if caps_on { 0b100 } else { 0 };
    unsafe { outb(KBD_DATA, mask) };
    if wait_output_full() {
        let _ = unsafe { inb(KBD_DATA) }; // ACK
    }
}

// Scancode to char tables
const NORMAL: [Option<u8>; 0x60] = {
    let mut t: [Option<u8>; 0x60] = [None; 0x60];
    t[0x02] = Some(b'1'); t[0x03] = Some(b'2'); t[0x04] = Some(b'3'); t[0x05] = Some(b'4');
    t[0x06] = Some(b'5'); t[0x07] = Some(b'6'); t[0x08] = Some(b'7'); t[0x09] = Some(b'8');
    t[0x0A] = Some(b'9'); t[0x0B] = Some(b'0'); t[0x0C] = Some(b'-'); t[0x0D] = Some(b'=');
    t[0x0E] = Some(0x08); // Backspace
    t[0x0F] = Some(b'\t');
    t[0x10] = Some(b'q'); t[0x11] = Some(b'w'); t[0x12] = Some(b'e'); t[0x13] = Some(b'r');
    t[0x14] = Some(b't'); t[0x15] = Some(b'y'); t[0x16] = Some(b'u'); t[0x17] = Some(b'i');
    t[0x18] = Some(b'o'); t[0x19] = Some(b'p'); t[0x1A] = Some(b'['); t[0x1B] = Some(b']');
    t[0x1C] = Some(b'\n');
    t[0x1E] = Some(b'a'); t[0x1F] = Some(b's'); t[0x20] = Some(b'd'); t[0x21] = Some(b'f');
    t[0x22] = Some(b'g'); t[0x23] = Some(b'h'); t[0x24] = Some(b'j'); t[0x25] = Some(b'k');
    t[0x26] = Some(b'l'); t[0x27] = Some(b';'); t[0x28] = Some(b'\''); t[0x29] = Some(b'`');
    t[0x2B] = Some(b'\\');
    t[0x2C] = Some(b'z'); t[0x2D] = Some(b'x'); t[0x2E] = Some(b'c'); t[0x2F] = Some(b'v');
    t[0x30] = Some(b'b'); t[0x31] = Some(b'n'); t[0x32] = Some(b'm'); t[0x33] = Some(b',');
    t[0x34] = Some(b'.'); t[0x35] = Some(b'/');
    t[0x39] = Some(b' ');
    t
};
const SHIFTED: [Option<u8>; 0x60] = {
    let mut t: [Option<u8>; 0x60] = [None; 0x60];
    t[0x02] = Some(b'!'); t[0x03] = Some(b'@'); t[0x04] = Some(b'#'); t[0x05] = Some(b'$');
    t[0x06] = Some(b'%'); t[0x07] = Some(b'^'); t[0x08] = Some(b'&'); t[0x09] = Some(b'*');
    t[0x0A] = Some(b'('); t[0x0B] = Some(b')'); t[0x0C] = Some(b'_'); t[0x0D] = Some(b'+');
    t[0x0E] = Some(0x08);
    t[0x0F] = Some(b'\t');
    t[0x10] = Some(b'Q'); t[0x11] = Some(b'W'); t[0x12] = Some(b'E'); t[0x13] = Some(b'R');
    t[0x14] = Some(b'T'); t[0x15] = Some(b'Y'); t[0x16] = Some(b'U'); t[0x17] = Some(b'I');
    t[0x18] = Some(b'O'); t[0x19] = Some(b'P'); t[0x1A] = Some(b'{'); t[0x1B] = Some(b'}');
    t[0x1C] = Some(b'\n');
    t[0x1E] = Some(b'A'); t[0x1F] = Some(b'S'); t[0x20] = Some(b'D'); t[0x21] = Some(b'F');
    t[0x22] = Some(b'G'); t[0x23] = Some(b'H'); t[0x24] = Some(b'J'); t[0x25] = Some(b'K');
    t[0x26] = Some(b'L'); t[0x27] = Some(b':'); t[0x28] = Some(b'"'); t[0x29] = Some(b'~');
    t[0x2B] = Some(b'|');
    t[0x2C] = Some(b'Z'); t[0x2D] = Some(b'X'); t[0x2E] = Some(b'C'); t[0x2F] = Some(b'V');
    t[0x30] = Some(b'B'); t[0x31] = Some(b'N'); t[0x32] = Some(b'M'); t[0x33] = Some(b'<');
    t[0x34] = Some(b'>'); t[0x35] = Some(b'?');
    t[0x39] = Some(b' ');
    t
};

// ISR
fn keyboard_isr(_: crate::arch::x86_64::InterruptStackFrame) {
    // Check status
    let status = unsafe { inb(KBD_STATUS) };
    if (status & 1) == 0 {
        eoi();
        return;
    }
    let sc = unsafe { inb(KBD_DATA) };

    // Handle extended prefixes (E0/E1)
    if sc == SC_EXT_E0 || sc == SC_EXT_E1 {
        EXTENDED.store(true, Ordering::Relaxed);
        eoi();
        return;
    }

    let is_break = (sc & 0x80) != 0;
    let code = sc & 0x7F;

    // Modifiers on make/break
    match code {
        0x2A | 0x36 => { SHIFT.store(!is_break, Ordering::Relaxed); eoi(); return; } // Shift
        0x1D => { CTRL.store(!is_break, Ordering::Relaxed); eoi(); return; }          // Ctrl
        0x38 => { ALT.store(!is_break, Ordering::Relaxed); eoi(); return; }           // Alt
        0x3A => { // Caps (toggle on make)
            if !is_break {
                let old = CAPS.load(Ordering::Relaxed);
                CAPS.store(!old, Ordering::Relaxed);
                update_leds();
            }
            eoi();
            return;
        }
        _ => {}
    }

    // Only process make codes for character/events
    if is_break {
        eoi();
        return;
    }

    // Extended handling for arrows (E0)
    if EXTENDED.swap(false, Ordering::Relaxed) {
        match code {
            0x48 => EVT_RING.push_evt(KeyEvent::Up),
            0x50 => EVT_RING.push_evt(KeyEvent::Down),
            0x4B => EVT_RING.push_evt(KeyEvent::Left),
            0x4D => EVT_RING.push_evt(KeyEvent::Right),
            _ => {}
        }
        eoi();
        return;
    }

    // Map to character
    let shift = SHIFT.load(Ordering::Relaxed);
    let caps = CAPS.load(Ordering::Relaxed);
    let mut ch_opt = if shift {
        SHIFTED.get(code as usize).copied().flatten()
    } else {
        NORMAL.get(code as usize).copied().flatten()
    };

    if let Some(mut ch) = ch_opt {
        // Apply CapsLock case toggle for letters if shift not already uppercase
        if ch.is_ascii_alphabetic() {
            let upper = shift ^ caps;
            ch = if upper { ch.to_ascii_uppercase() } else { ch.to_ascii_lowercase() };
        }
        // Push to ring
        CHAR_RING.push(ch);
    }

    eoi();
}

#[inline(always)]
fn eoi() {
    crate::arch::x86_64::interrupt::apic::send_eoi();
}

// Public API

pub fn init_keyboard() -> Result<(), &'static str> {
    // Register ISR
    crate::interrupts::register_interrupt_handler(KBD_VECTOR, keyboard_isr)?;
    // Best-effort controller init (non-blocking)
    i8042_init_best_effort();
    Ok(())
}

pub fn read_char() -> Option<char> {
    CHAR_RING.pop().map(|b| b as char)
}

pub fn has_data() -> bool {
    !CHAR_RING.is_empty()
}

pub fn read_event() -> Option<KeyEvent> {
    EVT_RING.pop_evt()
}

/// Keyboard interface structure 
pub struct KeyboardInterface {
    pub initialized: bool,
}

impl KeyboardInterface {
    pub fn read_char(&self) -> Option<char> {
        read_char()
    }
    
    pub fn has_data(&self) -> bool {
        has_data()
    }
    
    pub fn read_event(&self) -> Option<KeyEvent> {
        read_event()
    }
    
    pub fn get_modifiers(&self) -> u8 {
        let mut mods = 0;
        if SHIFT.load(Ordering::Relaxed) { mods |= 0x01; }
        if CTRL.load(Ordering::Relaxed) { mods |= 0x02; }
        if ALT.load(Ordering::Relaxed) { mods |= 0x04; }
        if CAPS.load(Ordering::Relaxed) { mods |= 0x08; }
        mods
    }
}

static KEYBOARD_INTERFACE: KeyboardInterface = KeyboardInterface { initialized: false };

/// Get the global keyboard interface for hardware interaction
pub fn get_keyboard() -> &'static KeyboardInterface {
    &KEYBOARD_INTERFACE
}