//! VGA Text Mode Console 

use core::{fmt, ptr};
use spin::Mutex;

const VGA_BUFFER_ADDR: usize = 0xB8000;
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Color {
    Black = 0x0,
    Blue = 0x1,
    Green = 0x2,
    Cyan = 0x3,
    Red = 0x4,
    Magenta = 0x5,
    Brown = 0x6,
    LightGrey = 0x7,
    DarkGrey = 0x8,
    LightBlue = 0x9,
    LightGreen = 0xA,
    LightCyan = 0xB,
    LightRed = 0xC,
    Pink = 0xD,
    Yellow = 0xE,
    White = 0xF,
}

#[inline(always)]
fn vga_color(fg: Color, bg: Color) -> u8 {
    ((bg as u8) << 4) | (fg as u8 & 0x0F)
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VgaCell {
    ascii: u8,
    color: u8,
}

struct Console {
    col: usize,
    row: usize,
    color: u8,
    buf: *mut VgaCell,
    // ANSI parser state
    esc: bool,
    csi: bool,
    // CSI params (support up to 2 for our subset)
    p1: usize,
    p2: usize,
    have_p1: bool,
    have_p2: bool,
    // Batch cursor updates
    cursor_dirty: bool,
}

impl Console {
    const fn new() -> Self {
        Self {
            col: 0,
            row: 0,
            color: vga_color(Color::LightGrey, Color::Black),
            buf: VGA_BUFFER_ADDR as *mut VgaCell,
            esc: false,
            csi: false,
            p1: 0,
            p2: 0,
            have_p1: false,
            have_p2: false,
            cursor_dirty: false,
        }
    }

    fn flush_cursor(&mut self) {
        if !self.cursor_dirty {
            return;
        }
        let pos = (self.row * VGA_WIDTH + self.col).min(VGA_WIDTH * VGA_HEIGHT - 1) as u16;
        unsafe {
            outb(0x3D4, 0x0F);
            outb(0x3D5, (pos & 0xFF) as u8);
            outb(0x3D4, 0x0E);
            outb(0x3D5, ((pos >> 8) & 0xFF) as u8);
        }
        self.cursor_dirty = false;
    }

    fn mark_cursor(&mut self) {
        self.cursor_dirty = true;
    }

    fn write_cell(&mut self, r: usize, c: usize, byte: u8, color: u8) {
        if r >= VGA_HEIGHT || c >= VGA_WIDTH {
            return;
        }
        unsafe {
            ptr::write_volatile(self.buf.add(r * VGA_WIDTH + c), VgaCell { ascii: byte, color });
        }
    }

    fn clear_region(&mut self, r0: usize, c0: usize, r1_ex: usize, c1_ex: usize) {
        let blank = VgaCell { ascii: b' ', color: self.color };
        for r in r0..r1_ex.min(VGA_HEIGHT) {
            for c in c0..c1_ex.min(VGA_WIDTH) {
                unsafe { ptr::write_volatile(self.buf.add(r * VGA_WIDTH + c), blank) }
            }
        }
    }

    fn clear_screen(&mut self) {
        self.clear_region(0, 0, VGA_HEIGHT, VGA_WIDTH);
        self.col = 0;
        self.row = 0;
        self.mark_cursor();
    }

    fn fast_scroll_up(&mut self) {
        // Move rows 1..N to 0..N-1 using 16-bit copies
        // Each cell is 2 bytes; a full row is 80 cells
        unsafe {
            let dst = self.buf as *mut u16;
            let src = self.buf.add(VGA_WIDTH) as *const u16;
            // Copy (HEIGHT-1) rows
            let words = (VGA_HEIGHT - 1) * VGA_WIDTH;
            ptr::copy(src, dst, words);
        }
        // Clear last row
        let blank = VgaCell { ascii: b' ', color: self.color };
        for c in 0..VGA_WIDTH {
            unsafe {
                ptr::write_volatile(self.buf.add((VGA_HEIGHT - 1) * VGA_WIDTH + c), blank);
            }
        }
        if self.row > 0 {
            self.row = VGA_HEIGHT - 1;
        }
        self.mark_cursor();
    }

    fn new_line(&mut self) {
        self.col = 0;
        self.row += 1;
        if self.row >= VGA_HEIGHT {
            self.fast_scroll_up();
        }
        self.mark_cursor();
    }

    fn put_printable(&mut self, b: u8) {
        if self.row >= VGA_HEIGHT {
            self.fast_scroll_up();
        }
        self.write_cell(self.row, self.col, b, self.color);
        self.col += 1;
        if self.col >= VGA_WIDTH {
            self.new_line();
        } else {
            self.mark_cursor();
        }
    }

    fn put_byte(&mut self, byte: u8) {
        // ANSI/CSI parsing (very small subset)
        if self.esc {
            if !self.csi {
                // Expect '[' to start CSI
                if byte == b'[' {
                    self.csi = true;
                    self.p1 = 0;
                    self.p2 = 0;
                    self.have_p1 = false;
                    self.have_p2 = false;
                    return;
                } else {
                    // Unknown escape, treat as literal
                    self.esc = false;
                }
            }

            if self.csi {
                match byte {
                    b'0'..=b'9' => {
                        let d = (byte - b'0') as usize;
                        if !self.have_p1 || (self.have_p1 && !self.have_p2 && self.p2 == 0) {
                            self.p1 = self.p1.saturating_mul(10).saturating_add(d);
                            self.have_p1 = true;
                        } else {
                            self.p2 = self.p2.saturating_mul(10).saturating_add(d);
                            self.have_p2 = true;
                        }
                        return;
                    }
                    b';' => {
                        // Switch to p2
                        if !self.have_p1 {
                            self.have_p1 = true;
                        }
                        return;
                    }
                    // CSI commands we handle: 'm' (SGR), 'H' (cursor pos), 'J' (erase display)
                    b'm' => {
                        // SGR: color attributes
                        let p = if self.have_p1 { self.p1 } else { 0 };
                        if p == 0 {
                            // Reset to default
                            self.color = vga_color(Color::LightGrey, Color::Black);
                        } else {
                            self.apply_sgr(p);
                            if self.have_p2 {
                                self.apply_sgr(self.p2);
                            }
                        }
                    }
                    b'H' => {
                        // Cursor position: row;col (1-based)
                        let row1 = if self.have_p1 { self.p1.max(1) } else { 1 };
                        let col1 = if self.have_p2 { self.p2.max(1) } else { 1 };
                        self.row = row1.saturating_sub(1).min(VGA_HEIGHT - 1);
                        self.col = col1.saturating_sub(1).min(VGA_WIDTH - 1);
                        self.mark_cursor();
                    }
                    b'J' => {
                        // Erase display: support 2 = all
                        let p = if self.have_p1 { self.p1 } else { 0 };
                        if p == 2 || p == 0 {
                            self.clear_screen();
                        }
                    }
                    _ => { /* ignore unsupported */ }
                }
                // End of CSI
                self.esc = false;
                self.csi = false;
                return;
            }
        }

        match byte {
            0x1B => {
                // ESC
                self.esc = true;
                self.csi = false;
            }
            b'\n' => self.new_line(),
            b'\r' => {
                self.col = 0;
                self.mark_cursor();
            }
            0x20..=0x7E => self.put_printable(byte),
            _ => {
                // Non-printable: replace with space
                self.put_printable(b' ');
            }
        }
    }

    fn apply_sgr(&mut self, p: usize) {
        // Support 30–37 fg, 40–47 bg
        match p {
            30..=37 => {
                let fg = match p - 30 {
                    0 => Color::Black,
                    1 => Color::Red,
                    2 => Color::Green,
                    3 => Color::Brown, // as Yellow/Brown approx for 33
                    4 => Color::Blue,
                    5 => Color::Magenta,
                    6 => Color::Cyan,
                    _ => Color::LightGrey,
                };
                // Preserve bg nibble
                let bg = (self.color >> 4) & 0xF;
                self.color = (bg << 4) | (fg as u8 & 0xF);
            }
            40..=47 => {
                let bg = match p - 40 {
                    0 => Color::Black,
                    1 => Color::Red,
                    2 => Color::Green,
                    3 => Color::Brown,
                    4 => Color::Blue,
                    5 => Color::Magenta,
                    6 => Color::Cyan,
                    _ => Color::LightGrey,
                };
                let fg = self.color & 0xF;
                self.color = ((bg as u8) << 4) | fg;
            }
            0 => {
                self.color = vga_color(Color::LightGrey, Color::Black);
            }
            _ => { /* ignore */ }
        }
    }

    fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.put_byte(b);
        }
        // Batch-flush cursor after the string
        self.flush_cursor();
    }

    fn clear(&mut self) {
        self.clear_screen();
        self.flush_cursor();
    }

    fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = vga_color(fg, bg);
    }
}

// Port I/O
#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

// Global console
static CONSOLE: Mutex<Console> = Mutex::new(Console::new());

// Public API
pub fn init_console() {
    let mut c = CONSOLE.lock();
    c.clear();
}

pub fn clear() {
    CONSOLE.lock().clear();
}

pub fn set_color(fg: Color, bg: Color) {
    CONSOLE.lock().set_color(fg, bg);
}

pub fn print(s: &str) {
    CONSOLE.lock().write_str(s);
}

pub fn println(s: &str) {
    let mut g = CONSOLE.lock();
    g.write_str(s);
    g.put_byte(b'\n');
    g.flush_cursor();
}

// Implement core::fmt::Write for formatted printing
struct ConsoleWriter;
impl fmt::Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        print(s);
        Ok(())
    }
}

pub fn printf(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut w = ConsoleWriter;
    let _ = w.write_fmt(args);
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ($crate::drivers::nonos_console::printf(format_args!($($arg)*)));
}
#[macro_export]
macro_rules! kprintln {
    () => ($crate::drivers::nonos_console::println(""));
    ($fmt:expr) => ($crate::drivers::nonos_console::println($fmt));
    ($fmt:expr, $($arg:tt)*) => ($crate::drivers::nonos_console::printf(format_args!(concat!($fmt, "\n"), $($arg)*)));
}
