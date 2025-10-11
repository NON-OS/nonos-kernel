//! VGA Text Mode Driver 

use core::ptr;
use spin::Mutex;

const VGA_BUFFER_ADDR: usize = 0xB8000;
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
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

struct Vga {
    col: usize,
    row: usize,
    color: u8,
    buf: *mut VgaCell,
    auto_cursor_update: bool,
    cursor_dirty: bool,
}

impl Vga {
    const fn new() -> Self {
        Self {
            col: 0,
            row: 0,
            color: vga_color(Color::LightGrey, Color::Black),
            buf: VGA_BUFFER_ADDR as *mut VgaCell,
            auto_cursor_update: true,
            cursor_dirty: false,
        }
    }

    #[inline]
    fn bounds_ok(r: usize, c: usize) -> bool {
        r < VGA_HEIGHT && c < VGA_WIDTH
    }

    #[inline]
    fn write_cell(&mut self, r: usize, c: usize, ch: u8, color: u8) {
        if !Self::bounds_ok(r, c) {
            return;
        }
        unsafe {
            ptr::write_volatile(self.buf.add(r * VGA_WIDTH + c), VgaCell { ascii: ch, color });
        }
    }

    fn mark_cursor(&mut self) {
        self.cursor_dirty = true;
        if self.auto_cursor_update {
            self.flush_cursor();
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

    fn fast_scroll_up(&mut self) {
        // Copy rows 1..N into 0..N-1 using 16-bit words (2 bytes per cell)
        unsafe {
            let dst = self.buf as *mut u16;
            let src = self.buf.add(VGA_WIDTH) as *const u16;
            let words = (VGA_HEIGHT - 1) * VGA_WIDTH;
            ptr::copy(src, dst, words);
        }
        // Clear bottom row (last line)
        let blank = VgaCell { ascii: b' ', color: self.color };
        for c in 0..VGA_WIDTH {
            unsafe { ptr::write_volatile(self.buf.add((VGA_HEIGHT - 1) * VGA_WIDTH + c), blank) }
        }
        if self.row > 0 {
            self.row = VGA_HEIGHT - 1;
        }
        self.mark_cursor();
    }

    fn newline(&mut self) {
        self.col = 0;
        self.row += 1;
        if self.row >= VGA_HEIGHT {
            self.fast_scroll_up();
        } else {
            self.mark_cursor();
        }
    }

    fn put_printable(&mut self, ch: u8) {
        if self.row >= VGA_HEIGHT {
            self.fast_scroll_up();
        }
        self.write_cell(self.row, self.col, ch, self.color);
        self.col += 1;
        if self.col >= VGA_WIDTH {
            self.newline();
        } else {
            self.mark_cursor();
        }
    }

    fn put_char(&mut self, ch: u8) {
        match ch {
            b'\n' => self.newline(),
            b'\r' => {
                self.col = 0;
                self.mark_cursor();
            }
            0x08 => {
                // Backspace
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = VGA_WIDTH - 1;
                }
                self.write_cell(self.row, self.col, b' ', self.color);
                self.mark_cursor();
            }
            0x20..=0x7E => self.put_printable(ch),
            _ => self.put_printable(b' '),
        }
    }

    fn write_str(&mut self, s: &str) {
        for b in s.bytes() {
            self.put_char(b);
        }
    }

    fn write_at(&mut self, x: usize, y: usize, ch: u8) {
        if !Self::bounds_ok(y, x) {
            return;
        }
        self.write_cell(y, x, ch, self.color);
    }

    fn write_str_at(&mut self, x: usize, y: usize, s: &str) {
        if y >= VGA_HEIGHT {
            return;
        }
        let mut col = x.min(VGA_WIDTH);
        for b in s.bytes() {
            if col >= VGA_WIDTH {
                break;
            }
            if (0x20..=0x7E).contains(&b) {
                self.write_cell(y, col, b, self.color);
            } else {
                self.write_cell(y, col, b' ', self.color);
            }
            col += 1;
        }
        self.mark_cursor();
    }

    fn clear(&mut self) {
        let blank = VgaCell { ascii: b' ', color: self.color };
        for r in 0..VGA_HEIGHT {
            for c in 0..VGA_WIDTH {
                unsafe { ptr::write_volatile(self.buf.add(r * VGA_WIDTH + c), blank) }
            }
        }
        self.col = 0;
        self.row = 0;
        self.mark_cursor();
    }

    fn clear_region(&mut self, x0: usize, y0: usize, x1_ex: usize, y1_ex: usize) {
        let blank = VgaCell { ascii: b' ', color: self.color };
        for r in y0.min(VGA_HEIGHT)..y1_ex.min(VGA_HEIGHT) {
            for c in x0.min(VGA_WIDTH)..x1_ex.min(VGA_WIDTH) {
                unsafe { ptr::write_volatile(self.buf.add(r * VGA_WIDTH + c), blank) }
            }
        }
        self.mark_cursor();
    }

    fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = vga_color(fg, bg);
    }

    fn get_color(&self) -> (Color, Color) {
        let fg = Color::from_u8(self.color & 0x0F);
        let bg = Color::from_u8((self.color >> 4) & 0x0F);
        (fg, bg)
    }

    fn set_cursor(&mut self, x: usize, y: usize) {
        self.col = x.min(VGA_WIDTH - 1);
        self.row = y.min(VGA_HEIGHT - 1);
        self.mark_cursor();
    }

    fn get_cursor(&self) -> (usize, usize) {
        (self.col, self.row)
    }

    fn set_auto_cursor_update(&mut self, on: bool) {
        self.auto_cursor_update = on;
        if on && self.cursor_dirty {
            // Bring hardware in sync
            let mut me = Vga { ..*self };
            me.flush_cursor();
        }
    }

    fn enable_cursor(&mut self, scanline_start: u8, scanline_end: u8) {
        // VGA cursor shape via CRT Controller registers 0x0A and 0x0B
        unsafe {
            outb(0x3D4, 0x0A);
            let cur_start = inb(0x3D5);
            outb(0x3D5, (cur_start & 0xC0) | (scanline_start & 0x1F));

            outb(0x3D4, 0x0B);
            let cur_end = inb(0x3D5);
            outb(0x3D5, (cur_end & 0xE0) | (scanline_end & 0x1F));
        }
        self.mark_cursor();
    }

    fn disable_cursor(&mut self) {
        // Set cursor disable (bit 5 of register 0x0A)
        unsafe {
            outb(0x3D4, 0x0A);
            let cur_start = inb(0x3D5);
            outb(0x3D5, cur_start | 0x20);
        }
    }
}

// Helper to decode color nibble back to enum
impl Color {
    fn from_u8(n: u8) -> Color {
        match n & 0x0F {
            0x0 => Color::Black,
            0x1 => Color::Blue,
            0x2 => Color::Green,
            0x3 => Color::Cyan,
            0x4 => Color::Red,
            0x5 => Color::Magenta,
            0x6 => Color::Brown,
            0x7 => Color::LightGrey,
            0x8 => Color::DarkGrey,
            0x9 => Color::LightBlue,
            0xA => Color::LightGreen,
            0xB => Color::LightCyan,
            0xC => Color::LightRed,
            0xD => Color::Pink,
            0xE => Color::Yellow,
            _ => Color::White,
        }
    }
}

// Port I/O
#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}
#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags));
    v
}

// Global VGA state
static VGA: Mutex<Vga> = Mutex::new(Vga::new());

// Public API

pub fn init_vga() {
    let mut g = VGA.lock();
    g.clear();
    // Set a sane default cursor shape (scanlines)
    g.enable_cursor(0, 15);
    g.flush_cursor();
}

pub fn clear() {
    let mut g = VGA.lock();
    g.clear();
    g.flush_cursor();
}

pub fn clear_region(x0: usize, y0: usize, x1_ex: usize, y1_ex: usize) {
    let mut g = VGA.lock();
    g.clear_region(x0, y0, x1_ex, y1_ex);
    g.flush_cursor();
}

pub fn set_color(fg: Color, bg: Color) {
    VGA.lock().set_color(fg, bg);
}
pub fn get_color() -> (Color, Color) {
    VGA.lock().get_color()
}

pub fn put_char(ch: u8) {
    let mut g = VGA.lock();
    g.put_char(ch);
    g.flush_cursor();
}

pub fn write_str(s: &str) {
    let mut g = VGA.lock();
    g.write_str(s);
    g.flush_cursor();
}

pub fn write_at(x: usize, y: usize, ch: u8) {
    let mut g = VGA.lock();
    g.write_at(x, y, ch);
    g.flush_cursor();
}

pub fn write_str_at(x: usize, y: usize, s: &str) {
    let mut g = VGA.lock();
    g.write_str_at(x, y, s);
    g.flush_cursor();
}

pub fn set_cursor(x: usize, y: usize) {
    let mut g = VGA.lock();
    g.set_cursor(x, y);
    g.flush_cursor();
}

pub fn get_cursor() -> (usize, usize) {
    VGA.lock().get_cursor()
}

pub fn enable_cursor(start: u8, end: u8) {
    let mut g = VGA.lock();
    g.enable_cursor(start, end);
    g.flush_cursor();
}

pub fn disable_cursor() {
    VGA.lock().disable_cursor();
}

pub fn set_auto_cursor_update(on: bool) {
    VGA.lock().set_auto_cursor_update(on);
}

pub fn flush_cursor() {
    VGA.lock().flush_cursor();
}

// Non-blocking write, for ISR/early boot: silently drops if busy
pub fn try_write_str(s: &str) {
    if let Some(mut g) = VGA.try_lock() {
        g.write_str(s);
        g.flush_cursor();
    }
}

pub fn get_size() -> (usize, usize) {
    (VGA_WIDTH, VGA_HEIGHT)
}
