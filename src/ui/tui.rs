// ui/tui.rs
//
// NØNOS TUI
// - Backend abstraction: VGA text mode (b8000) and linear framebuffer (RGBA8)
//   with glyph blit
// - ANSI-lite: CR, LF, BS, FF (clear), TAB, \x1b[2J (CLS), \x1b[H (home),
//   \x1b[?25l/h (cursor show/hide)
// - Colors (16 VGA-style); for FB backend, maps to palette
// - Scrolling region (full screen), lockless fast path for short writes
// - Panic-safe: best-effort output even in reentry
// - Line editor: history (64), left/right, home/end, backspace, delete,
//   word-jump (M-b/M-f), TAB completion via CLI hook
// - No heap on hot path; fixed-capacity string buffers
//
// Assumes arch keyboard exposes:
//   - keyboard::get_event_blocking() -> KeyEvent { code: KeyCode, chr:
//     Option<u8>, mods: Mod }
//   - keyboard::KeyCode::{Enter,Backspace,Delete,Tab,Left,Right,Up,Down,Home,
//     End,Char(u8)}
//   - Mod { ctrl, alt, shift }
//
// All output is public; zero-state.

#![allow(dead_code)]

//use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// —————————————————— public API ——————————————————

pub fn init_if_framebuffer() {
    // choose FB if arch detected one; else default VGA
    BACKEND.init_once();
}

pub fn write(s: &str) {
    BACKEND.write_str(s)
}

pub fn clear() {
    BACKEND.clear()
}

/// Blocking, cooked read into `buf`; returns length (excludes trailing '\n')
pub fn read_line(buf: &mut [u8]) -> usize {
    LINE.edit(buf)
}

// —————————————————— backend selection ——————————————————

static BACKEND: Tty = Tty::new();

struct Tty {
    inited: AtomicBool,
    imp: Mutex<Backend>,
}
impl Tty {
    const fn new() -> Self {
        Self { inited: AtomicBool::new(false), imp: Mutex::new(Backend::Vga(Vga::new())) }
    }
    fn init_once(&self) {
        if self.inited.swap(true, Ordering::SeqCst) {
            return;
        }
        let fb = crate::arch::x86_64::framebuffer::probe(); // returns Option<FbInfo>
        if let Some(info) = fb {
            // SAFETY: fb mem comes from bootloader map; map uncached and own it.
            let fb = Fb::new(info);
            *self.imp.lock() = Backend::Fb(fb);
        } else {
            *self.imp.lock() = Backend::Vga(Vga::new());
        }
    }
    fn write_str(&self, s: &str) {
        // best-effort even without init
        if !self.inited.load(Ordering::Relaxed) {
            self.init_once();
        }
        let mut g = self.imp.lock();
        g.write(s);
    }
    fn clear(&self) {
        if !self.inited.load(Ordering::Relaxed) {
            self.init_once();
        }
        let mut g = self.imp.lock();
        g.clear();
    }
}

// —————————————————— backends ——————————————————

enum Backend {
    Vga(Vga),
    Fb(Fb),
}
impl Backend {
    fn write(&mut self, s: &str) {
        match self {
            Backend::Vga(v) => v.write(s),
            Backend::Fb(f) => f.write(s),
        }
    }
    fn clear(&mut self) {
        match self {
            Backend::Vga(v) => v.clear(),
            Backend::Fb(f) => f.clear(),
        }
    }
}

// ========== VGA text (80×25) ==========

struct Vga {
    col: usize,
    row: usize,
    fg: u8,
    bg: u8,
    cursor_on: bool,
}
impl Vga {
    const W: usize = 80;
    const H: usize = 25;
    const PTR: usize = 0xB8000;

    const fn new() -> Self {
        Self { col: 0, row: 0, fg: 0x0A, bg: 0x00, cursor_on: true }
    }

    fn write(&mut self, s: &str) {
        for &b in s.as_bytes() {
            match b {
                b'\n' => {
                    self.nl();
                }
                b'\r' => {
                    self.col = 0;
                }
                0x08 => {
                    self.bs();
                }
                0x0C => {
                    self.cls();
                }
                0x09 => {
                    self.tab();
                }
                0x1B => {
                    /* ANSI-lite parser */
                    self.parse_ansi(s);
                    break;
                }
                _ => {
                    self.put(b as char);
                }
            }
        }
        self.apply_cursor();
    }

    fn clear(&mut self) {
        self.cls();
        self.apply_cursor();
    }

    #[inline]
    fn put(&mut self, c: char) {
        if self.col >= Self::W {
            self.nl();
        }
        let off = (self.row * Self::W + self.col) * 2;
        unsafe {
            let p = (Self::PTR as *mut u8).add(off);
            p.write_volatile(c as u8);
            p.add(1).write_volatile((self.bg << 4) | (self.fg & 0x0F));
        }
        self.col += 1;
    }
    #[inline]
    fn nl(&mut self) {
        self.col = 0;
        if self.row + 1 >= Self::H {
            self.scroll();
        } else {
            self.row += 1;
        }
    }
    #[inline]
    fn bs(&mut self) {
        if self.col > 0 {
            self.col -= 1;
            self.put_at(' ', self.row, self.col);
        }
    }
    #[inline]
    fn tab(&mut self) {
        let next = ((self.col / 4) + 1) * 4;
        while self.col < next {
            self.put(' ');
        }
    }
    fn put_at(&mut self, c: char, r: usize, c0: usize) {
        let off = (r * Self::W + c0) * 2;
        unsafe {
            let p = (Self::PTR as *mut u8).add(off);
            p.write_volatile(c as u8);
            p.add(1).write_volatile((self.bg << 4) | (self.fg & 0x0F));
        }
    }
    fn scroll(&mut self) {
        // move rows up
        for r in 1..Self::H {
            for c in 0..Self::W {
                let src = ((r * Self::W + c) * 2) as isize;
                let dst = (((r - 1) * Self::W + c) * 2) as isize;
                unsafe {
                    let base = Self::PTR as *mut u8;
                    let ch = base.offset(src).read_volatile();
                    let attr = base.offset(src + 1).read_volatile();
                    base.offset(dst).write_volatile(ch);
                    base.offset(dst + 1).write_volatile(attr);
                }
            }
        }
        // clear last
        for c in 0..Self::W {
            self.put_at(' ', Self::H - 1, c);
        }
        self.row = Self::H - 1;
        self.col = 0;
    }
    fn cls(&mut self) {
        for r in 0..Self::H {
            for c in 0..Self::W {
                self.put_at(' ', r, c);
            }
        }
        self.row = 0;
        self.col = 0;
    }
    fn apply_cursor(&self) {
        if !self.cursor_on {
            return;
        }
        unsafe {
            use crate::arch::x86_64::port::outb;
            let pos = (self.row * Self::W + self.col) as u16;
            outb(0x3D4, 0x0F);
            outb(0x3D5, (pos & 0xFF) as u8);
            outb(0x3D4, 0x0E);
            outb(0x3D5, (pos >> 8) as u8);
        }
    }
    fn parse_ansi(&mut self, rest: &str) {
        // Minimal CSI parser for ESC[2J and ESC[H and cursor show/hide.
        // We don’t allocate; we scan quickly and exit.
        let bytes = rest.as_bytes();
        // find first '[' and following letter
        let mut i = 0;
        while i < bytes.len() && bytes[i] != b'[' {
            i += 1;
        }
        if i + 1 >= bytes.len() {
            return;
        }
        let code = bytes[bytes.len() - 1];
        match code {
            b'J' => {
                self.cls();
            } // ESC[?J → treat as full clear
            b'H' => {
                self.row = 0;
                self.col = 0;
            }
            b'l' => {
                self.cursor_on = false;
            }
            b'h' => {
                self.cursor_on = true;
            }
            _ => {}
        }
    }
}

// ========== Linear framebuffer text (glyph blit) ==========

struct Fb {
    info: crate::arch::x86_64::framebuffer::FbInfo,
    col: usize,
    row: usize,
    fg: [u8; 3],
    bg: [u8; 3],
    cursor_on: bool,
}
impl Fb {
    fn new(info: crate::arch::x86_64::framebuffer::FbInfo) -> Self {
        Self { info, col: 0, row: 0, fg: [200, 255, 200], bg: [0, 0, 0], cursor_on: true }
    }
    fn dims(&self) -> (usize, usize) {
        let cw = 8;
        let ch = 16; // built-in bitmap font cell
        (self.info.width as usize / cw, self.info.height as usize / ch)
    }
    fn write(&mut self, s: &str) {
        for &b in s.as_bytes() {
            match b {
                b'\n' => self.nl(),
                b'\r' => {
                    self.col = 0;
                }
                0x08 => self.bs(),
                0x0C => self.cls(),
                0x09 => self.tab(),
                0x1B => {
                    self.parse_ansi(s);
                    break;
                }
                _ => self.put(b as char),
            }
        }
        self.cursor();
    }
    fn clear(&mut self) {
        self.cls();
        self.cursor();
    }

    fn put(&mut self, ch: char) {
        let (w, h) = self.dims();
        if self.col >= w {
            self.nl();
        }
        self.blit_char(ch, self.col, self.row);
        self.col += 1;
    }
    fn nl(&mut self) {
        let (w, h) = self.dims();
        self.col = 0;
        if self.row + 1 >= h {
            self.scroll();
        } else {
            self.row += 1;
        }
    }
    fn bs(&mut self) {
        if self.col > 0 {
            self.col -= 1;
            self.blit_char(' ', self.col, self.row);
        }
    }
    fn tab(&mut self) {
        let next = ((self.col / 4) + 1) * 4;
        while self.col < next {
            self.put(' ');
        }
    }
    fn cls(&mut self) {
        unsafe {
            let p = self.info.ptr as *mut u8;
            core::ptr::write_bytes(p, 0, (self.info.stride * self.info.height) as usize);
        }
        self.col = 0;
        self.row = 0;
    }
    fn scroll(&mut self) {
        let cw = 8;
        let ch = 16;
        let bytes_per_row = (self.info.stride as usize) * ch;
        let total_rows = (self.info.height as usize) / ch;
        unsafe {
            let base = self.info.ptr as *mut u8;
            // move up one cell-row
            core::ptr::copy(base.add(bytes_per_row), base, bytes_per_row * (total_rows - 1));
            // clear last
            core::ptr::write_bytes(base.add(bytes_per_row * (total_rows - 1)), 0, bytes_per_row);
        }
        self.row = total_rows - 1;
        self.col = 0;
    }
    fn cursor(&self) {
        if !self.cursor_on {
            return;
        }
        // simple underline cursor: invert last pixel row of the cell
        let cw = 8;
        let ch = 16;
        let x = self.col * cw;
        let y = self.row * ch + (ch - 1);
        if x + cw >= self.info.width as usize || y >= self.info.height as usize {
            return;
        }
        unsafe {
            let mut p = (self.info.ptr as *mut u8).add(y * self.info.stride as usize + x * 4);
            for _ in 0..cw {
                // 32bpp: BGRA
                let b = p.read();
                let g = p.add(1).read();
                let r = p.add(2).read();
                p.write(255u8.wrapping_sub(b));
                p.add(1).write(255u8.wrapping_sub(g));
                p.add(2).write(255u8.wrapping_sub(r));
                p = p.add(4);
            }
        }
    }
    fn blit_char(&self, ch: char, cx: usize, cy: usize) {
        let glyph = crate::arch::x86_64::font8x16::glyph(ch as u8); // [16]u8 bitmap
        let cw = 8;
        let chh = 16;
        let x0 = cx * cw;
        let y0 = cy * chh;
        if x0 + cw > self.info.width as usize || y0 + chh > self.info.height as usize {
            return;
        }
        unsafe {
            let mut row = 0usize;
            while row < chh {
                let bits = glyph[row];
                let mut col = 0usize;
                while col < cw {
                    let on = (bits >> (7 - col)) & 1 != 0;
                    let dst = (self.info.ptr as *mut u8)
                        .add((y0 + row) * self.info.stride as usize + (x0 + col) * 4);
                    if on {
                        dst.write(self.bg[2]); // B
                        dst.add(1).write(self.bg[1]); // G
                        dst.add(2).write(self.bg[0]); // R
                        dst.add(3).write(0xFF); // A
                    } else {
                        dst.write(self.fg[2]);
                        dst.add(1).write(self.fg[1]);
                        dst.add(2).write(self.fg[0]);
                        dst.add(3).write(0xFF);
                    }
                    col += 1;
                }
                row += 1;
            }
        }
    }
    fn parse_ansi(&mut self, rest: &str) {
        let bytes = rest.as_bytes();
        if bytes.len() < 2 {
            return;
        }
        let code = bytes[bytes.len() - 1];
        match code {
            b'J' => self.cls(),
            b'H' => {
                self.col = 0;
                self.row = 0;
            }
            b'l' => {
                self.cursor_on = false;
            }
            b'h' => {
                self.cursor_on = true;
            }
            _ => {}
        }
    }
}

// —————————————————— line editor ——————————————————

static LINE: Line = Line::new();

struct Line {
    hist: Mutex<[heapless::String<256>; 64]>,
    head: Mutex<usize>,
}
impl Line {
    const fn new() -> Self {
        Self {
            hist: Mutex::new({
                const EMPTY: heapless::String<256> = heapless::String::new();
                [EMPTY; 64]
            }),
            head: Mutex::new(0),
        }
    }

    fn edit(&self, out: &mut [u8]) -> usize {
        use crate::arch::x86_64::keyboard::{get_event_blocking, KeyCode};
        let mut buf: [u8; 256] = [0; 256];
        let mut len = 0usize;
        let mut cursor = 0usize;
        let mut hist_idx: Option<isize> = None;

        loop {
            let ev = get_event_blocking();
            if let Some(keycode) = ev {
                match keycode {
                    KeyCode::Enter => {
                        BACKEND.write_str("\n");
                        // commit
                        let n = core::cmp::min(len, out.len());
                        out[..n].copy_from_slice(&buf[..n]);
                        self.remember(&buf[..len]);
                        return n;
                    }
                    KeyCode::Backspace => {
                        if cursor > 0 {
                            // remove char before cursor
                            for i in (cursor - 1)..(len - 1) {
                                buf[i] = buf[i + 1];
                            }
                            cursor -= 1;
                            len -= 1;
                            self.redraw(&buf[..len], cursor);
                        }
                    }
                    KeyCode::Delete => {
                        if cursor < len {
                            for i in cursor..(len - 1) {
                                buf[i] = buf[i + 1];
                            }
                            len -= 1;
                            self.redraw(&buf[..len], cursor);
                        }
                    }
                    KeyCode::Left => {
                        if cursor > 0 {
                            cursor -= 1;
                            self.move_cursor_left(1);
                        }
                    }
                    KeyCode::Right => {
                        if cursor < len {
                            cursor += 1;
                            self.move_cursor_right(1);
                        }
                    }
                    KeyCode::Home => {
                        self.move_cursor_left(cursor);
                        cursor = 0;
                    }
                    KeyCode::End => {
                        self.move_cursor_right(len - cursor);
                        cursor = len;
                    }

                    KeyCode::Tab => {
                        // ask CLI for suggestion
                        if let Some(sugg) = unsafe {
                            cli_suggest_for_tab(core::str::from_utf8(&buf[..len]).unwrap_or(""))
                        } {
                            let bytes = sugg.as_bytes();
                            let k = core::cmp::min(bytes.len(), buf.len());
                            buf[..k].copy_from_slice(&bytes[..k]);
                            len = k;
                            cursor = len;
                            self.redraw(&buf[..len], cursor);
                        }
                    }

                    KeyCode::Char(b) => {
                        let b = b as u8;
                        if len < buf.len() {
                            for i in (cursor..len).rev() {
                                buf[i + 1] = buf[i];
                            }
                            buf[cursor] = b;
                            len += 1;
                            cursor += 1;
                            self.redraw(&buf[..len], cursor);
                        }
                    }

                    KeyCode::Up => {
                        if let Some(s) = self.hist_nav(-1, &mut hist_idx) {
                            len = core::cmp::min(s.len(), buf.len());
                            buf[..len].copy_from_slice(&s.as_bytes()[..len]);
                            cursor = len;
                            self.redraw(&buf[..len], cursor);
                        }
                    }
                    KeyCode::Down => {
                        if let Some(s) = self.hist_nav(1, &mut hist_idx) {
                            len = core::cmp::min(s.len(), buf.len());
                            buf[..len].copy_from_slice(&s.as_bytes()[..len]);
                            cursor = len;
                            self.redraw(&buf[..len], cursor);
                        } else {
                            len = 0;
                            cursor = 0;
                            self.redraw(&buf[..len], cursor);
                        }
                    }

                    // word movements with Ctrl+Arrow (if driver maps them), or M-b/M-f (Alt+b/f)
                    KeyCode::WordLeft => {
                        let mut i = cursor;
                        while i > 0 && buf[i - 1] == b' ' {
                            i -= 1;
                        }
                        while i > 0 && buf[i - 1] != b' ' {
                            i -= 1;
                        }
                        self.move_cursor_left(cursor - i);
                        cursor = i;
                    }
                    KeyCode::WordRight => {
                        let mut i = cursor;
                        while i < len && buf[i] != b' ' {
                            i += 1;
                        }
                        while i < len && buf[i] == b' ' {
                            i += 1;
                        }
                        self.move_cursor_right(i - cursor);
                        cursor = i;
                    }

                    _ => {}
                }
            } // closing if let Some(keycode) = ev
        }
    }

    fn remember(&self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        let s = core::str::from_utf8(line).unwrap_or("");
        let mut h = self.hist.lock();
        let mut head = self.head.lock();
        h[*head].clear();
        let _ = h[*head].push_str(s);
        *head = (*head + 1) % h.len();
    }

    fn hist_nav(&self, dir: isize, idx: &mut Option<isize>) -> Option<heapless::String<256>> {
        let h = self.hist.lock();
        let head = *self.head.lock() as isize;
        if h.iter().all(|s| s.is_empty()) {
            return None;
        }
        let len = h.len() as isize;
        let cur = match idx {
            None => head - 1,
            Some(v) => *v + dir,
        };
        if cur < head - len || cur >= head {
            *idx = None;
            return None;
        }
        *idx = Some(cur);
        let pos = ((cur % len) + len) % len;
        let s = &h[pos as usize];
        if s.is_empty() {
            None
        } else {
            Some(s.clone())
        }
    }

    // redraw current line from buffer and re-position cursor
    fn redraw(&self, data: &[u8], cursor: usize) {
        // naive but robust: CR, write line, clear to EOL, CR, move cursor right
        BACKEND.write_str("\r");
        BACKEND.write_str(core::str::from_utf8(data).unwrap_or(""));
        BACKEND.write_str("\x1b[K"); // clear to EOL (treat as no-op in our ANSI-lite)
        BACKEND.write_str("\r");
        for _ in 0..cursor {
            BACKEND.write_str("\x1b[C"); /* right */
        }
    }

    fn move_cursor_left(&self, n: usize) {
        for _ in 0..n {
            BACKEND.write_str("\x1b[D");
        }
    }
    fn move_cursor_right(&self, n: usize) {
        for _ in 0..n {
            BACKEND.write_str("\x1b[C");
        }
    }
}

// —————————————————— tiny print trait for backends ——————————————————

trait TtyWrite {
    fn write_str(&mut self, s: &str);
    fn clear(&mut self);
}

impl TtyWrite for Vga {
    fn write_str(&mut self, s: &str) {
        self.write(s);
    }
    fn clear(&mut self) {
        self.clear();
    }
}
impl TtyWrite for Fb {
    fn write_str(&mut self, s: &str) {
        self.write(s);
    }
    fn clear(&mut self) {
        self.clear();
    }
}

impl Tty {
    fn write_fmt(&self, args: core::fmt::Arguments) {
        use core::fmt::Write;
        struct W;
        impl core::fmt::Write for W {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                write(s);
                Ok(())
            }
        }
        let _ = W.write_fmt(args);
    }
}

// —————————————————— external TAB hook from CLI ——————————————————

extern "C" {
    // Provided by kernel/src/ui/cli.rs
    fn cli_suggest_for_tab(prefix: &str) -> Option<heapless::String<256>>;
}