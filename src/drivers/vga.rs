//! VGA Text Mode Driver
//!
//! Real VGA driver with hardware register control and multiple color modes

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::instructions::port::{Port, PortReadOnly, PortWriteOnly};

/// VGA text mode dimensions
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;
const VGA_SIZE: usize = VGA_WIDTH * VGA_HEIGHT;

/// VGA text mode buffer address
const VGA_BUFFER_ADDR: usize = 0xB8000;

/// VGA I/O port addresses
const VGA_MISC_WRITE: u16 = 0x3C2;
const VGA_MISC_READ: u16 = 0x3CC;
const VGA_SEQ_INDEX: u16 = 0x3C4;
const VGA_SEQ_DATA: u16 = 0x3C5;
const VGA_CRTC_INDEX_COLOR: u16 = 0x3D4;
const VGA_CRTC_DATA_COLOR: u16 = 0x3D5;
const VGA_CRTC_INDEX_MONO: u16 = 0x3B4;
const VGA_CRTC_DATA_MONO: u16 = 0x3B5;
const VGA_GC_INDEX: u16 = 0x3CE;
const VGA_GC_DATA: u16 = 0x3CF;
const VGA_AC_INDEX: u16 = 0x3C0;
const VGA_AC_WRITE: u16 = 0x3C0;
const VGA_AC_READ: u16 = 0x3C1;
const VGA_INPUT_STATUS_1: u16 = 0x3DA;

/// VGA color codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VgaColor {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

/// VGA character with color attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct VgaChar {
    character: u8,
    color: u8,
}

impl VgaChar {
    fn new(character: u8, foreground: VgaColor, background: VgaColor) -> VgaChar {
        VgaChar { character, color: (background as u8) << 4 | (foreground as u8) }
    }
}

/// VGA text buffer
#[repr(transparent)]
struct VgaBuffer {
    chars: [[VgaChar; VGA_WIDTH]; VGA_HEIGHT],
}

/// VGA driver state
struct VgaState {
    buffer: &'static mut VgaBuffer,
    cursor_row: usize,
    cursor_col: usize,
    color: u8,
    tab_width: usize,
}

/// VGA text mode driver
pub struct VgaDriver {
    state: Mutex<VgaState>,
    characters_written: AtomicUsize,

    // Hardware ports
    crtc_index: UnsafeCell<Port<u8>>,
    crtc_data: UnsafeCell<Port<u8>>,
    seq_index: UnsafeCell<PortWriteOnly<u8>>,
    seq_data: UnsafeCell<Port<u8>>,
    gc_index: UnsafeCell<PortWriteOnly<u8>>,
    gc_data: UnsafeCell<Port<u8>>,
    ac_index: UnsafeCell<PortWriteOnly<u8>>,
    ac_write: UnsafeCell<PortWriteOnly<u8>>,
    ac_read: UnsafeCell<PortReadOnly<u8>>,
    input_status: UnsafeCell<PortReadOnly<u8>>,
}

impl VgaDriver {
    /// Create new VGA driver
    pub fn new() -> Self {
        let buffer = unsafe { &mut *(VGA_BUFFER_ADDR as *mut VgaBuffer) };

        VgaDriver {
            state: Mutex::new(VgaState {
                buffer,
                cursor_row: 0,
                cursor_col: 0,
                color: VgaChar::new(0, VgaColor::White, VgaColor::Black).color,
                tab_width: 4,
            }),
            characters_written: AtomicUsize::new(0),
            crtc_index: UnsafeCell::new(Port::new(VGA_CRTC_INDEX_COLOR)),
            crtc_data: UnsafeCell::new(Port::new(VGA_CRTC_DATA_COLOR)),
            seq_index: UnsafeCell::new(PortWriteOnly::new(VGA_SEQ_INDEX)),
            seq_data: UnsafeCell::new(Port::new(VGA_SEQ_DATA)),
            gc_index: UnsafeCell::new(PortWriteOnly::new(VGA_GC_INDEX)),
            gc_data: UnsafeCell::new(Port::new(VGA_GC_DATA)),
            ac_index: UnsafeCell::new(PortWriteOnly::new(VGA_AC_INDEX)),
            ac_write: UnsafeCell::new(PortWriteOnly::new(VGA_AC_WRITE)),
            ac_read: UnsafeCell::new(PortReadOnly::new(VGA_AC_READ)),
            input_status: UnsafeCell::new(PortReadOnly::new(VGA_INPUT_STATUS_1)),
        }
    }

    /// Initialize VGA hardware
    pub fn initialize(&self) -> Result<(), &'static str> {
        // Set up 80x25 text mode
        self.set_text_mode()?;

        // Clear screen
        self.clear_screen();

        // Enable cursor
        self.enable_cursor()?;

        // Update hardware cursor position
        self.update_cursor_position(0, 0)?;

        Ok(())
    }

    /// Set VGA to text mode
    fn set_text_mode(&self) -> Result<(), &'static str> {
        // Disable interrupts during mode switch
        x86_64::instructions::interrupts::without_interrupts(|| {
            unsafe {
                // Set miscellaneous register
                let mut misc_port = PortWriteOnly::new(VGA_MISC_WRITE);
                misc_port.write(0x67u8);

                // Reset sequencer
                unsafe {
                    (*self.seq_index.get()).write(0x00);
                }
                unsafe {
                    (*self.seq_data.get()).write(0x03);
                }

                // Set sequencer registers
                let seq_regs = [0x03, 0x00, 0x03, 0x00, 0x02];
                for (i, &val) in seq_regs.iter().enumerate() {
                    unsafe {
                        (*self.seq_index.get()).write(i as u8);
                    }
                    unsafe {
                        (*self.seq_data.get()).write(val);
                    }
                }

                // Unlock CRTC registers
                unsafe {
                    (*self.crtc_index.get()).write(0x03);
                }
                unsafe {
                    (*self.crtc_data.get()).write(0x80 | (*self.crtc_data.get()).read());
                }
                unsafe {
                    (*self.crtc_index.get()).write(0x11);
                }
                unsafe {
                    (*self.crtc_data.get()).write(0x7F & (*self.crtc_data.get()).read());
                }

                // Set CRTC registers for 80x25 text mode
                let crtc_regs = [
                    0x5F, 0x4F, 0x50, 0x82, 0x55, 0x81, 0xBF, 0x1F, 0x00, 0x47, 0x0D, 0x0E, 0x00,
                    0x00, 0x00, 0x50, 0x9C, 0x0E, 0x8F, 0x28, 0x1F, 0x96, 0xB9, 0xA3, 0xFF,
                ];

                for (i, &val) in crtc_regs.iter().enumerate() {
                    unsafe {
                        (*self.crtc_index.get()).write(i as u8);
                    }
                    unsafe {
                        (*self.crtc_data.get()).write(val);
                    }
                }

                // Set graphics controller registers
                let gc_regs = [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0E, 0x00, 0xFF];
                for (i, &val) in gc_regs.iter().enumerate() {
                    unsafe {
                        (*self.gc_index.get()).write(i as u8);
                    }
                    unsafe {
                        (*self.gc_data.get()).write(val);
                    }
                }

                // Set attribute controller registers
                let ac_regs = [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
                    0x3D, 0x3E, 0x3F, 0x0C, 0x00, 0x0F, 0x08, 0x00,
                ];

                // Reset attribute controller flip-flop
                unsafe {
                    (*self.input_status.get()).read();
                }

                for (i, &val) in ac_regs.iter().enumerate() {
                    unsafe {
                        (*self.ac_index.get()).write(i as u8);
                    }
                    unsafe {
                        (*self.ac_write.get()).write(val);
                    }
                }

                // Enable video
                unsafe {
                    (*self.ac_index.get()).write(0x20);
                }
            }
        });

        Ok(())
    }

    /// Clear the screen
    pub fn clear_screen(&self) {
        let mut state = self.state.lock();
        let blank = VgaChar::new(b' ', VgaColor::White, VgaColor::Black);

        for row in 0..VGA_HEIGHT {
            for col in 0..VGA_WIDTH {
                state.buffer.chars[row][col] = blank;
            }
        }

        state.cursor_row = 0;
        state.cursor_col = 0;
    }

    /// Set text colors
    pub fn set_colors(&self, foreground: VgaColor, background: VgaColor) {
        let mut state = self.state.lock();
        state.color = VgaChar::new(0, foreground, background).color;
    }

    /// Write a string to the screen
    pub fn write_string(&self, s: &str) {
        let mut state = self.state.lock();

        for byte in s.bytes() {
            match byte {
                b'\n' => self.new_line(&mut state),
                b'\r' => state.cursor_col = 0,
                b'\t' => {
                    let spaces = state.tab_width - (state.cursor_col % state.tab_width);
                    for _ in 0..spaces {
                        if state.cursor_col >= VGA_WIDTH {
                            self.new_line(&mut state);
                        }
                        self.write_byte(&mut state, b' ');
                    }
                }
                b'\x08' => {
                    // Backspace
                    if state.cursor_col > 0 {
                        state.cursor_col -= 1;
                        self.write_byte(&mut state, b' ');
                        state.cursor_col -= 1;
                    }
                }
                byte => {
                    if state.cursor_col >= VGA_WIDTH {
                        self.new_line(&mut state);
                    }
                    self.write_byte(&mut state, byte);
                }
            }

            self.characters_written.fetch_add(1, Ordering::Relaxed);
        }

        // Update hardware cursor
        let _ = self.update_cursor_position(state.cursor_row, state.cursor_col);
    }

    /// Write a single byte to current cursor position
    fn write_byte(&self, state: &mut VgaState, byte: u8) {
        let character = VgaChar { character: byte, color: state.color };

        state.buffer.chars[state.cursor_row][state.cursor_col] = character;
        state.cursor_col += 1;
    }

    /// Move to new line
    fn new_line(&self, state: &mut VgaState) {
        state.cursor_col = 0;

        if state.cursor_row < VGA_HEIGHT - 1 {
            state.cursor_row += 1;
        } else {
            // Scroll screen up
            self.scroll_up(state);
        }
    }

    /// Scroll screen up by one line
    fn scroll_up(&self, state: &mut VgaState) {
        for row in 1..VGA_HEIGHT {
            for col in 0..VGA_WIDTH {
                state.buffer.chars[row - 1][col] = state.buffer.chars[row][col];
            }
        }

        // Clear last line
        let blank = VgaChar::new(b' ', VgaColor::White, VgaColor::Black);
        for col in 0..VGA_WIDTH {
            state.buffer.chars[VGA_HEIGHT - 1][col] = blank;
        }
    }

    /// Enable hardware cursor
    fn enable_cursor(&self) -> Result<(), &'static str> {
        unsafe {
            // Enable cursor
            (*self.crtc_index.get()).write(0x0A);
            let cursor_start = (*self.crtc_data.get()).read() & 0xC0;
            (*self.crtc_data.get()).write(cursor_start | 14);

            // Set cursor end
            (*self.crtc_index.get()).write(0x0B);
            let cursor_end = (*self.crtc_data.get()).read() & 0xE0;
            (*self.crtc_data.get()).write(cursor_end | 15);
        }

        Ok(())
    }

    /// Disable hardware cursor
    pub fn disable_cursor(&self) -> Result<(), &'static str> {
        unsafe {
            (*self.crtc_index.get()).write(0x0A);
            (*self.crtc_data.get()).write(0x20);
        }

        Ok(())
    }

    /// Update hardware cursor position
    fn update_cursor_position(&self, row: usize, col: usize) -> Result<(), &'static str> {
        let position = (row * VGA_WIDTH + col) as u16;

        unsafe {
            // Set cursor location high byte
            (*self.crtc_index.get()).write(0x0E);
            (*self.crtc_data.get()).write((position >> 8) as u8);

            // Set cursor location low byte
            (*self.crtc_index.get()).write(0x0F);
            (*self.crtc_data.get()).write((position & 0xFF) as u8);
        }

        Ok(())
    }

    /// Set cursor position
    pub fn set_cursor(&self, row: usize, col: usize) -> Result<(), &'static str> {
        if row >= VGA_HEIGHT || col >= VGA_WIDTH {
            return Err("Cursor position out of bounds");
        }

        {
            let mut state = self.state.lock();
            state.cursor_row = row;
            state.cursor_col = col;
        }

        self.update_cursor_position(row, col)
    }

    /// Get cursor position
    pub fn get_cursor(&self) -> (usize, usize) {
        let state = self.state.lock();
        (state.cursor_row, state.cursor_col)
    }

    /// Write character at specific position with colors
    pub fn write_char_at(
        &self,
        row: usize,
        col: usize,
        character: u8,
        fg: VgaColor,
        bg: VgaColor,
    ) -> Result<(), &'static str> {
        if row >= VGA_HEIGHT || col >= VGA_WIDTH {
            return Err("Position out of bounds");
        }

        let mut state = self.state.lock();
        let vga_char = VgaChar::new(character, fg, bg);
        state.buffer.chars[row][col] = vga_char;

        Ok(())
    }

    /// Fill region with character and colors
    pub fn fill_region(
        &self,
        start_row: usize,
        start_col: usize,
        end_row: usize,
        end_col: usize,
        character: u8,
        fg: VgaColor,
        bg: VgaColor,
    ) -> Result<(), &'static str> {
        if start_row >= VGA_HEIGHT
            || start_col >= VGA_WIDTH
            || end_row >= VGA_HEIGHT
            || end_col >= VGA_WIDTH
        {
            return Err("Region out of bounds");
        }

        let mut state = self.state.lock();
        let vga_char = VgaChar::new(character, fg, bg);

        for row in start_row..=end_row {
            for col in start_col..=end_col {
                state.buffer.chars[row][col] = vga_char;
            }
        }

        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> VgaStats {
        VgaStats {
            characters_written: self.characters_written.load(Ordering::Relaxed),
            cursor_position: self.get_cursor(),
        }
    }
}

/// VGA driver statistics
#[derive(Debug, Clone)]
pub struct VgaStats {
    pub characters_written: usize,
    pub cursor_position: (usize, usize),
}

/// Global VGA driver instance
static mut VGA_DRIVER: Option<VgaDriver> = None;

/// Initialize VGA driver
pub fn init_vga() -> Result<(), &'static str> {
    let vga = VgaDriver::new();
    vga.initialize()?;

    unsafe {
        VGA_DRIVER = Some(vga);
    }

    Ok(())
}

/// Get VGA driver instance
pub fn get_vga() -> Option<&'static VgaDriver> {
    unsafe { VGA_DRIVER.as_ref() }
}

/// Write string to VGA (convenience function)
pub fn write_string(s: &str) {
    if let Some(vga) = get_vga() {
        vga.write_string(s);
    }
}

/// Set VGA colors (convenience function)
pub fn set_colors(foreground: VgaColor, background: VgaColor) {
    if let Some(vga) = get_vga() {
        vga.set_colors(foreground, background);
    }
}

/// Clear screen (convenience function)
pub fn clear_screen() {
    if let Some(vga) = get_vga() {
        vga.clear_screen();
    }
}
