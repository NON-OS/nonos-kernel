// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//!
//! Intel 8254 Programmable Interval Timer (PIT) Driver
//! **Complete 8254 interface**
//! **Accurate timing**
//! **TSC calibration**
//! **One-shot timers**
//! **Speaker control**
//! **Thread-safe design**
//!
//! ## 8254 PIT Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    8254 PIT Block Diagram                       │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  1.193182 MHz ──┬──► [Channel 0] ──► IRQ 0 (System Timer)       │
//! │                 │                                               │
//! │                 ├──► [Channel 1] ──► DRAM Refresh (obsolete)    │
//! │                 │                                               │
//! │                 └──► [Channel 2] ──► PC Speaker / Gate          │
//! │                                                                 │
//! │  I/O Ports:                                                     │
//! │    0x40 - Channel 0 data                                        │
//! │    0x41 - Channel 1 data                                        │
//! │    0x42 - Channel 2 data                                        │
//! │    0x43 - Command/Mode register                                 │
//! │    0x61 - System control port B (speaker gate)                  │
//! │                                                                 │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//! ## Operating Modes
//!
//! | Mode | Name                    | Description                          |
//! |------|-------------------------|--------------------------------------|
//! | 0    | Interrupt on Terminal   | One-shot countdown, output goes low  |
//! | 1    | Hardware Retriggerable  | One-shot, retrigger restarts         |
//! | 2    | Rate Generator          | Periodic square wave divisor         |
//! | 3    | Square Wave Generator   | Periodic 50% duty cycle              |
//! | 4    | Software Triggered      | One-shot strobe                      |
//! | 5    | Hardware Triggered      | Hardware strobe                      |

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::RwLock;

// ============================================================================
// Constants
// ============================================================================

/// PIT oscillator frequency in Hz (1.193182 MHz)
pub const PIT_FREQUENCY: u64 = 1193182;

/// Maximum divisor value (16-bit)
pub const MAX_DIVISOR: u16 = 65535;

/// Minimum divisor value
pub const MIN_DIVISOR: u16 = 1;

/// Maximum frequency achievable (PIT_FREQUENCY / 1)
pub const MAX_TIMER_FREQUENCY: u32 = 1193182;

/// Minimum frequency achievable (PIT_FREQUENCY / 65535)
pub const MIN_TIMER_FREQUENCY: u32 = 19; // ~18.2 Hz

/// Default system timer frequency (1000 Hz = 1ms ticks)
pub const DEFAULT_FREQUENCY: u32 = 1000;

// ============================================================================
// I/O Ports
// ============================================================================

/// PIT I/O port addresses
mod ports {
    /// Channel 0 data port (system timer)
    pub const CHANNEL0: u16 = 0x40;
    /// Channel 1 data port (DRAM refresh, obsolete)
    pub const CHANNEL1: u16 = 0x41;
    /// Channel 2 data port (PC speaker)
    pub const CHANNEL2: u16 = 0x42;
    /// Command/mode control register
    pub const COMMAND: u16 = 0x43;
    /// System control port B (speaker gate, timer gate)
    pub const SYSTEM_CONTROL_B: u16 = 0x61;
}

// ============================================================================
// Command Register Bits
// ============================================================================

/// Command register bit fields
mod command {
    /// BCD mode (0 = binary, 1 = BCD)
    pub const BCD_MODE: u8 = 0x01;

    /// Operating mode bits (bits 1-3)
    pub const MODE_MASK: u8 = 0x0E;
    pub const MODE_0: u8 = 0x00; // Interrupt on terminal count
    pub const MODE_1: u8 = 0x02; // Hardware retriggerable one-shot
    pub const MODE_2: u8 = 0x04; // Rate generator
    pub const MODE_3: u8 = 0x06; // Square wave generator
    pub const MODE_4: u8 = 0x08; // Software triggered strobe
    pub const MODE_5: u8 = 0x0A; // Hardware triggered strobe

    /// Access mode bits (bits 4-5)
    pub const ACCESS_MASK: u8 = 0x30;
    pub const ACCESS_LATCH: u8 = 0x00;  // Latch count value
    pub const ACCESS_LOBYTE: u8 = 0x10; // Read/write low byte only
    pub const ACCESS_HIBYTE: u8 = 0x20; // Read/write high byte only
    pub const ACCESS_LOHI: u8 = 0x30;   // Read/write low byte then high byte

    /// Channel select bits (bits 6-7)
    pub const CHANNEL_MASK: u8 = 0xC0;
    pub const CHANNEL_0: u8 = 0x00;
    pub const CHANNEL_1: u8 = 0x40;
    pub const CHANNEL_2: u8 = 0x80;
    pub const READ_BACK: u8 = 0xC0; // Read-back command

    /// Read-back command bits
    pub const READBACK_COUNT: u8 = 0x20;  // Don't latch count
    pub const READBACK_STATUS: u8 = 0x10; // Don't latch status
    pub const READBACK_CH0: u8 = 0x02;
    pub const READBACK_CH1: u8 = 0x04;
    pub const READBACK_CH2: u8 = 0x08;
}

/// System control port B bits
mod system_control {
    /// Timer 2 gate (enables channel 2 counting)
    pub const TIMER2_GATE: u8 = 0x01;
    /// Speaker data enable
    pub const SPEAKER_ENABLE: u8 = 0x02;
    /// Channel 2 output status (read-only)
    pub const TIMER2_OUTPUT: u8 = 0x20;
}

// ============================================================================
// Error Handling
// ============================================================================

/// PIT error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PitError {
    /// PIT not initialized
    NotInitialized = 0,
    /// Already initialized
    AlreadyInitialized = 1,
    /// Invalid frequency requested
    InvalidFrequency = 2,
    /// Invalid divisor value
    InvalidDivisor = 3,
    /// Invalid channel specified
    InvalidChannel = 4,
    /// Invalid operating mode
    InvalidMode = 5,
    /// Channel not available
    ChannelBusy = 6,
    /// Timeout waiting for operation
    Timeout = 7,
    /// Hardware access error
    HardwareError = 8,
    /// Calibration failed
    CalibrationFailed = 9,
    /// Speaker not available
    SpeakerUnavailable = 10,
    /// One-shot already pending
    OneShotPending = 11,
}

impl PitError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "PIT not initialized",
            Self::AlreadyInitialized => "PIT already initialized",
            Self::InvalidFrequency => "Invalid frequency requested",
            Self::InvalidDivisor => "Invalid divisor value",
            Self::InvalidChannel => "Invalid channel specified",
            Self::InvalidMode => "Invalid operating mode",
            Self::ChannelBusy => "Channel not available",
            Self::Timeout => "Timeout waiting for operation",
            Self::HardwareError => "Hardware access error",
            Self::CalibrationFailed => "Calibration failed",
            Self::SpeakerUnavailable => "Speaker not available",
            Self::OneShotPending => "One-shot timer already pending",
        }
    }
}

/// Result type for PIT operations
pub type PitResult<T> = Result<T, PitError>;

// ============================================================================
// Type Definitions
// ============================================================================

/// PIT channel identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    /// Channel 0: System timer (IRQ 0)
    Channel0 = 0,
    /// Channel 1: DRAM refresh (obsolete, don't use)
    Channel1 = 1,
    /// Channel 2: PC speaker / calibration
    Channel2 = 2,
}

impl Channel {
    /// Get the data port for this channel
    pub const fn data_port(&self) -> u16 {
        match self {
            Self::Channel0 => ports::CHANNEL0,
            Self::Channel1 => ports::CHANNEL1,
            Self::Channel2 => ports::CHANNEL2,
        }
    }

    /// Get the channel select bits for command register
    pub const fn select_bits(&self) -> u8 {
        match self {
            Self::Channel0 => command::CHANNEL_0,
            Self::Channel1 => command::CHANNEL_1,
            Self::Channel2 => command::CHANNEL_2,
        }
    }

    /// Get the read-back bit for this channel
    pub const fn readback_bit(&self) -> u8 {
        match self {
            Self::Channel0 => command::READBACK_CH0,
            Self::Channel1 => command::READBACK_CH1,
            Self::Channel2 => command::READBACK_CH2,
        }
    }

    /// Create from channel number
    pub const fn from_num(num: u8) -> Option<Self> {
        match num {
            0 => Some(Self::Channel0),
            1 => Some(Self::Channel1),
            2 => Some(Self::Channel2),
            _ => None,
        }
    }
}

/// PIT operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Mode {
    /// Mode 0: Interrupt on terminal count
    /// Output goes low after count reaches 0
    InterruptOnTerminal = 0,

    /// Mode 1: Hardware retriggerable one-shot
    /// Gate signal restarts countdown
    HardwareOneShot = 1,

    /// Mode 2: Rate generator
    /// Periodic pulses at programmed rate
    #[default]
    RateGenerator = 2,

    /// Mode 3: Square wave generator
    /// 50% duty cycle square wave
    SquareWave = 3,

    /// Mode 4: Software triggered strobe
    /// One-shot strobe pulse
    SoftwareStrobe = 4,

    /// Mode 5: Hardware triggered strobe
    /// Strobe on gate signal
    HardwareStrobe = 5,
}

impl Mode {
    /// Get the mode bits for command register
    pub const fn bits(&self) -> u8 {
        match self {
            Self::InterruptOnTerminal => command::MODE_0,
            Self::HardwareOneShot => command::MODE_1,
            Self::RateGenerator => command::MODE_2,
            Self::SquareWave => command::MODE_3,
            Self::SoftwareStrobe => command::MODE_4,
            Self::HardwareStrobe => command::MODE_5,
        }
    }

    /// Create from mode number
    pub const fn from_num(num: u8) -> Option<Self> {
        match num {
            0 => Some(Self::InterruptOnTerminal),
            1 => Some(Self::HardwareOneShot),
            2 => Some(Self::RateGenerator),
            3 => Some(Self::SquareWave),
            4 => Some(Self::SoftwareStrobe),
            5 => Some(Self::HardwareStrobe),
            _ => None,
        }
    }

    /// Is this a periodic mode?
    pub const fn is_periodic(&self) -> bool {
        matches!(self, Self::RateGenerator | Self::SquareWave)
    }

    /// Is this a one-shot mode?
    pub const fn is_oneshot(&self) -> bool {
        matches!(
            self,
            Self::InterruptOnTerminal | Self::HardwareOneShot |
            Self::SoftwareStrobe | Self::HardwareStrobe
        )
    }
}

/// Access mode for reading/writing counter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessMode {
    /// Latch current count value
    Latch = 0,
    /// Access low byte only
    LowByte = 1,
    /// Access high byte only
    HighByte = 2,
    /// Access low byte then high byte
    LowHigh = 3,
}

impl AccessMode {
    /// Get the access mode bits for command register
    pub const fn bits(&self) -> u8 {
        match self {
            Self::Latch => command::ACCESS_LATCH,
            Self::LowByte => command::ACCESS_LOBYTE,
            Self::HighByte => command::ACCESS_HIBYTE,
            Self::LowHigh => command::ACCESS_LOHI,
        }
    }
}

// ============================================================================
// Channel State
// ============================================================================

/// State for a single PIT channel
#[derive(Debug)]
struct ChannelState {
    /// Is this channel configured?
    configured: bool,
    /// Current operating mode
    mode: Mode,
    /// Current divisor value
    divisor: u16,
    /// Configured frequency in Hz
    frequency_hz: u32,
    /// Number of interrupts/ticks
    tick_count: AtomicU64,
    /// Is a one-shot pending?
    oneshot_pending: AtomicBool,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            configured: false,
            mode: Mode::RateGenerator,
            divisor: 0,
            frequency_hz: 0,
            tick_count: AtomicU64::new(0),
            oneshot_pending: AtomicBool::new(false),
        }
    }
}

// ============================================================================
// PIT Statistics
// ============================================================================

/// PIT statistics
#[derive(Debug, Clone, Default)]
pub struct PitStatistics {
    /// Is PIT initialized?
    pub initialized: bool,
    /// Channel 0 configured frequency
    pub channel0_frequency: u32,
    /// Channel 0 divisor
    pub channel0_divisor: u16,
    /// Channel 0 tick count
    pub channel0_ticks: u64,
    /// Channel 2 configured frequency
    pub channel2_frequency: u32,
    /// Channel 2 divisor
    pub channel2_divisor: u16,
    /// Total calibrations performed
    pub calibrations: u64,
    /// Last calibration result (TSC frequency)
    pub last_calibration_hz: u64,
    /// Speaker beeps generated
    pub speaker_beeps: u64,
    /// One-shot timers completed
    pub oneshot_completed: u64,
}

// ============================================================================
// Global State
// ============================================================================

/// PIT initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Channel states
static CHANNELS: RwLock<[ChannelState; 3]> = RwLock::new([
    ChannelState {
        configured: false,
        mode: Mode::RateGenerator,
        divisor: 0,
        frequency_hz: 0,
        tick_count: AtomicU64::new(0),
        oneshot_pending: AtomicBool::new(false),
    },
    ChannelState {
        configured: false,
        mode: Mode::RateGenerator,
        divisor: 0,
        frequency_hz: 0,
        tick_count: AtomicU64::new(0),
        oneshot_pending: AtomicBool::new(false),
    },
    ChannelState {
        configured: false,
        mode: Mode::RateGenerator,
        divisor: 0,
        frequency_hz: 0,
        tick_count: AtomicU64::new(0),
        oneshot_pending: AtomicBool::new(false),
    },
]);

/// Statistics counters
static STATS_CALIBRATIONS: AtomicU64 = AtomicU64::new(0);
static STATS_LAST_CALIBRATION: AtomicU64 = AtomicU64::new(0);
static STATS_SPEAKER_BEEPS: AtomicU64 = AtomicU64::new(0);
static STATS_ONESHOT_COMPLETED: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Port I/O
// ============================================================================

/// Read byte from I/O port
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nostack, preserves_flags, nomem)
    );
    value
}

/// Write byte to I/O port
#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("al") value,
        in("dx") port,
        options(nostack, preserves_flags, nomem)
    );
}

/// Small I/O delay (for PIT timing requirements)
#[inline]
fn io_delay() {
    unsafe {
        // Read from unused port for delay
        inb(0x80);
    }
}

// ============================================================================
// Low-Level Channel Operations
// ============================================================================

/// Configure a PIT channel
fn configure_channel_raw(channel: Channel, mode: Mode, divisor: u16) {
    let command_byte = channel.select_bits() | AccessMode::LowHigh.bits() | mode.bits();

    unsafe {
        // Send command byte
        outb(ports::COMMAND, command_byte);
        io_delay();

        // Send divisor low byte
        outb(channel.data_port(), (divisor & 0xFF) as u8);
        io_delay();

        // Send divisor high byte
        outb(channel.data_port(), ((divisor >> 8) & 0xFF) as u8);
        io_delay();
    }
}

/// Read current count from a channel
fn read_channel_count(channel: Channel) -> u16 {
    // Latch the count
    let latch_command = channel.select_bits() | AccessMode::Latch.bits();

    unsafe {
        outb(ports::COMMAND, latch_command);
        io_delay();

        // Read low byte
        let low = inb(channel.data_port());
        io_delay();

        // Read high byte
        let high = inb(channel.data_port());

        ((high as u16) << 8) | (low as u16)
    }
}

/// Read channel status using read-back command
fn read_channel_status(channel: Channel) -> u8 {
    unsafe {
        // Read-back command: latch status only
        let readback = command::READ_BACK | command::READBACK_COUNT | channel.readback_bit();
        outb(ports::COMMAND, readback);
        io_delay();

        inb(channel.data_port())
    }
}

// ============================================================================
// Frequency and Divisor Calculations
// ============================================================================

/// Calculate divisor for desired frequency
pub fn frequency_to_divisor(frequency_hz: u32) -> PitResult<u16> {
    if frequency_hz == 0 {
        return Err(PitError::InvalidFrequency);
    }

    if frequency_hz > MAX_TIMER_FREQUENCY {
        return Err(PitError::InvalidFrequency);
    }

    let divisor = PIT_FREQUENCY / frequency_hz as u64;

    if divisor > MAX_DIVISOR as u64 {
        return Err(PitError::InvalidFrequency);
    }

    if divisor < MIN_DIVISOR as u64 {
        return Err(PitError::InvalidFrequency);
    }

    Ok(divisor as u16)
}

/// Calculate actual frequency for a given divisor
pub fn divisor_to_frequency(divisor: u16) -> u32 {
    if divisor == 0 {
        return 0;
    }
    (PIT_FREQUENCY / divisor as u64) as u32
}

/// Calculate divisor for desired period in microseconds
pub fn period_us_to_divisor(period_us: u32) -> PitResult<u16> {
    if period_us == 0 {
        return Err(PitError::InvalidDivisor);
    }

    // divisor = period_us * PIT_FREQUENCY / 1_000_000
    let divisor = (period_us as u64 * PIT_FREQUENCY) / 1_000_000;

    if divisor > MAX_DIVISOR as u64 {
        return Err(PitError::InvalidDivisor);
    }

    if divisor < MIN_DIVISOR as u64 {
        return Err(PitError::InvalidDivisor);
    }

    Ok(divisor as u16)
}

/// Calculate period in nanoseconds for a given divisor
pub fn divisor_to_period_ns(divisor: u16) -> u64 {
    if divisor == 0 {
        return 0;
    }
    // period_ns = divisor * 1_000_000_000 / PIT_FREQUENCY
    (divisor as u64 * 1_000_000_000) / PIT_FREQUENCY
}

/// Calculate the error between desired and actual frequency
pub fn frequency_error(desired_hz: u32, divisor: u16) -> i32 {
    let actual = divisor_to_frequency(divisor);
    actual as i32 - desired_hz as i32
}

// ============================================================================
// Channel 0 - System Timer
// ============================================================================

/// Initialize channel 0 as system timer
pub fn init_system_timer(frequency_hz: u32) -> PitResult<()> {
    let divisor = frequency_to_divisor(frequency_hz)?;
    init_system_timer_with_divisor(divisor)
}

/// Initialize channel 0 with specific divisor
pub fn init_system_timer_with_divisor(divisor: u16) -> PitResult<()> {
    if divisor == 0 {
        return Err(PitError::InvalidDivisor);
    }

    configure_channel_raw(Channel::Channel0, Mode::RateGenerator, divisor);

    let frequency = divisor_to_frequency(divisor);

    {
        let mut channels = CHANNELS.write();
        channels[0].configured = true;
        channels[0].mode = Mode::RateGenerator;
        channels[0].divisor = divisor;
        channels[0].frequency_hz = frequency;
        channels[0].tick_count = AtomicU64::new(0);
    }

    Ok(())
}

/// Handle channel 0 interrupt (call from IRQ 0 handler)
pub fn system_timer_tick() {
    let channels = CHANNELS.read();
    channels[0].tick_count.fetch_add(1, Ordering::Relaxed);
}

/// Get channel 0 tick count
pub fn get_system_timer_ticks() -> u64 {
    CHANNELS.read()[0].tick_count.load(Ordering::Relaxed)
}

/// Get channel 0 frequency
pub fn get_system_timer_frequency() -> u32 {
    CHANNELS.read()[0].frequency_hz
}

/// Get time elapsed since init in nanoseconds (based on tick count)
pub fn elapsed_ns() -> u64 {
    let channels = CHANNELS.read();
    let ticks = channels[0].tick_count.load(Ordering::Relaxed);
    let divisor = channels[0].divisor;

    if divisor == 0 {
        return 0;
    }

    // Each tick is (divisor / PIT_FREQUENCY) seconds
    // = (divisor * 1_000_000_000) / PIT_FREQUENCY nanoseconds
    ticks * divisor_to_period_ns(divisor)
}

/// Get time elapsed in milliseconds
pub fn elapsed_ms() -> u64 {
    elapsed_ns() / 1_000_000
}

// ============================================================================
// Channel 2 - Speaker and Calibration
// ============================================================================

/// Enable channel 2 gate (allows counter to run)
fn enable_channel2_gate() {
    unsafe {
        let control = inb(ports::SYSTEM_CONTROL_B);
        outb(ports::SYSTEM_CONTROL_B, control | system_control::TIMER2_GATE);
    }
}

/// Disable channel 2 gate
fn disable_channel2_gate() {
    unsafe {
        let control = inb(ports::SYSTEM_CONTROL_B);
        outb(ports::SYSTEM_CONTROL_B, control & !system_control::TIMER2_GATE);
    }
}

/// Get channel 2 output state
fn get_channel2_output() -> bool {
    unsafe { (inb(ports::SYSTEM_CONTROL_B) & system_control::TIMER2_OUTPUT) != 0 }
}

/// Enable PC speaker
fn enable_speaker() {
    unsafe {
        let control = inb(ports::SYSTEM_CONTROL_B);
        outb(
            ports::SYSTEM_CONTROL_B,
            control | system_control::SPEAKER_ENABLE | system_control::TIMER2_GATE,
        );
    }
}

/// Disable PC speaker
fn disable_speaker() {
    unsafe {
        let control = inb(ports::SYSTEM_CONTROL_B);
        outb(
            ports::SYSTEM_CONTROL_B,
            control & !(system_control::SPEAKER_ENABLE | system_control::TIMER2_GATE),
        );
    }
}

/// Generate a beep at specified frequency for duration
pub fn beep(frequency_hz: u32, duration_ms: u32) -> PitResult<()> {
    let divisor = frequency_to_divisor(frequency_hz)?;

    // Configure channel 2 for square wave
    configure_channel_raw(Channel::Channel2, Mode::SquareWave, divisor);

    // Enable speaker
    enable_speaker();

    STATS_SPEAKER_BEEPS.fetch_add(1, Ordering::Relaxed);

    // Wait for duration
    pit_sleep_ms(duration_ms as u64);

    // Disable speaker
    disable_speaker();

    Ok(())
}

/// Start continuous tone at frequency (call stop_tone to stop)
pub fn start_tone(frequency_hz: u32) -> PitResult<()> {
    let divisor = frequency_to_divisor(frequency_hz)?;

    configure_channel_raw(Channel::Channel2, Mode::SquareWave, divisor);
    enable_speaker();

    {
        let mut channels = CHANNELS.write();
        channels[2].configured = true;
        channels[2].mode = Mode::SquareWave;
        channels[2].divisor = divisor;
        channels[2].frequency_hz = frequency_hz;
    }

    STATS_SPEAKER_BEEPS.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Stop continuous tone
pub fn stop_tone() {
    disable_speaker();

    let mut channels = CHANNELS.write();
    channels[2].configured = false;
}

// ============================================================================
// One-Shot Timer (Channel 2)
// ============================================================================

/// Start a one-shot timer on channel 2
pub fn start_oneshot(duration_us: u32) -> PitResult<()> {
    let divisor = period_us_to_divisor(duration_us)?;

    {
        let channels = CHANNELS.read();
        if channels[2].oneshot_pending.load(Ordering::Relaxed) {
            return Err(PitError::OneShotPending);
        }
    }

    // Configure channel 2 for one-shot mode
    configure_channel_raw(Channel::Channel2, Mode::InterruptOnTerminal, divisor);

    {
        let mut channels = CHANNELS.write();
        channels[2].configured = true;
        channels[2].mode = Mode::InterruptOnTerminal;
        channels[2].divisor = divisor;
        channels[2].oneshot_pending.store(true, Ordering::Relaxed);
    }

    // Enable the gate to start counting
    enable_channel2_gate();

    Ok(())
}

/// Wait for one-shot timer to complete
pub fn wait_oneshot() -> PitResult<()> {
    // Wait for output to go low (one-shot complete)
    let mut timeout = 1_000_000u32;
    while get_channel2_output() && timeout > 0 {
        timeout -= 1;
        core::hint::spin_loop();
    }

    if timeout == 0 {
        return Err(PitError::Timeout);
    }

    {
        let channels = CHANNELS.read();
        channels[2].oneshot_pending.store(false, Ordering::Relaxed);
    }

    STATS_ONESHOT_COMPLETED.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

/// Execute a precise one-shot delay
pub fn oneshot_delay_us(duration_us: u32) -> PitResult<()> {
    start_oneshot(duration_us)?;
    wait_oneshot()
}

// ============================================================================
// TSC Calibration
// ============================================================================

/// Read TSC
#[inline]
fn rdtsc() -> u64 {
    let hi: u32;
    let lo: u32;
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Calibrate TSC using PIT channel 2
pub fn calibrate_tsc() -> PitResult<u64> {
    calibrate_tsc_with_duration(50) // 50ms calibration
}

/// Calibrate TSC with specified duration in milliseconds
pub fn calibrate_tsc_with_duration(duration_ms: u32) -> PitResult<u64> {
    // Calculate divisor for the calibration period
    // We want to count for duration_ms milliseconds
    let frequency_hz = 1000 / duration_ms.max(1);
    let divisor = if frequency_hz < MIN_TIMER_FREQUENCY {
        MAX_DIVISOR
    } else {
        frequency_to_divisor(frequency_hz)?
    };

    // The actual period in nanoseconds
    let period_ns = divisor_to_period_ns(divisor);

    unsafe {
        // Save current speaker port state
        let saved_control = inb(ports::SYSTEM_CONTROL_B);

        // Configure channel 2 for one-shot mode
        configure_channel_raw(Channel::Channel2, Mode::InterruptOnTerminal, divisor);

        // Disable speaker, enable gate
        outb(
            ports::SYSTEM_CONTROL_B,
            (saved_control & !system_control::SPEAKER_ENABLE) | system_control::TIMER2_GATE,
        );

        // Wait for output to go high (counter loaded)
        let mut timeout = 100_000u32;
        while !get_channel2_output() && timeout > 0 {
            timeout -= 1;
        }

        // Read start TSC
        let start_tsc = rdtsc();

        // Wait for output to go low (countdown complete)
        timeout = 100_000_000;
        while get_channel2_output() && timeout > 0 {
            timeout -= 1;
            core::hint::spin_loop();
        }

        // Read end TSC
        let end_tsc = rdtsc();

        // Restore speaker port
        outb(ports::SYSTEM_CONTROL_B, saved_control);

        if timeout == 0 {
            return Err(PitError::CalibrationFailed);
        }

        // Calculate TSC frequency
        let tsc_ticks = end_tsc.saturating_sub(start_tsc);
        if tsc_ticks == 0 || period_ns == 0 {
            return Err(PitError::CalibrationFailed);
        }

        // TSC frequency = ticks / time = ticks * 1_000_000_000 / period_ns
        let frequency = (tsc_ticks * 1_000_000_000) / period_ns;

        STATS_CALIBRATIONS.fetch_add(1, Ordering::Relaxed);
        STATS_LAST_CALIBRATION.store(frequency, Ordering::Relaxed);

        Ok(frequency)
    }
}

/// Perform multiple calibrations and return median
pub fn calibrate_tsc_accurate() -> PitResult<u64> {
    const NUM_SAMPLES: usize = 5;
    let mut samples = [0u64; NUM_SAMPLES];
    let mut valid = 0;

    for sample in samples.iter_mut() {
        if let Ok(freq) = calibrate_tsc_with_duration(20) {
            *sample = freq;
            valid += 1;
        }
    }

    if valid < 3 {
        return Err(PitError::CalibrationFailed);
    }

    // Sort and return median
    samples[..valid].sort_unstable();
    Ok(samples[valid / 2])
}

// ============================================================================
// Sleep Functions
// ============================================================================

/// Busy-wait sleep using system timer ticks
pub fn pit_sleep_ticks(ticks: u64) {
    let start = get_system_timer_ticks();
    while get_system_timer_ticks() - start < ticks {
        core::hint::spin_loop();
    }
}

/// Busy-wait sleep in milliseconds
pub fn pit_sleep_ms(ms: u64) {
    let frequency = get_system_timer_frequency() as u64;
    if frequency == 0 {
        // Fallback: use approximate loop
        for _ in 0..ms * 10000 {
            core::hint::spin_loop();
        }
        return;
    }

    let ticks = (ms * frequency) / 1000;
    pit_sleep_ticks(ticks);
}

/// Busy-wait sleep in microseconds (less accurate)
pub fn pit_sleep_us(us: u64) {
    let frequency = get_system_timer_frequency() as u64;
    if frequency == 0 {
        for _ in 0..us * 10 {
            core::hint::spin_loop();
        }
        return;
    }

    let ticks = (us * frequency) / 1_000_000;
    if ticks == 0 {
        // Less than one tick, busy wait
        for _ in 0..us {
            core::hint::spin_loop();
        }
    } else {
        pit_sleep_ticks(ticks);
    }
}

/// Sleep using PIT (legacy API compatibility)
pub fn pit_sleep(ms: u64) {
    pit_sleep_ms(ms);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize PIT with default settings
pub fn init() -> PitResult<()> {
    init_with_frequency(DEFAULT_FREQUENCY)
}

/// Initialize PIT with specified system timer frequency
pub fn init_with_frequency(frequency_hz: u32) -> PitResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(PitError::AlreadyInitialized);
    }

    // Initialize channel 0 as system timer
    init_system_timer(frequency_hz)?;

    Ok(())
}

/// Initialize PIT for periodic interrupts (legacy API)
pub fn init_pit(freq_hz: u32) {
    let _ = init_with_frequency(freq_hz);
}

/// Check if PIT is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

/// Reset PIT to default state
pub fn reset() -> PitResult<()> {
    // Disable channel 2 speaker
    disable_speaker();

    // Reset all channel states
    {
        let mut channels = CHANNELS.write();
        for channel in channels.iter_mut() {
            channel.configured = false;
            channel.mode = Mode::RateGenerator;
            channel.divisor = 0;
            channel.frequency_hz = 0;
            channel.tick_count = AtomicU64::new(0);
            channel.oneshot_pending = AtomicBool::new(false);
        }
    }

    INITIALIZED.store(false, Ordering::SeqCst);

    Ok(())
}

// ============================================================================
// Channel Status and Information
// ============================================================================

/// Get channel configuration
pub fn get_channel_config(channel: Channel) -> Option<(Mode, u16, u32)> {
    let channels = CHANNELS.read();
    let ch = &channels[channel as usize];

    if ch.configured {
        Some((ch.mode, ch.divisor, ch.frequency_hz))
    } else {
        None
    }
}

/// Read current count from channel
pub fn read_count(channel: Channel) -> u16 {
    read_channel_count(channel)
}

/// Read channel status
pub fn read_status(channel: Channel) -> u8 {
    read_channel_status(channel)
}

/// Check if channel output is high
pub fn is_output_high(channel: Channel) -> bool {
    let status = read_channel_status(channel);
    (status & 0x80) != 0
}

// ============================================================================
// Statistics
// ============================================================================

/// Get PIT statistics
pub fn get_statistics() -> PitStatistics {
    let channels = CHANNELS.read();

    PitStatistics {
        initialized: INITIALIZED.load(Ordering::Relaxed),
        channel0_frequency: channels[0].frequency_hz,
        channel0_divisor: channels[0].divisor,
        channel0_ticks: channels[0].tick_count.load(Ordering::Relaxed),
        channel2_frequency: channels[2].frequency_hz,
        channel2_divisor: channels[2].divisor,
        calibrations: STATS_CALIBRATIONS.load(Ordering::Relaxed),
        last_calibration_hz: STATS_LAST_CALIBRATION.load(Ordering::Relaxed),
        speaker_beeps: STATS_SPEAKER_BEEPS.load(Ordering::Relaxed),
        oneshot_completed: STATS_ONESHOT_COMPLETED.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Calculate the best divisor for a target frequency with minimum error
pub fn find_best_divisor(target_hz: u32) -> Option<(u16, u32, i32)> {
    if target_hz == 0 || target_hz > MAX_TIMER_FREQUENCY {
        return None;
    }

    let ideal_divisor = PIT_FREQUENCY / target_hz as u64;

    // Check divisor and divisor+1 for best match
    let candidates = [
        ideal_divisor.saturating_sub(1),
        ideal_divisor,
        ideal_divisor.saturating_add(1),
    ];

    let mut best_divisor = 0u16;
    let mut best_frequency = 0u32;
    let mut best_error = i32::MAX;

    for &div in &candidates {
        if div < MIN_DIVISOR as u64 || div > MAX_DIVISOR as u64 {
            continue;
        }

        let divisor = div as u16;
        let actual_freq = divisor_to_frequency(divisor);
        let error = (actual_freq as i32 - target_hz as i32).abs();

        if error < best_error {
            best_divisor = divisor;
            best_frequency = actual_freq;
            best_error = error;
        }
    }

    if best_divisor > 0 {
        Some((best_divisor, best_frequency, best_error))
    } else {
        None
    }
}

/// Get the maximum achievable frequency
pub const fn max_frequency() -> u32 {
    MAX_TIMER_FREQUENCY
}

/// Get the minimum achievable frequency
pub const fn min_frequency() -> u32 {
    MIN_TIMER_FREQUENCY
}

/// Get the PIT base oscillator frequency
pub const fn oscillator_frequency() -> u64 {
    PIT_FREQUENCY
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pit_error_messages() {
        assert_eq!(PitError::NotInitialized.as_str(), "PIT not initialized");
        assert_eq!(PitError::InvalidFrequency.as_str(), "Invalid frequency requested");
        assert_eq!(PitError::CalibrationFailed.as_str(), "Calibration failed");
    }

    #[test]
    fn test_channel_ports() {
        assert_eq!(Channel::Channel0.data_port(), 0x40);
        assert_eq!(Channel::Channel1.data_port(), 0x41);
        assert_eq!(Channel::Channel2.data_port(), 0x42);
    }

    #[test]
    fn test_channel_select_bits() {
        assert_eq!(Channel::Channel0.select_bits(), 0x00);
        assert_eq!(Channel::Channel1.select_bits(), 0x40);
        assert_eq!(Channel::Channel2.select_bits(), 0x80);
    }

    #[test]
    fn test_mode_bits() {
        assert_eq!(Mode::InterruptOnTerminal.bits(), 0x00);
        assert_eq!(Mode::HardwareOneShot.bits(), 0x02);
        assert_eq!(Mode::RateGenerator.bits(), 0x04);
        assert_eq!(Mode::SquareWave.bits(), 0x06);
        assert_eq!(Mode::SoftwareStrobe.bits(), 0x08);
        assert_eq!(Mode::HardwareStrobe.bits(), 0x0A);
    }

    #[test]
    fn test_mode_properties() {
        assert!(Mode::RateGenerator.is_periodic());
        assert!(Mode::SquareWave.is_periodic());
        assert!(!Mode::InterruptOnTerminal.is_periodic());

        assert!(Mode::InterruptOnTerminal.is_oneshot());
        assert!(Mode::HardwareOneShot.is_oneshot());
        assert!(!Mode::RateGenerator.is_oneshot());
    }

    #[test]
    fn test_frequency_to_divisor() {
        // 1000 Hz should give divisor of ~1193
        let divisor = frequency_to_divisor(1000).unwrap();
        assert_eq!(divisor, 1193);

        // 100 Hz should give divisor of ~11932
        let divisor = frequency_to_divisor(100).unwrap();
        assert_eq!(divisor, 11931);

        // 0 Hz should fail
        assert!(frequency_to_divisor(0).is_err());

        // Too high frequency should fail
        assert!(frequency_to_divisor(2_000_000).is_err());
    }

    #[test]
    fn test_divisor_to_frequency() {
        assert_eq!(divisor_to_frequency(1193), 1000);
        assert_eq!(divisor_to_frequency(11932), 100);
        assert_eq!(divisor_to_frequency(0), 0);
    }

    #[test]
    fn test_divisor_to_period_ns() {
        // Divisor of 1193 should give ~1ms period
        let period = divisor_to_period_ns(1193);
        assert!(period > 990_000 && period < 1_010_000); // ~1ms with some tolerance
    }

    #[test]
    fn test_find_best_divisor() {
        let result = find_best_divisor(1000);
        assert!(result.is_some());

        let (divisor, actual_freq, error) = result.unwrap();
        assert!(divisor > 0);
        assert!(actual_freq > 990 && actual_freq < 1010);
        assert!(error.abs() < 10);
    }

    #[test]
    fn test_access_mode_bits() {
        assert_eq!(AccessMode::Latch.bits(), 0x00);
        assert_eq!(AccessMode::LowByte.bits(), 0x10);
        assert_eq!(AccessMode::HighByte.bits(), 0x20);
        assert_eq!(AccessMode::LowHigh.bits(), 0x30);
    }

    #[test]
    fn test_channel_from_num() {
        assert_eq!(Channel::from_num(0), Some(Channel::Channel0));
        assert_eq!(Channel::from_num(1), Some(Channel::Channel1));
        assert_eq!(Channel::from_num(2), Some(Channel::Channel2));
        assert_eq!(Channel::from_num(3), None);
    }

    #[test]
    fn test_mode_from_num() {
        assert_eq!(Mode::from_num(0), Some(Mode::InterruptOnTerminal));
        assert_eq!(Mode::from_num(2), Some(Mode::RateGenerator));
        assert_eq!(Mode::from_num(3), Some(Mode::SquareWave));
        assert_eq!(Mode::from_num(6), None);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PIT_FREQUENCY, 1193182);
        assert_eq!(MAX_DIVISOR, 65535);
        assert_eq!(MIN_DIVISOR, 1);
        assert_eq!(DEFAULT_FREQUENCY, 1000);
    }

    #[test]
    fn test_statistics_default() {
        let stats = PitStatistics::default();
        assert!(!stats.initialized);
        assert_eq!(stats.channel0_frequency, 0);
        assert_eq!(stats.calibrations, 0);
    }
}
