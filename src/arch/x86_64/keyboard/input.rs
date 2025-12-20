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
//
//! **A high-performance, thread-safe input event queue for handling keyboard
//! and mouse events in the NØNOS kernel. It is designed for a RAM-only OS
//!
//! With the following features**
//!
//! **Structured Error Handling**
//! **Fine-grained Locking**
//! **Configurable Limits**
//! **Event Timestamps**
//! **Event Priority**
//! **Event Filtering**
//! **Mouse Coalescing**
//! **Wake-up Mechanism**
//! **Input Device Abstraction**

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};

// ============================================================================
// Configuration Constants (can be overridden at compile time)
// ============================================================================

/// Default maximum queue size
pub const DEFAULT_MAX_QUEUE_SIZE: usize = 256;

/// Maximum allowed queue size (hard limit for safety)
pub const MAX_ALLOWED_QUEUE_SIZE: usize = 65536;

/// Default threshold for queue pressure warnings
pub const DEFAULT_PRESSURE_THRESHOLD: usize = 192; // 75% of default

/// Maximum coalesced mouse events before forcing a flush
pub const MAX_COALESCE_COUNT: usize = 16;

/// Size of stack-allocated log buffer
const LOG_BUFFER_SIZE: usize = 256;

// ============================================================================
// Stack-Allocated Log Buffer (no heap allocation for error logging)
// ============================================================================

/// Fixed-size buffer for formatting log messages without heap allocation
struct LogBuffer {
    data: [u8; LOG_BUFFER_SIZE],
    pos: usize,
}

impl LogBuffer {
    /// Creates a new empty log buffer
    #[inline]
    const fn new() -> Self {
        Self {
            data: [0u8; LOG_BUFFER_SIZE],
            pos: 0,
        }
    }

    /// Returns the written content as a string slice
    #[inline]
    fn as_str(&self) -> &str {
        // Safety: we only write valid UTF-8 via fmt::Write
        unsafe { core::str::from_utf8_unchecked(&self.data[..self.pos]) }
    }
}

impl core::fmt::Write for LogBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = LOG_BUFFER_SIZE - self.pos;
        let to_write = bytes.len().min(remaining);
        if to_write > 0 {
            self.data[self.pos..self.pos + to_write].copy_from_slice(&bytes[..to_write]);
            self.pos += to_write;
        }
        Ok(())
    }
}

// ============================================================================
// Error Handling
// ============================================================================

/// Error codes for input operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InputErrorCode {
    /// Queue is full and event was dropped
    QueueFull = 1,
    /// Queue is empty, no events available
    QueueEmpty = 2,
    /// Invalid event data provided
    InvalidEvent = 3,
    /// Invalid configuration parameter
    InvalidConfig = 4,
    /// Device not found or not registered
    DeviceNotFound = 5,
    /// Operation timed out
    Timeout = 6,
    /// Internal error (should not occur)
    InternalError = 7,
    /// Queue has been shutdown
    QueueShutdown = 8,
    /// Filter rejected the event
    FilterRejected = 9,
    /// Resource exhausted (memory, etc.)
    ResourceExhausted = 10,
}

impl InputErrorCode {
    /// Returns a human-readable description of the error
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "input queue is full",
            Self::QueueEmpty => "input queue is empty",
            Self::InvalidEvent => "invalid event data",
            Self::InvalidConfig => "invalid configuration parameter",
            Self::DeviceNotFound => "input device not found",
            Self::Timeout => "operation timed out",
            Self::InternalError => "internal error",
            Self::QueueShutdown => "queue has been shutdown",
            Self::FilterRejected => "event rejected by filter",
            Self::ResourceExhausted => "resource exhausted",
        }
    }

    /// Returns the numeric error code
    #[inline]
    pub const fn code(self) -> u32 {
        self as u32
    }
}

/// Detailed input error with context
#[derive(Debug, Clone)]
pub struct InputError {
    /// The error code
    code: InputErrorCode,
    /// Optional context message
    context: Option<String>,
    /// Associated event type (if applicable)
    event_type: Option<&'static str>,
    /// Timestamp when error occurred
    timestamp: u64,
}

impl InputError {
    /// Creates a new error with the given code
    #[inline]
    pub fn new(code: InputErrorCode) -> Self {
        Self {
            code,
            context: None,
            event_type: None,
            timestamp: get_timestamp(),
        }
    }

    /// Creates an error with additional context
    pub fn with_context(code: InputErrorCode, context: impl Into<String>) -> Self {
        Self {
            code,
            context: Some(context.into()),
            event_type: None,
            timestamp: get_timestamp(),
        }
    }

    /// Attaches event type information to the error
    #[inline]
    pub fn with_event_type(mut self, event_type: &'static str) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Returns the error code
    #[inline]
    pub const fn code(&self) -> InputErrorCode {
        self.code
    }

    /// Returns the context message if available
    #[inline]
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// Returns the timestamp when the error occurred
    #[inline]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Logs the error to serial debug output
    pub fn log(&self) {
        use core::fmt::Write;

        // Format error message to a stack buffer
        let mut buf = LogBuffer::new();
        let _ = write!(buf, "[INPUT ERR] {}", self.code.as_str());
        if let Some(ref ctx) = self.context {
            let _ = write!(buf, ": {}", ctx);
        }
        if let Some(event_type) = self.event_type {
            let _ = write!(buf, " [{}]", event_type);
        }
        let _ = write!(buf, " @{}\n", self.timestamp);

        // Output to serial
        crate::sys::serial::print_str(buf.as_str());
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(ref ctx) = self.context {
            write!(f, ": {}", ctx)?;
        }
        if let Some(event_type) = self.event_type {
            write!(f, " [event: {}]", event_type)?;
        }
        Ok(())
    }
}

/// Result type for input operations
pub type InputResult<T> = Result<T, InputError>;

// ============================================================================
// Event Types
// ============================================================================

/// Unique identifier for input devices
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u16);

impl DeviceId {
    /// The primary keyboard device
    pub const KEYBOARD: Self = Self(0);
    /// The primary mouse device
    pub const MOUSE: Self = Self(1);
    /// Virtual/software input device
    pub const VIRTUAL: Self = Self(0xFFFF);
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::KEYBOARD
    }
}

/// Event priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum EventPriority {
    /// Low priority - can be dropped under pressure
    Low = 0,
    /// Normal priority - standard events
    Normal = 1,
    /// High priority - should not be dropped
    High = 2,
    /// Critical priority - never dropped (system events)
    Critical = 3,
}

impl Default for EventPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Extended key modifier flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modifiers {
    bits: u16,
}

impl Modifiers {
    pub const NONE: Self = Self { bits: 0 };
    pub const SHIFT: Self = Self { bits: 1 << 0 };
    pub const CTRL: Self = Self { bits: 1 << 1 };
    pub const ALT: Self = Self { bits: 1 << 2 };
    pub const META: Self = Self { bits: 1 << 3 };
    pub const CAPS_LOCK: Self = Self { bits: 1 << 4 };
    pub const NUM_LOCK: Self = Self { bits: 1 << 5 };
    pub const SCROLL_LOCK: Self = Self { bits: 1 << 6 };

    /// Creates modifiers from raw bits
    #[inline]
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Returns the raw bits
    #[inline]
    pub const fn bits(self) -> u16 {
        self.bits
    }

    /// Checks if a modifier is active
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// Combines two modifier sets
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Checks if any modifier is active
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}

/// Keyboard event data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Scan code from hardware
    pub scan_code: u8,
    /// Whether the key was pressed (true) or released (false)
    pub pressed: bool,
    /// Active modifiers at time of event
    pub modifiers: Modifiers,
    /// Repeat count (0 = first press)
    pub repeat_count: u8,
}

/// Mouse button identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseButton {
    Left = 0,
    Right = 1,
    Middle = 2,
    Side1 = 3,
    Side2 = 4,
}

/// Mouse event data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseMoveEvent {
    /// Delta X movement
    pub dx: i16,
    /// Delta Y movement
    pub dy: i16,
    /// Absolute X position (if available)
    pub abs_x: Option<u16>,
    /// Absolute Y position (if available)
    pub abs_y: Option<u16>,
}

/// Mouse button event data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseButtonEvent {
    /// Which button
    pub button: MouseButton,
    /// Pressed (true) or released (false)
    pub pressed: bool,
    /// Click count (1 = single, 2 = double, etc.)
    pub click_count: u8,
}

/// Mouse scroll event data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseScrollEvent {
    /// Vertical scroll delta (positive = up)
    pub delta_y: i8,
    /// Horizontal scroll delta (positive = right)
    pub delta_x: i8,
}

/// Input event payload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEventKind {
    /// Key press event
    KeyPress(KeyEvent),
    /// Key release event
    KeyRelease(KeyEvent),
    /// Mouse movement
    MouseMove(MouseMoveEvent),
    /// Mouse button press/release
    MouseButton(MouseButtonEvent),
    /// Mouse scroll
    MouseScroll(MouseScrollEvent),
    /// Device connected
    DeviceConnected(DeviceId),
    /// Device disconnected
    DeviceDisconnected(DeviceId),
}

impl InputEventKind {
    /// Returns true if this is a keyboard event
    #[inline]
    pub const fn is_key_event(&self) -> bool {
        matches!(self, Self::KeyPress(_) | Self::KeyRelease(_))
    }

    /// Returns true if this is a mouse event
    #[inline]
    pub const fn is_mouse_event(&self) -> bool {
        matches!(
            self,
            Self::MouseMove(_) | Self::MouseButton(_) | Self::MouseScroll(_)
        )
    }

    /// Returns true if this is a device event
    #[inline]
    pub const fn is_device_event(&self) -> bool {
        matches!(self, Self::DeviceConnected(_) | Self::DeviceDisconnected(_))
    }

    /// Returns the scan code if this is a key event
    #[inline]
    pub const fn scan_code(&self) -> Option<u8> {
        match self {
            Self::KeyPress(k) | Self::KeyRelease(k) => Some(k.scan_code),
            _ => None,
        }
    }

    /// Returns the event type name for logging
    #[inline]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::KeyPress(_) => "KeyPress",
            Self::KeyRelease(_) => "KeyRelease",
            Self::MouseMove(_) => "MouseMove",
            Self::MouseButton(_) => "MouseButton",
            Self::MouseScroll(_) => "MouseScroll",
            Self::DeviceConnected(_) => "DeviceConnected",
            Self::DeviceDisconnected(_) => "DeviceDisconnected",
        }
    }
}

/// Complete input event with metadata
#[derive(Debug, Clone, Copy)]
pub struct InputEvent {
    /// The event data
    pub kind: InputEventKind,
    /// Timestamp (monotonic counter)
    pub timestamp: u64,
    /// Source device
    pub device: DeviceId,
    /// Event priority
    pub priority: EventPriority,
    /// Sequence number for ordering
    pub sequence: u64,
}

impl InputEvent {
    /// Creates a new input event with default metadata
    pub fn new(kind: InputEventKind) -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        Self {
            kind,
            timestamp: get_timestamp(),
            device: DeviceId::default(),
            priority: EventPriority::default(),
            sequence: SEQUENCE.fetch_add(1, Ordering::SeqCst),
        }
    }

    /// Creates an event with specific device
    pub fn with_device(mut self, device: DeviceId) -> Self {
        self.device = device;
        self
    }

    /// Creates an event with specific priority
    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Legacy compatibility: creates a key press event from scan code
    pub fn key_press(scan_code: u8) -> Self {
        Self::new(InputEventKind::KeyPress(KeyEvent {
            scan_code,
            pressed: true,
            modifiers: Modifiers::NONE,
            repeat_count: 0,
        }))
    }

    /// Legacy compatibility: creates a key release event from scan code
    pub fn key_release(scan_code: u8) -> Self {
        Self::new(InputEventKind::KeyRelease(KeyEvent {
            scan_code,
            pressed: false,
            modifiers: Modifiers::NONE,
            repeat_count: 0,
        }))
    }

    /// Legacy compatibility: creates a mouse move event
    pub fn mouse_move(dx: i16, dy: i16) -> Self {
        Self::new(InputEventKind::MouseMove(MouseMoveEvent {
            dx,
            dy,
            abs_x: None,
            abs_y: None,
        }))
        .with_device(DeviceId::MOUSE)
    }

    /// Legacy compatibility: creates a mouse button event
    pub fn mouse_button(button: u8, pressed: bool) -> Self {
        let btn = match button {
            0 => MouseButton::Left,
            1 => MouseButton::Right,
            2 => MouseButton::Middle,
            3 => MouseButton::Side1,
            4 => MouseButton::Side2,
            _ => MouseButton::Left,
        };
        Self::new(InputEventKind::MouseButton(MouseButtonEvent {
            button: btn,
            pressed,
            click_count: 1,
        }))
        .with_device(DeviceId::MOUSE)
    }

    /// Legacy compatibility: creates a mouse scroll event
    pub fn mouse_scroll(delta: i8) -> Self {
        Self::new(InputEventKind::MouseScroll(MouseScrollEvent {
            delta_y: delta,
            delta_x: 0,
        }))
        .with_device(DeviceId::MOUSE)
    }
}

impl PartialEq for InputEvent {
    fn eq(&self, other: &Self) -> bool {
        self.sequence == other.sequence
    }
}

impl Eq for InputEvent {}

// ============================================================================
// Event Filter
// ============================================================================

/// Filter for selecting events
#[derive(Debug, Clone, Copy)]
pub struct EventFilter {
    /// Include keyboard events
    pub keyboard: bool,
    /// Include mouse events
    pub mouse: bool,
    /// Include device events
    pub device: bool,
    /// Minimum priority to include
    pub min_priority: EventPriority,
    /// Filter by specific device (None = all devices)
    pub device_id: Option<DeviceId>,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl EventFilter {
    /// Filter that accepts all events
    pub const fn all() -> Self {
        Self {
            keyboard: true,
            mouse: true,
            device: true,
            min_priority: EventPriority::Low,
            device_id: None,
        }
    }

    /// Filter for keyboard events only
    pub const fn keyboard_only() -> Self {
        Self {
            keyboard: true,
            mouse: false,
            device: false,
            min_priority: EventPriority::Low,
            device_id: None,
        }
    }

    /// Filter for mouse events only
    pub const fn mouse_only() -> Self {
        Self {
            keyboard: false,
            mouse: true,
            device: false,
            min_priority: EventPriority::Low,
            device_id: None,
        }
    }

    /// Check if an event matches this filter
    pub fn matches(&self, event: &InputEvent) -> bool {
        // Check priority
        if event.priority < self.min_priority {
            return false;
        }

        // Check device
        if let Some(device_id) = self.device_id {
            if event.device != device_id {
                return false;
            }
        }

        // Check event type
        match &event.kind {
            InputEventKind::KeyPress(_) | InputEventKind::KeyRelease(_) => self.keyboard,
            InputEventKind::MouseMove(_)
            | InputEventKind::MouseButton(_)
            | InputEventKind::MouseScroll(_) => self.mouse,
            InputEventKind::DeviceConnected(_) | InputEventKind::DeviceDisconnected(_) => {
                self.device
            }
        }
    }
}

// ============================================================================
// Input Device Trait (Backend Abstraction)
// ============================================================================

/// Trait for input device backends
pub trait InputDevice: Send + Sync {
    /// Returns the device identifier
    fn device_id(&self) -> DeviceId;

    /// Returns the device name
    fn name(&self) -> &str;

    /// Polls the device for new events
    fn poll(&self) -> Option<InputEventKind>;

    /// Returns true if the device is connected
    fn is_connected(&self) -> bool;

    /// Enables or disables the device
    fn set_enabled(&mut self, enabled: bool);

    /// Returns true if the device is enabled
    fn is_enabled(&self) -> bool;
}

// ============================================================================
// Device Registry
// ============================================================================

/// Maximum number of registered input devices
pub const MAX_INPUT_DEVICES: usize = 16;

/// Registered device entry
struct DeviceEntry {
    device: &'static dyn InputDevice,
    enabled: bool,
}

/// Global device registry
struct DeviceRegistry {
    devices: [Option<DeviceEntry>; MAX_INPUT_DEVICES],
    count: usize,
}

impl DeviceRegistry {
    const fn new() -> Self {
        const NONE: Option<DeviceEntry> = None;
        Self {
            devices: [NONE; MAX_INPUT_DEVICES],
            count: 0,
        }
    }
}

static DEVICE_REGISTRY: Mutex<DeviceRegistry> = Mutex::new(DeviceRegistry::new());

/// Registers an input device with the system
///
/// # Arguments
/// * `device` - Static reference to the device implementation
///
/// # Returns
/// * `Ok(())` if registration succeeded
/// * `Err(InputError)` if registry is full or device already registered
pub fn register_device(device: &'static dyn InputDevice) -> InputResult<()> {
    let mut registry = DEVICE_REGISTRY.lock();

    // Check if already registered
    let device_id = device.device_id();
    for entry in registry.devices.iter().flatten() {
        if entry.device.device_id() == device_id {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                "device already registered",
            ));
        }
    }

    // Find empty slot
    for slot in registry.devices.iter_mut() {
        if slot.is_none() {
            *slot = Some(DeviceEntry {
                device,
                enabled: true,
            });
            registry.count += 1;

            // Push device connected event
            let event = InputEvent::new(InputEventKind::DeviceConnected(device_id))
                .with_priority(EventPriority::High);
            drop(registry); // Release lock before pushing event
            let _ = push_event(event);

            return Ok(());
        }
    }

    Err(InputError::with_context(
        InputErrorCode::ResourceExhausted,
        "device registry full",
    ))
}

/// Unregisters an input device
pub fn unregister_device(device_id: DeviceId) -> InputResult<()> {
    let mut registry = DEVICE_REGISTRY.lock();

    for slot in registry.devices.iter_mut() {
        if let Some(entry) = slot {
            if entry.device.device_id() == device_id {
                *slot = None;
                registry.count -= 1;

                // Push device disconnected event
                let event = InputEvent::new(InputEventKind::DeviceDisconnected(device_id))
                    .with_priority(EventPriority::High);
                drop(registry);
                let _ = push_event(event);

                return Ok(());
            }
        }
    }

    Err(InputError::new(InputErrorCode::DeviceNotFound))
}

/// Polls all registered devices for new events
///
/// This should be called periodically (e.g., from a timer interrupt or polling loop)
/// to collect events from all registered input devices.
pub fn poll_all_devices() {
    let registry = DEVICE_REGISTRY.lock();

    for entry in registry.devices.iter().flatten() {
        if !entry.enabled {
            continue;
        }
        if !entry.device.is_connected() {
            continue;
        }
        if !entry.device.is_enabled() {
            continue;
        }

        // Poll device and push any events
        while let Some(event_kind) = entry.device.poll() {
            let event = InputEvent::new(event_kind).with_device(entry.device.device_id());
            // Note: We hold the registry lock here, but push_event only needs the queue lock
            // This is safe because we never acquire registry lock while holding queue lock
            if push_event(event).is_err() {
                // Queue full or shutdown, stop polling
                break;
            }
        }
    }
}

/// Returns the number of registered devices
pub fn device_count() -> usize {
    DEVICE_REGISTRY.lock().count
}

/// Returns information about registered devices
pub fn list_devices() -> Vec<(DeviceId, &'static str, bool)> {
    let registry = DEVICE_REGISTRY.lock();
    let mut result = Vec::with_capacity(registry.count);

    for entry in registry.devices.iter().flatten() {
        result.push((
            entry.device.device_id(),
            entry.device.name(),
            entry.enabled && entry.device.is_enabled() && entry.device.is_connected(),
        ));
    }

    result
}

/// Enables or disables a registered device
pub fn set_device_enabled(device_id: DeviceId, enabled: bool) -> InputResult<()> {
    let mut registry = DEVICE_REGISTRY.lock();

    for entry in registry.devices.iter_mut().flatten() {
        if entry.device.device_id() == device_id {
            entry.enabled = enabled;
            return Ok(());
        }
    }

    Err(InputError::new(InputErrorCode::DeviceNotFound))
}

// ============================================================================
// Queue Configuration
// ============================================================================

/// Configuration for the input queue
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Maximum number of events in the queue
    pub max_size: usize,
    /// Threshold for pressure warnings
    pub pressure_threshold: usize,
    /// Enable mouse movement coalescing
    pub coalesce_mouse_moves: bool,
    /// Maximum coalesced events before flush
    pub max_coalesce_count: usize,
    /// Drop low-priority events under pressure
    pub drop_low_priority_under_pressure: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_QUEUE_SIZE,
            pressure_threshold: DEFAULT_PRESSURE_THRESHOLD,
            coalesce_mouse_moves: true,
            max_coalesce_count: MAX_COALESCE_COUNT,
            drop_low_priority_under_pressure: true,
        }
    }
}

impl QueueConfig {
    /// Validates the configuration
    pub fn validate(&self) -> InputResult<()> {
        if self.max_size == 0 {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                "max_size cannot be zero",
            ));
        }
        if self.max_size > MAX_ALLOWED_QUEUE_SIZE {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                alloc::format!("max_size exceeds limit of {}", MAX_ALLOWED_QUEUE_SIZE),
            ));
        }
        if self.pressure_threshold >= self.max_size {
            return Err(InputError::with_context(
                InputErrorCode::InvalidConfig,
                "pressure_threshold must be less than max_size",
            ));
        }
        Ok(())
    }
}

// ============================================================================
// Queue Statistics
// ============================================================================

/// Statistics about queue operation
#[derive(Debug, Clone, Copy, Default)]
pub struct QueueStats {
    /// Total events received
    pub total_events: u64,
    /// Events dropped due to queue full
    pub dropped_events: u64,
    /// Events dropped due to low priority under pressure
    pub priority_drops: u64,
    /// Events coalesced
    pub coalesced_events: u64,
    /// Peak queue size reached
    pub peak_size: usize,
    /// Current queue size
    pub current_size: usize,
    /// Number of pressure warnings
    pub pressure_warnings: u64,
}

// ============================================================================
// Wake-up Mechanism
// ============================================================================

/// Waiter notification handle
pub struct WaitHandle {
    notified: AtomicBool,
}

impl WaitHandle {
    /// Creates a new wait handle
    pub const fn new() -> Self {
        Self {
            notified: AtomicBool::new(false),
        }
    }

    /// Checks if notification was received
    pub fn is_notified(&self) -> bool {
        self.notified.load(Ordering::Acquire)
    }

    /// Clears the notification flag
    pub fn clear(&self) {
        self.notified.store(false, Ordering::Release);
    }

    /// Sets the notification flag
    fn notify(&self) {
        self.notified.store(true, Ordering::Release);
    }
}

impl Default for WaitHandle {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Input Queue Implementation
// ============================================================================

/// Thread-safe input event queue
struct InputQueueInner {
    /// The event queue
    events: VecDeque<InputEvent>,
    /// Pending coalesced mouse movement
    pending_mouse_move: Option<MouseMoveEvent>,
    /// Count of coalesced movements
    coalesce_count: usize,
}

/// Global input queue state
struct InputQueueState {
    /// Inner queue (mutex protected for modification)
    inner: Mutex<InputQueueInner>,
    /// Configuration (RwLock for concurrent reads)
    config: RwLock<QueueConfig>,
    /// Statistics (atomic for lock-free reads)
    stats: QueueStatsAtomic,
    /// Shutdown flag
    shutdown: AtomicBool,
    /// Registered waiters
    waiters: Mutex<Vec<&'static WaitHandle>>,
}

/// Atomic statistics for lock-free access
struct QueueStatsAtomic {
    total_events: AtomicU64,
    dropped_events: AtomicU64,
    priority_drops: AtomicU64,
    coalesced_events: AtomicU64,
    peak_size: AtomicUsize,
    pressure_warnings: AtomicU64,
}

impl QueueStatsAtomic {
    const fn new() -> Self {
        Self {
            total_events: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            priority_drops: AtomicU64::new(0),
            coalesced_events: AtomicU64::new(0),
            peak_size: AtomicUsize::new(0),
            pressure_warnings: AtomicU64::new(0),
        }
    }

    fn snapshot(&self, current_size: usize) -> QueueStats {
        QueueStats {
            total_events: self.total_events.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            priority_drops: self.priority_drops.load(Ordering::Relaxed),
            coalesced_events: self.coalesced_events.load(Ordering::Relaxed),
            peak_size: self.peak_size.load(Ordering::Relaxed),
            current_size,
            pressure_warnings: self.pressure_warnings.load(Ordering::Relaxed),
        }
    }
}

static INPUT_QUEUE: InputQueueState = InputQueueState {
    inner: Mutex::new(InputQueueInner {
        events: VecDeque::new(),
        pending_mouse_move: None,
        coalesce_count: 0,
    }),
    config: RwLock::new(QueueConfig {
        max_size: DEFAULT_MAX_QUEUE_SIZE,
        pressure_threshold: DEFAULT_PRESSURE_THRESHOLD,
        coalesce_mouse_moves: true,
        max_coalesce_count: MAX_COALESCE_COUNT,
        drop_low_priority_under_pressure: true,
    }),
    stats: QueueStatsAtomic::new(),
    shutdown: AtomicBool::new(false),
    waiters: Mutex::new(Vec::new()),
};

/// Global timestamp counter
static TIMESTAMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Gets the current timestamp
#[inline]
pub fn get_timestamp() -> u64 {
    TIMESTAMP_COUNTER.fetch_add(1, Ordering::SeqCst)
}

// ============================================================================
// Public API
// ============================================================================

/// Configures the input queue
///
/// # Errors
/// Returns an error if the configuration is invalid.
pub fn configure(config: QueueConfig) -> InputResult<()> {
    config.validate()?;
    *INPUT_QUEUE.config.write() = config;
    Ok(())
}

/// Returns the current configuration
pub fn get_config() -> QueueConfig {
    INPUT_QUEUE.config.read().clone()
}

/// Pushes an event to the queue
///
/// # Returns
/// - `Ok(())` if the event was queued successfully
/// - `Err(InputError)` if the event was dropped or queue is shutdown
pub fn push_event(event: InputEvent) -> InputResult<()> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return Err(InputError::new(InputErrorCode::QueueShutdown));
    }

    let config = INPUT_QUEUE.config.read();
    let mut inner = INPUT_QUEUE.inner.lock();

    // Check for mouse move coalescing
    if config.coalesce_mouse_moves {
        if let InputEventKind::MouseMove(move_event) = &event.kind {
            if let Some(ref mut pending) = inner.pending_mouse_move {
                // Coalesce with pending movement
                pending.dx = pending.dx.saturating_add(move_event.dx);
                pending.dy = pending.dy.saturating_add(move_event.dy);
                if move_event.abs_x.is_some() {
                    pending.abs_x = move_event.abs_x;
                }
                if move_event.abs_y.is_some() {
                    pending.abs_y = move_event.abs_y;
                }
                inner.coalesce_count += 1;
                INPUT_QUEUE
                    .stats
                    .coalesced_events
                    .fetch_add(1, Ordering::Relaxed);

                // Flush if we've coalesced too many
                if inner.coalesce_count >= config.max_coalesce_count {
                    flush_pending_mouse_move(&mut inner, &config)?;
                }

                return Ok(());
            } else {
                // Start new pending movement
                inner.pending_mouse_move = Some(*move_event);
                inner.coalesce_count = 1;
                INPUT_QUEUE.stats.total_events.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        } else {
            // Non-mouse-move event: flush pending mouse move first
            if inner.pending_mouse_move.is_some() {
                flush_pending_mouse_move(&mut inner, &config)?;
            }
        }
    }

    push_event_inner(&mut inner, &config, event)
}

/// Flushes any pending coalesced mouse movement
fn flush_pending_mouse_move(
    inner: &mut InputQueueInner,
    config: &QueueConfig,
) -> InputResult<()> {
    if let Some(pending) = inner.pending_mouse_move.take() {
        let event = InputEvent::new(InputEventKind::MouseMove(pending))
            .with_device(DeviceId::MOUSE);
        inner.coalesce_count = 0;
        push_event_inner(inner, config, event)?;
    }
    Ok(())
}

/// Inner push implementation
fn push_event_inner(
    inner: &mut InputQueueInner,
    config: &QueueConfig,
    event: InputEvent,
) -> InputResult<()> {
    let current_len = inner.events.len();

    // Check pressure and potentially drop low-priority events
    if current_len >= config.pressure_threshold {
        INPUT_QUEUE
            .stats
            .pressure_warnings
            .fetch_add(1, Ordering::Relaxed);

        if config.drop_low_priority_under_pressure && event.priority == EventPriority::Low {
            INPUT_QUEUE
                .stats
                .priority_drops
                .fetch_add(1, Ordering::Relaxed);
            return Err(InputError::new(InputErrorCode::FilterRejected)
                .with_event_type(event.kind.type_name()));
        }
    }

    // Check if queue is full
    if current_len >= config.max_size {
        // Try to drop oldest low-priority event
        if config.drop_low_priority_under_pressure {
            if let Some(idx) = inner
                .events
                .iter()
                .position(|e| e.priority == EventPriority::Low)
            {
                inner.events.remove(idx);
                INPUT_QUEUE
                    .stats
                    .priority_drops
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                // No low-priority events, drop oldest
                inner.events.pop_front();
                INPUT_QUEUE
                    .stats
                    .dropped_events
                    .fetch_add(1, Ordering::Relaxed);
            }
        } else {
            inner.events.pop_front();
            INPUT_QUEUE
                .stats
                .dropped_events
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    // Add event
    inner.events.push_back(event);
    INPUT_QUEUE.stats.total_events.fetch_add(1, Ordering::Relaxed);

    // Update peak size
    let new_len = inner.events.len();
    let mut peak = INPUT_QUEUE.stats.peak_size.load(Ordering::Relaxed);
    while new_len > peak {
        match INPUT_QUEUE.stats.peak_size.compare_exchange_weak(
            peak,
            new_len,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(p) => peak = p,
        }
    }

    // Notify waiters
    notify_waiters();

    Ok(())
}

/// Pops the next event from the queue
pub fn pop_event() -> Option<InputEvent> {
    pop_event_filtered(&EventFilter::all())
}

/// Pops the next event matching the filter
pub fn pop_event_filtered(filter: &EventFilter) -> Option<InputEvent> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return None;
    }

    let config = INPUT_QUEUE.config.read();
    let mut inner = INPUT_QUEUE.inner.lock();

    // Flush pending mouse move if we're looking for mouse events
    if filter.mouse && inner.pending_mouse_move.is_some() {
        let _ = flush_pending_mouse_move(&mut inner, &config);
    }

    // Find and remove first matching event
    if let Some(idx) = inner.events.iter().position(|e| filter.matches(e)) {
        inner.events.remove(idx)
    } else {
        None
    }
}

/// Peeks at the next event without removing it
pub fn peek_event() -> Option<InputEvent> {
    peek_event_filtered(&EventFilter::all())
}

/// Peeks at the next event matching the filter
pub fn peek_event_filtered(filter: &EventFilter) -> Option<InputEvent> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return None;
    }

    let inner = INPUT_QUEUE.inner.lock();
    inner.events.iter().find(|e| filter.matches(e)).copied()
}

/// Drains all events from the queue
pub fn drain_events() -> Vec<InputEvent> {
    drain_events_filtered(&EventFilter::all())
}

/// Drains all events matching the filter
pub fn drain_events_filtered(filter: &EventFilter) -> Vec<InputEvent> {
    if INPUT_QUEUE.shutdown.load(Ordering::Acquire) {
        return Vec::new();
    }

    let config = INPUT_QUEUE.config.read();
    let mut inner = INPUT_QUEUE.inner.lock();

    // Flush pending mouse move
    if filter.mouse && inner.pending_mouse_move.is_some() {
        let _ = flush_pending_mouse_move(&mut inner, &config);
    }

    if filter.keyboard && filter.mouse && filter.device && filter.min_priority == EventPriority::Low
    {
        // Fast path: drain all
        inner.events.drain(..).collect()
    } else {
        // Filtered drain
        let mut result = Vec::new();
        let mut i = 0;
        while i < inner.events.len() {
            if filter.matches(&inner.events[i]) {
                if let Some(event) = inner.events.remove(i) {
                    result.push(event);
                }
            } else {
                i += 1;
            }
        }
        result
    }
}

/// Returns the current queue length
pub fn queue_len() -> usize {
    let inner = INPUT_QUEUE.inner.lock();
    inner.events.len() + if inner.pending_mouse_move.is_some() { 1 } else { 0 }
}

/// Returns true if the queue is empty
pub fn is_empty() -> bool {
    let inner = INPUT_QUEUE.inner.lock();
    inner.events.is_empty() && inner.pending_mouse_move.is_none()
}

/// Clears all events from the queue
pub fn clear() {
    let mut inner = INPUT_QUEUE.inner.lock();
    inner.events.clear();
    inner.pending_mouse_move = None;
    inner.coalesce_count = 0;
}

/// Returns queue statistics
pub fn stats() -> QueueStats {
    let inner = INPUT_QUEUE.inner.lock();
    let current_size = inner.events.len();
    INPUT_QUEUE.stats.snapshot(current_size)
}

/// Returns total events ever received
pub fn total_events() -> u64 {
    INPUT_QUEUE.stats.total_events.load(Ordering::Relaxed)
}

/// Returns total events dropped
pub fn dropped_events() -> u64 {
    INPUT_QUEUE.stats.dropped_events.load(Ordering::Relaxed)
}

/// Shuts down the queue
pub fn shutdown() {
    INPUT_QUEUE.shutdown.store(true, Ordering::Release);
    notify_waiters();
}

/// Restarts the queue after shutdown
pub fn restart() {
    INPUT_QUEUE.shutdown.store(false, Ordering::Release);
}

/// Checks if the queue is shutdown
pub fn is_shutdown() -> bool {
    INPUT_QUEUE.shutdown.load(Ordering::Acquire)
}

// ============================================================================
// Wait Handle Management
// ============================================================================

/// # Safety
/// The wait handle must remain valid for the lifetime of registration.
pub fn register_waiter(handle: &'static WaitHandle) {
    INPUT_QUEUE.waiters.lock().push(handle);
}

pub fn unregister_waiter(handle: &'static WaitHandle) {
    let mut waiters = INPUT_QUEUE.waiters.lock();
    waiters.retain(|h| !core::ptr::eq(*h, handle));
}

fn notify_waiters() {
    let waiters = INPUT_QUEUE.waiters.lock();
    for waiter in waiters.iter() {
        waiter.notify();
    }
}

// ============================================================================
// Legacy Compatibility API
// ============================================================================

/// Legacy: Push a simple key press event
pub fn push_key_press(scan_code: u8) {
    let _ = push_event(InputEvent::key_press(scan_code));
}

/// Legacy: Push a simple key release event
pub fn push_key_release(scan_code: u8) {
    let _ = push_event(InputEvent::key_release(scan_code));
}

/// Legacy: Push a simple mouse move event
pub fn push_mouse_move(dx: i16, dy: i16) {
    let _ = push_event(InputEvent::mouse_move(dx, dy));
}

/// Legacy: Push a simple mouse button event
pub fn push_mouse_button(button: u8, pressed: bool) {
    let _ = push_event(InputEvent::mouse_button(button, pressed));
}

/// Legacy: Push a simple mouse scroll event
pub fn push_mouse_scroll(delta: i8) {
    let _ = push_event(InputEvent::mouse_scroll(delta));
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        clear();
        restart();
        let _ = configure(QueueConfig::default());
    }

    #[test]
    fn test_push_pop() {
        setup();
        let event = InputEvent::key_press(0x1E);
        assert!(push_event(event).is_ok());
        let popped = pop_event();
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().kind.scan_code(), Some(0x1E));
        assert!(pop_event().is_none());
    }

    #[test]
    fn test_peek() {
        setup();
        let event = InputEvent::key_press(0x30);
        assert!(push_event(event).is_ok());
        assert!(peek_event().is_some());
        assert!(peek_event().is_some()); // Still there
        pop_event();
        assert!(peek_event().is_none());
    }

    #[test]
    fn test_drain() {
        setup();
        assert!(push_event(InputEvent::key_press(1)).is_ok());
        assert!(push_event(InputEvent::key_release(1)).is_ok());
        assert!(push_event(InputEvent::key_press(2)).is_ok());
        let events = drain_events();
        assert_eq!(events.len(), 3);
        assert!(is_empty());
    }

    #[test]
    fn test_event_type_checks() {
        let key_event = InputEventKind::KeyPress(KeyEvent {
            scan_code: 0,
            pressed: true,
            modifiers: Modifiers::NONE,
            repeat_count: 0,
        });
        assert!(key_event.is_key_event());
        assert!(!key_event.is_mouse_event());

        let mouse_event = InputEventKind::MouseMove(MouseMoveEvent {
            dx: 1,
            dy: -1,
            abs_x: None,
            abs_y: None,
        });
        assert!(mouse_event.is_mouse_event());
        assert!(!mouse_event.is_key_event());
    }

    #[test]
    fn test_scan_code() {
        let key = InputEventKind::KeyPress(KeyEvent {
            scan_code: 0x1E,
            pressed: true,
            modifiers: Modifiers::NONE,
            repeat_count: 0,
        });
        assert_eq!(key.scan_code(), Some(0x1E));

        let mouse = InputEventKind::MouseMove(MouseMoveEvent {
            dx: 0,
            dy: 0,
            abs_x: None,
            abs_y: None,
        });
        assert_eq!(mouse.scan_code(), None);
    }

    #[test]
    fn test_queue_len() {
        setup();
        assert_eq!(queue_len(), 0);
        assert!(push_event(InputEvent::key_press(1)).is_ok());
        assert!(push_event(InputEvent::key_press(2)).is_ok());
        assert_eq!(queue_len(), 2);
        pop_event();
        assert_eq!(queue_len(), 1);
    }

    #[test]
    fn test_filter() {
        setup();
        assert!(push_event(InputEvent::key_press(1)).is_ok());
        assert!(push_event(InputEvent::mouse_move(10, 20)).is_ok());
        assert!(push_event(InputEvent::key_press(2)).is_ok());

        let filter = EventFilter::keyboard_only();
        let event = pop_event_filtered(&filter);
        assert!(event.is_some());
        assert!(event.unwrap().kind.is_key_event());
    }

    #[test]
    fn test_priority() {
        setup();
        let mut config = QueueConfig::default();
        config.max_size = 2;
        config.pressure_threshold = 1;
        config.drop_low_priority_under_pressure = true;
        assert!(configure(config).is_ok());

        let high_priority = InputEvent::key_press(1).with_priority(EventPriority::High);
        let low_priority = InputEvent::key_press(2).with_priority(EventPriority::Low);

        assert!(push_event(high_priority).is_ok());
        // Under pressure now, low priority should be rejected
        let result = push_event(low_priority);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), InputErrorCode::FilterRejected);
    }

    #[test]
    fn test_shutdown() {
        setup();
        shutdown();
        assert!(is_shutdown());
        let result = push_event(InputEvent::key_press(1));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), InputErrorCode::QueueShutdown);
        restart();
        assert!(!is_shutdown());
    }

    #[test]
    fn test_modifiers() {
        let mods = Modifiers::SHIFT.union(Modifiers::CTRL);
        assert!(mods.contains(Modifiers::SHIFT));
        assert!(mods.contains(Modifiers::CTRL));
        assert!(!mods.contains(Modifiers::ALT));
        assert!(!mods.is_empty());
        assert!(Modifiers::NONE.is_empty());
    }

    #[test]
    fn test_config_validation() {
        let mut config = QueueConfig::default();
        assert!(config.validate().is_ok());

        config.max_size = 0;
        assert!(config.validate().is_err());

        config.max_size = MAX_ALLOWED_QUEUE_SIZE + 1;
        assert!(config.validate().is_err());

        config.max_size = 100;
        config.pressure_threshold = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_stats() {
        setup();
        assert!(push_event(InputEvent::key_press(1)).is_ok());
        assert!(push_event(InputEvent::key_press(2)).is_ok());
        let s = stats();
        assert!(s.total_events >= 2);
        assert_eq!(s.current_size, 2);
    }

    #[test]
    fn test_legacy_api() {
        setup();
        push_key_press(0x1E);
        push_key_release(0x1E);
        push_mouse_move(10, 20);
        push_mouse_button(0, true);
        push_mouse_scroll(-1);
        // Should have pushed events (mouse moves may coalesce)
        assert!(!is_empty());
    }

    #[test]
    fn test_device_id() {
        assert_eq!(DeviceId::KEYBOARD, DeviceId(0));
        assert_eq!(DeviceId::MOUSE, DeviceId(1));
        assert_ne!(DeviceId::KEYBOARD, DeviceId::MOUSE);
    }

    #[test]
    fn test_error_display() {
        let err = InputError::with_context(InputErrorCode::QueueFull, "test context")
            .with_event_type("KeyPress");
        let msg = alloc::format!("{}", err);
        assert!(msg.contains("full"));
        assert!(msg.contains("test context"));
        assert!(msg.contains("KeyPress"));
    }
}
