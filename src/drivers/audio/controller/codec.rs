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
//! HD Audio codec discovery, graph walking, and path configuration.
//! Codec (CAD 0-15)
//! ├── Root Node (NID 0)
//! │   └── Subordinate nodes info
//! └── Audio Function Group (NID 1+, type 0x01)
//!     └── Audio Widgets
//!         ├── Audio Output (DAC) - type 0x0
//!         ├── Audio Input (ADC) - type 0x1
//!         ├── Audio Mixer - type 0x2
//!         ├── Audio Selector - type 0x3
//!         ├── Pin Complex - type 0x4
//!         ├── Power Widget - type 0x5
//!         ├── Volume Knob - type 0x6
//!         └── Beep Generator - type 0x7

use super::super::error::AudioError;
use super::super::types::DmaRegion;
use super::super::constants::*;
use super::helpers::RegisterAccess;
use super::corb_rirb::{corb_send_verb, get_parameter};

// =============================================================================
// Widget Type Constants
// =============================================================================

/// Widget type: Audio Output (DAC)
const WIDGET_TYPE_DAC: u8 = 0x0;
/// Widget type: Audio Input (ADC)
const WIDGET_TYPE_ADC: u8 = 0x1;
/// Widget type: Audio Mixer
const WIDGET_TYPE_MIXER: u8 = 0x2;
/// Widget type: Audio Selector
const WIDGET_TYPE_SELECTOR: u8 = 0x3;
/// Widget type: Pin Complex
const WIDGET_TYPE_PIN: u8 = 0x4;
/// Widget type: Power Widget
const WIDGET_TYPE_POWER: u8 = 0x5;
/// Widget type: Volume Knob
const WIDGET_TYPE_VOLUME_KNOB: u8 = 0x6;
/// Widget type: Beep Generator
const WIDGET_TYPE_BEEP: u8 = 0x7;

// =============================================================================
// Pin Configuration Defaults
// =============================================================================

/// Default device types from pin config default
const PIN_DEV_LINE_OUT: u8 = 0x0;
const PIN_DEV_SPEAKER: u8 = 0x1;
const PIN_DEV_HP_OUT: u8 = 0x2;
const PIN_DEV_CD: u8 = 0x3;
const PIN_DEV_SPDIF_OUT: u8 = 0x4;
const PIN_DEV_DIG_OTHER_OUT: u8 = 0x5;
const PIN_DEV_MODEM_LINE: u8 = 0x6;
const PIN_DEV_MODEM_HANDSET: u8 = 0x7;
const PIN_DEV_LINE_IN: u8 = 0x8;
const PIN_DEV_AUX: u8 = 0x9;
const PIN_DEV_MIC_IN: u8 = 0xA;
const PIN_DEV_TELEPHONY: u8 = 0xB;
const PIN_DEV_SPDIF_IN: u8 = 0xC;
const PIN_DEV_DIG_OTHER_IN: u8 = 0xD;
const PIN_DEV_OTHER: u8 = 0xF;

// =============================================================================
// Data Structures
// =============================================================================

/// Codec information discovered during enumeration.
#[derive(Clone, Copy, Debug)]
pub struct CodecInfo {
    /// Codec address (0-15).
    pub cad: u8,
    /// Vendor ID (upper 16 bits of vendor/device response).
    pub vendor_id: u16,
    /// Device ID (lower 16 bits of vendor/device response).
    pub device_id: u16,
    /// Revision ID.
    pub revision_id: u32,
    /// Starting node ID for function groups.
    pub fn_group_start: u8,
    /// Number of function groups.
    pub fn_group_count: u8,
}

impl CodecInfo {
    /// Creates an empty codec info.
    pub const fn empty() -> Self {
        Self {
            cad: 0,
            vendor_id: 0,
            device_id: 0,
            revision_id: 0,
            fn_group_start: 0,
            fn_group_count: 0,
        }
    }
}

/// Information about a single audio widget.
#[derive(Clone, Copy, Debug, Default)]
pub struct WidgetInfo {
    /// Node ID.
    pub nid: u8,
    /// Widget type (0-15).
    pub widget_type: u8,
    /// Widget capabilities.
    pub caps: u32,
    /// Connection list length (if applicable).
    pub conn_len: u8,
    /// First connection entry (for simple paths).
    pub conn_first: u8,
    /// Pin capabilities (for pin widgets).
    pub pin_caps: u32,
    /// Pin config default (for pin widgets).
    pub pin_config: u32,
    /// Amplifier input capabilities.
    pub amp_in_caps: u32,
    /// Amplifier output capabilities.
    pub amp_out_caps: u32,
}

impl WidgetInfo {
    /// Returns true if this widget has an output amplifier.
    pub fn has_out_amp(&self) -> bool {
        (self.caps & (1 << 2)) != 0
    }

    /// Returns true if this widget has an input amplifier.
    pub fn has_in_amp(&self) -> bool {
        (self.caps & (1 << 1)) != 0
    }

    /// Returns true if this is an output-capable pin.
    pub fn is_output_pin(&self) -> bool {
        self.widget_type == WIDGET_TYPE_PIN && (self.pin_caps & (1 << 4)) != 0
    }

    /// Returns true if this is an input-capable pin.
    pub fn is_input_pin(&self) -> bool {
        self.widget_type == WIDGET_TYPE_PIN && (self.pin_caps & (1 << 5)) != 0
    }

    /// Returns the default device type from pin config.
    pub fn pin_device_type(&self) -> u8 {
        ((self.pin_config >> 20) & 0xF) as u8
    }

    /// Returns the port connectivity from pin config.
    /// 0 = jack, 1 = none, 2 = fixed, 3 = both
    pub fn pin_connectivity(&self) -> u8 {
        ((self.pin_config >> 30) & 0x3) as u8
    }

    /// Returns true if this pin is connected (not "none").
    pub fn is_connected(&self) -> bool {
        self.pin_connectivity() != 1
    }

    /// Returns the output amp gain steps.
    pub fn out_amp_steps(&self) -> u8 {
        ((self.amp_out_caps >> 8) & 0x7F) as u8
    }

    /// Returns the input amp gain steps.
    pub fn in_amp_steps(&self) -> u8 {
        ((self.amp_in_caps >> 8) & 0x7F) as u8
    }
}

/// Audio path from DAC to output pin.
#[derive(Clone, Copy, Debug, Default)]
pub struct AudioPath {
    /// DAC node ID.
    pub dac_nid: u8,
    /// Intermediate nodes (mixer/selector NIDs), 0 = unused.
    pub path: [u8; 8],
    /// Number of intermediate nodes.
    pub path_len: u8,
    /// Output pin node ID.
    pub pin_nid: u8,
    /// Pin device type (speaker, headphone, etc.).
    pub device_type: u8,
    /// Whether this path is active.
    pub active: bool,
}

/// Discovered audio paths for a codec.
#[derive(Clone, Debug)]
pub struct CodecPaths {
    /// Output paths (DAC to pin).
    pub output_paths: [AudioPath; MAX_OUTPUT_PATHS],
    /// Number of valid output paths.
    pub output_count: usize,
    /// Primary output path index (usually speaker or headphone).
    pub primary_output: usize,
}

/// Maximum number of output paths to track.
const MAX_OUTPUT_PATHS: usize = 8;
/// Maximum widgets to scan in a function group.
const MAX_WIDGETS: usize = 64;

impl Default for CodecPaths {
    fn default() -> Self {
        Self {
            output_paths: [AudioPath::default(); MAX_OUTPUT_PATHS],
            output_count: 0,
            primary_output: 0,
        }
    }
}

// =============================================================================
// Codec Discovery
// =============================================================================
pub fn discover_codec<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
) -> Result<CodecInfo, AudioError> {
    // Get Vendor/Device ID from root node (NID 0)
    let vendor_device = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, 0, PARAM_VENDOR_ID,
    )?;

    let vendor_id = (vendor_device >> 16) as u16;
    let device_id = (vendor_device & 0xFFFF) as u16;

    // Validate vendor ID - 0x0000 and 0xFFFF are invalid
    if vendor_id == 0x0000 || vendor_id == 0xFFFF {
        return Err(AudioError::NoCodecPresent);
    }

    // Get Revision ID
    let revision_id = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, 0, PARAM_REVISION_ID,
    ).unwrap_or(0);

    // Get subordinate node count (function groups)
    let sub_nodes = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, 0, PARAM_SUB_NODE_COUNT,
    ).unwrap_or(0);

    let fn_group_start = ((sub_nodes >> 16) & 0xFF) as u8;
    let fn_group_count = (sub_nodes & 0xFF) as u8;

    Ok(CodecInfo {
        cad,
        vendor_id,
        device_id,
        revision_id,
        fn_group_start,
        fn_group_count,
    })
}

// =============================================================================
// Widget Discovery
// =============================================================================
fn discover_widget<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
) -> Result<WidgetInfo, AudioError> {
    // Get widget capabilities
    let caps = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, PARAM_AUDIO_WIDGET_CAP,
    )?;

    let widget_type = ((caps >> 20) & 0xF) as u8;

    // Get connection list length
    let conn_len = if (caps & (1 << 8)) != 0 {
        // Has connection list
        let conn_info = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_CONN_LIST_LEN,
        ).unwrap_or(0);
        (conn_info & 0x7F) as u8
    } else {
        0
    };

    // Get first connection entry (if any)
    let conn_first = if conn_len > 0 {
        let conn = corb_send_verb(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, VERB_GET_CONN_LIST, 0,
        ).unwrap_or(0);
        (conn & 0xFF) as u8
    } else {
        0
    };

    // Get pin-specific info
    let (pin_caps, pin_config) = if widget_type == WIDGET_TYPE_PIN {
        let pc = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_PIN_CAP,
        ).unwrap_or(0);
        let cfg = corb_send_verb(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, VERB_GET_CONFIG_DEFAULT, 0,
        ).unwrap_or(0);
        (pc, cfg)
    } else {
        (0, 0)
    };

    // Get amplifier capabilities
    let amp_in_caps = if (caps & (1 << 1)) != 0 {
        get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_AMP_IN_CAP,
        ).unwrap_or(0)
    } else {
        0
    };

    let amp_out_caps = if (caps & (1 << 2)) != 0 {
        get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_AMP_OUT_CAP,
        ).unwrap_or(0)
    } else {
        0
    };

    Ok(WidgetInfo {
        nid,
        widget_type,
        caps,
        conn_len,
        conn_first,
        pin_caps,
        pin_config,
        amp_in_caps,
        amp_out_caps,
    })
}

// =============================================================================
// Graph Walking
// =============================================================================
/// This function discovers all widgets, finds output pins, and traces
/// back to find connected DACs, building complete audio paths.
pub fn discover_paths<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    codec: &CodecInfo,
) -> Result<CodecPaths, AudioError> {
    let mut paths = CodecPaths::default();

    // Walk function groups
    for fg_idx in 0..codec.fn_group_count {
        let fg_nid = codec.fn_group_start + fg_idx;

        // Get function group type
        let fg_type = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, fg_nid, PARAM_FN_GROUP_TYPE,
        ).unwrap_or(0);

        // Only process audio function groups (type 0x01)
        if (fg_type & 0xFF) != 0x01 {
            continue;
        }

        // Get subordinate nodes (widgets)
        let sub_nodes = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, fg_nid, PARAM_SUB_NODE_COUNT,
        ).unwrap_or(0);

        let widget_start = ((sub_nodes >> 16) & 0xFF) as u8;
        let widget_count = ((sub_nodes & 0xFF) as u8).min(MAX_WIDGETS as u8);

        // Discover all widgets
        let mut widgets: [WidgetInfo; MAX_WIDGETS] = [WidgetInfo::default(); MAX_WIDGETS];
        let mut widget_map: [u8; 256] = [0xFF; 256]; // NID -> index mapping

        for w_idx in 0..widget_count {
            let nid = widget_start.saturating_add(w_idx);
            if let Ok(widget) = discover_widget(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                codec.cad, nid,
            ) {
                widgets[w_idx as usize] = widget;
                widget_map[nid as usize] = w_idx;
            }
        }

        // Find output pins and trace paths
        for w_idx in 0..widget_count as usize {
            let widget = &widgets[w_idx];

            // Skip non-pins, input-only pins, and unconnected pins
            if !widget.is_output_pin() || !widget.is_connected() {
                continue;
            }

            // Prioritize speakers and headphones
            let dev_type = widget.pin_device_type();
            let priority = match dev_type {
                PIN_DEV_SPEAKER => 0,
                PIN_DEV_HP_OUT => 1,
                PIN_DEV_LINE_OUT => 2,
                _ => 10,
            };

            // Only track speaker, headphone, and line out
            if priority > 5 {
                continue;
            }

            // Trace back to find DAC
            if let Some(path) = trace_to_dac(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                codec.cad, widget.nid, &widgets, &widget_map, widget_start, widget_count,
            ) {
                if paths.output_count < MAX_OUTPUT_PATHS {
                    let mut audio_path = AudioPath {
                        dac_nid: path.0,
                        path: [0; 8],
                        path_len: path.1.len() as u8,
                        pin_nid: widget.nid,
                        device_type: dev_type,
                        active: false,
                    };
                    for (i, &nid) in path.1.iter().enumerate() {
                        if i < 8 {
                            audio_path.path[i] = nid;
                        }
                    }

                    // Update primary output if this is higher priority
                    if priority < match paths.output_paths[paths.primary_output].device_type {
                        PIN_DEV_SPEAKER => 0,
                        PIN_DEV_HP_OUT => 1,
                        PIN_DEV_LINE_OUT => 2,
                        _ => 10,
                    } {
                        paths.primary_output = paths.output_count;
                    }

                    paths.output_paths[paths.output_count] = audio_path;
                    paths.output_count += 1;
                }
            }
        }
    }

    if paths.output_count == 0 {
        return Err(AudioError::CodecInitFailed);
    }

    Ok(paths)
}

/// Traces from a pin back to a DAC.
fn trace_to_dac<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    start_nid: u8,
    widgets: &[WidgetInfo; MAX_WIDGETS],
    widget_map: &[u8; 256],
    widget_start: u8,
    widget_count: u8,
) -> Option<(u8, alloc::vec::Vec<u8>)> {
    use alloc::vec::Vec;

    let mut path: Vec<u8> = Vec::with_capacity(8);
    let mut current_nid = start_nid;
    let mut visited: [bool; 256] = [false; 256];

    // Maximum depth to prevent infinite loops
    const MAX_DEPTH: usize = 16;

    for _ in 0..MAX_DEPTH {
        if visited[current_nid as usize] {
            return None; // Cycle detected
        }
        visited[current_nid as usize] = true;

        let idx = widget_map[current_nid as usize];
        if idx == 0xFF || idx >= widget_count {
            return None;
        }

        let widget = &widgets[idx as usize];

        // If we found a DAC, we're done
        if widget.widget_type == WIDGET_TYPE_DAC {
            return Some((current_nid, path));
        }

        // Add to path (except the starting pin)
        if current_nid != start_nid {
            path.push(current_nid);
        }

        // Get connection list
        if widget.conn_len == 0 {
            return None; // Dead end
        }

        // For selectors, we need to check which input is selected or find a valid one
        if widget.widget_type == WIDGET_TYPE_SELECTOR && widget.conn_len > 1 {
            // Try each connection to find a DAC
            for conn_idx in 0..widget.conn_len.min(16) {
                let conn = corb_send_verb(
                    ctrl, corb, rirb, corb_entries, rirb_entries,
                    cad, current_nid, VERB_GET_CONN_LIST, conn_idx as u16,
                ).unwrap_or(0);
                let next_nid = (conn & 0xFF) as u8;

                if next_nid >= widget_start && next_nid < widget_start + widget_count {
                    // Recursively check if this leads to a DAC
                    let next_idx = widget_map[next_nid as usize];
                    if next_idx != 0xFF && next_idx < widget_count {
                        let next_widget = &widgets[next_idx as usize];
                        if next_widget.widget_type == WIDGET_TYPE_DAC {
                            path.push(current_nid);
                            return Some((next_nid, path));
                        }
                    }
                    current_nid = next_nid;
                    break;
                }
            }
        } else {
            // Follow first connection
            let next_nid = widget.conn_first;
            if next_nid < widget_start || next_nid >= widget_start + widget_count {
                return None;
            }
            current_nid = next_nid;
        }
    }

    None
}

// =============================================================================
// Initializes a codec by discovering and configuring audio paths.
// =============================================================================
/// This function:
/// 1. Powers up the codec
/// 2. Discovers all widgets and traces audio paths
/// 3. Configures the primary output path (DAC → mixer/selector → pin)
/// 4. Sets up amplifiers at maximum gain
/// 5. Enables output pins

pub fn init_codec_path<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    codec: &CodecInfo,
) -> Result<CodecPaths, AudioError> {
    // Power up codec function groups
    for fg_idx in 0..codec.fn_group_count {
        let fg_nid = codec.fn_group_start + fg_idx;
        let _ = set_power_state(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, fg_nid, POWER_STATE_D0,
        );
    }

    // Discover audio paths
    let mut paths = discover_paths(
        ctrl, corb, rirb, corb_entries, rirb_entries, codec,
    )?;

    // Configure primary output path
    if paths.output_count > 0 {
        let path = &mut paths.output_paths[paths.primary_output];
        configure_output_path(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, path,
        )?;
        path.active = true;
    }

    Ok(paths)
}

/// Configures a single output path.
fn configure_output_path<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    path: &AudioPath,
) -> Result<(), AudioError> {
    // 1. Power up and configure DAC
    set_power_state(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, POWER_STATE_D0,
    )?;

    // Set DAC to stream 1, channel 0 (will be reconfigured when playing)
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, VERB_SET_STREAM_CHANNEL, 0x10, // Stream 1, channel 0
    )?;

    // 2. Configure intermediate nodes (mixers, selectors)
    for i in 0..path.path_len as usize {
        let nid = path.path[i];
        if nid == 0 {
            continue;
        }

        // Power up
        let _ = set_power_state(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, POWER_STATE_D0,
        );

        // Get widget type
        let caps = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_AUDIO_WIDGET_CAP,
        ).unwrap_or(0);
        let widget_type = ((caps >> 20) & 0xF) as u8;

        // Configure amplifiers to max gain, unmuted
        if (caps & (1 << 2)) != 0 {
            // Has output amp - set to 0dB, unmuted
            set_amp_gain(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                cad, nid, true, false, 0, 0x7F, // Output, left+right, index 0, max gain
            )?;
        }
        if (caps & (1 << 1)) != 0 {
            // Has input amp - set to 0dB, unmuted
            set_amp_gain(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                cad, nid, false, false, 0, 0x7F, // Input, left+right, index 0, max gain
            )?;
        }

        // For selectors, select the connection leading to DAC
        if widget_type == WIDGET_TYPE_SELECTOR {
            // Find which connection leads to our path
            // (simplified: just select index 0)
            corb_send_verb(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                cad, nid, VERB_SET_CONN_SELECT, 0,
            )?;
        }
    }

    // 3. Configure output pin
    set_power_state(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, POWER_STATE_D0,
    )?;

    // Get pin capabilities
    let pin_caps = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, PARAM_PIN_CAP,
    ).unwrap_or(0);

    // Enable output
    let mut pin_ctl = PIN_CTL_OUT_EN;
    if path.device_type == PIN_DEV_HP_OUT {
        pin_ctl |= PIN_CTL_HP_EN; // Enable headphone amp
    }
    set_pin_control(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, pin_ctl,
    )?;

    // Enable EAPD if supported
    if (pin_caps & (1 << 16)) != 0 {
        set_eapd(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, path.pin_nid, EAPD_ENABLE,
        )?;
    }

    // Configure output amp on pin (if present)
    let caps = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, PARAM_AUDIO_WIDGET_CAP,
    ).unwrap_or(0);
    if (caps & (1 << 2)) != 0 {
        set_amp_gain(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, path.pin_nid, true, false, 0, 0x7F,
        )?;
    }

    Ok(())
}

// =============================================================================
// Control Verb Helpers
// =============================================================================

/// Power state D0 (fully on).
const POWER_STATE_D0: u8 = 0x00;
/// Pin control: output enable.
const PIN_CTL_OUT_EN: u8 = 0x40;
/// Pin control: headphone amp enable.
const PIN_CTL_HP_EN: u8 = 0x80;
/// EAPD enable bit.
const EAPD_ENABLE: u8 = 0x02;

/// Sets the power state of a node.
fn set_power_state<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    state: u8,
) -> Result<u32, AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_POWER_STATE, state as u16,
    )
}

/// Sets pin widget control.
fn set_pin_control<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    control: u8,
) -> Result<u32, AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_PIN_WIDGET_CONTROL, control as u16,
    )
}

/// Sets EAPD/BTL enable.
fn set_eapd<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    enable: u8,
) -> Result<u32, AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_EAPD_BTL_ENABLE, enable as u16,
    )
}

/// Sets amplifier gain.
///
/// # Arguments
///
/// * `output` - true for output amp, false for input amp
/// * `mute` - true to mute
/// * `index` - connection index (for input amps)
/// * `gain` - gain value (0-127)
fn set_amp_gain<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    output: bool,
    mute: bool,
    index: u8,
    gain: u8,
) -> Result<u32, AudioError> {
    // Amp gain/mute payload format:
    // Bit 15: Set output amp
    // Bit 14: Set input amp
    // Bit 13: Set left channel
    // Bit 12: Set right channel
    // Bit 7: Mute
    // Bits 6:0: Gain
    // Bits 11:8: Index (for input amps)
    let mut payload: u16 = 0;
    payload |= if output { 1 << 15 } else { 1 << 14 };
    payload |= (1 << 13) | (1 << 12); // Both channels
    payload |= (index as u16 & 0xF) << 8;
    payload |= if mute { 1 << 7 } else { 0 };
    payload |= (gain as u16) & 0x7F;

    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_AMP_GAIN_MUTE, payload,
    )
}

// =============================================================================
// Volume Control
// =============================================================================

/// Sets the volume on the primary output path.
///
/// # Arguments
///
/// * `volume` - Volume level 0-100 (percentage)
pub fn set_volume<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    paths: &CodecPaths,
    volume: u8,
) -> Result<(), AudioError> {
    if paths.output_count == 0 {
        return Err(AudioError::StreamNotConfigured);
    }

    let path = &paths.output_paths[paths.primary_output];

    // Map 0-100 to 0-127 gain range
    let gain = ((volume as u16 * 127) / 100) as u8;
    let mute = volume == 0;

    // Set gain on DAC
    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, true, mute, 0, gain,
    )?;

    // Set gain on output pin
    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, true, mute, 0, gain,
    )?;

    Ok(())
}

/// Mutes or unmutes the primary output.
pub fn set_mute<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    paths: &CodecPaths,
    mute: bool,
) -> Result<(), AudioError> {
    if paths.output_count == 0 {
        return Err(AudioError::StreamNotConfigured);
    }

    let path = &paths.output_paths[paths.primary_output];
    let gain = if mute { 0 } else { 0x7F };

    // Set on DAC
    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, true, mute, 0, gain,
    )?;

    // Set on pin
    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, true, mute, 0, gain,
    )?;

    Ok(())
}

// =============================================================================
// Vendor Information
// =============================================================================

/// Gets the name of a codec vendor from its ID.
pub fn vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0x8086 => "Intel",
        0x10DE => "NVIDIA",
        0x1002 => "AMD/ATI",
        0x10EC => "Realtek",
        0x14F1 => "Conexant",
        0x1106 => "VIA",
        0x11D4 => "Analog Devices",
        0x1057 => "Motorola",
        0x1095 => "Silicon Image",
        0x17E8 => "Chrontel",
        0x1AF4 => "VirtIO",
        0x1013 => "Cirrus Logic",
        0x1039 => "SiS",
        0x10B9 => "ALi",
        0x1274 => "Creative/Ensoniq",
        0x13F6 => "C-Media",
        0x15AD => "VMware",
        0x19E5 => "Huawei",
        0x1D17 => "Zhaoxin",
        _ => "Unknown",
    }
}

/// Gets the device name for known codec IDs.
pub fn device_name(vendor_id: u16, device_id: u16) -> &'static str {
    match (vendor_id, device_id) {
        // Realtek
        (0x10EC, 0x0221) => "ALC221",
        (0x10EC, 0x0233) => "ALC233",
        (0x10EC, 0x0235) => "ALC235",
        (0x10EC, 0x0255) => "ALC255",
        (0x10EC, 0x0256) => "ALC256",
        (0x10EC, 0x0257) => "ALC257",
        (0x10EC, 0x0269) => "ALC269",
        (0x10EC, 0x0275) => "ALC275",
        (0x10EC, 0x0280) => "ALC280",
        (0x10EC, 0x0282) => "ALC282",
        (0x10EC, 0x0283) => "ALC283",
        (0x10EC, 0x0285) => "ALC285",
        (0x10EC, 0x0287) => "ALC287",
        (0x10EC, 0x0289) => "ALC289",
        (0x10EC, 0x0292) => "ALC292",
        (0x10EC, 0x0293) => "ALC293",
        (0x10EC, 0x0295) => "ALC295",
        (0x10EC, 0x0298) => "ALC298",
        (0x10EC, 0x0299) => "ALC299",
        (0x10EC, 0x0662) => "ALC662",
        (0x10EC, 0x0663) => "ALC663",
        (0x10EC, 0x0668) => "ALC668",
        (0x10EC, 0x0670) => "ALC670",
        (0x10EC, 0x0671) => "ALC671",
        (0x10EC, 0x0700) => "ALC700",
        (0x10EC, 0x0867) => "ALC867",
        (0x10EC, 0x0880) => "ALC880",
        (0x10EC, 0x0882) => "ALC882",
        (0x10EC, 0x0883) => "ALC883",
        (0x10EC, 0x0885) => "ALC885",
        (0x10EC, 0x0887) => "ALC887",
        (0x10EC, 0x0888) => "ALC888",
        (0x10EC, 0x0889) => "ALC889",
        (0x10EC, 0x0892) => "ALC892",
        (0x10EC, 0x0897) => "ALC897",
        (0x10EC, 0x0899) => "ALC899",
        (0x10EC, 0x0900) => "ALC1150",
        (0x10EC, 0x1168) => "ALC1168",
        (0x10EC, 0x1220) => "ALC1220",

        // Intel HDMI
        (0x8086, 0x2805) => "Haswell HDMI",
        (0x8086, 0x2807) => "Haswell HDMI",
        (0x8086, 0x2808) => "Broadwell HDMI",
        (0x8086, 0x2809) => "Skylake HDMI",
        (0x8086, 0x280A) => "Broxton HDMI",
        (0x8086, 0x280B) => "Kabylake HDMI",
        (0x8086, 0x280C) => "Cannonlake HDMI",
        (0x8086, 0x280D) => "Geminilake HDMI",
        (0x8086, 0x280F) => "Icelake HDMI",
        (0x8086, 0x2812) => "Tigerlake HDMI",
        (0x8086, 0x2814) => "Alderlake HDMI",
        (0x8086, 0x2815) => "Alderlake-P HDMI",
        (0x8086, 0x2816) => "Alderlake-N HDMI",
        (0x8086, 0x2819) => "Raptorlake HDMI",
        (0x8086, 0x281A) => "Raptorlake-P HDMI",

        // NVIDIA HDMI
        (0x10DE, 0x0002) => "GeForce HDMI",
        (0x10DE, 0x0003) => "GeForce HDMI",
        (0x10DE, 0x0004) => "GeForce HDMI",
        (0x10DE, 0x0005) => "GeForce HDMI",
        (0x10DE, 0x0006) => "GeForce HDMI",
        (0x10DE, 0x0007) => "GeForce HDMI",
        (0x10DE, 0x0008) => "GeForce HDMI",
        (0x10DE, 0x0009) => "GeForce HDMI",
        (0x10DE, 0x000A) => "GeForce HDMI",
        (0x10DE, 0x000B) => "GeForce HDMI",
        (0x10DE, 0x000C) => "GeForce HDMI",
        (0x10DE, 0x000D) => "GeForce HDMI",
        (0x10DE, 0x0010) => "Tesla HDMI",
        (0x10DE, 0x0011) => "Quadro HDMI",
        (0x10DE, 0x0014) => "GTX 1060 HDMI",
        (0x10DE, 0x0015) => "GTX 1080 HDMI",

        // AMD HDMI
        (0x1002, 0x1308) => "Kaveri HDMI",
        (0x1002, 0x1314) => "Kaveri HDMI",
        (0x1002, 0x4383) => "SBx00 HDMI",
        (0x1002, 0xAA01) => "R600 HDMI",
        (0x1002, 0xAA28) => "RV700 HDMI",
        (0x1002, 0xAA38) => "RV710/730 HDMI",
        (0x1002, 0xAA60) => "Redwood HDMI",
        (0x1002, 0xAA68) => "Cedar HDMI",
        (0x1002, 0xAA98) => "Caicos HDMI",
        (0x1002, 0xAAA0) => "Tahiti HDMI",
        (0x1002, 0xAAB0) => "Oland HDMI",
        (0x1002, 0xAAB8) => "Hawaii HDMI",
        (0x1002, 0xAAC0) => "Tonga HDMI",
        (0x1002, 0xAAC8) => "Fiji HDMI",
        (0x1002, 0xAAE0) => "Polaris 11 HDMI",
        (0x1002, 0xAAE8) => "Polaris 10 HDMI",
        (0x1002, 0xAAF0) => "Vega 10 HDMI",
        (0x1002, 0xAAF8) => "Vega 20 HDMI",
        (0x1002, 0xAB08) => "Navi 10 HDMI",
        (0x1002, 0xAB18) => "Navi 14 HDMI",
        (0x1002, 0xAB28) => "Navi 21 HDMI",
        (0x1002, 0xAB38) => "Navi 22 HDMI",

        // VirtIO
        (0x1AF4, _) => "VirtIO Sound",

        // VMware
        (0x15AD, _) => "VMware HD Audio",

        _ => "Unknown Device",
    }
}
