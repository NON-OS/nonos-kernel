// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use super::super::super::error::AudioError;
use super::super::super::types::Volume;
use super::super::codec;
use super::structure::HdAudioController;
use core::sync::atomic::Ordering;

impl HdAudioController {
    #[inline]
    pub fn get_volume(&self) -> Volume {
        Volume::new(self.volume.load(Ordering::Relaxed))
    }

    pub fn set_volume(&self, volume: u8) -> Result<(), AudioError> {
        let vol = volume.min(100);
        self.volume.store(vol, Ordering::Relaxed);
        if let (Some(cad), Some(ref paths)) = (self.primary_codec, &self.codec_paths) {
            codec::set_volume(
                self,
                &self.corb,
                &self.rirb,
                self.corb_entries,
                self.rirb_entries,
                cad,
                paths,
                vol,
            )?;
        }
        Ok(())
    }

    #[inline]
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    pub fn set_mute(&self, mute: bool) -> Result<(), AudioError> {
        self.muted.store(mute, Ordering::Relaxed);
        if let (Some(cad), Some(ref paths)) = (self.primary_codec, &self.codec_paths) {
            codec::set_mute(
                self,
                &self.corb,
                &self.rirb,
                self.corb_entries,
                self.rirb_entries,
                cad,
                paths,
                mute,
            )?;
        }
        Ok(())
    }

    pub fn toggle_mute(&self) -> Result<bool, AudioError> {
        let new_muted = !self.muted.load(Ordering::Relaxed);
        self.set_mute(new_muted)?;
        Ok(new_muted)
    }
}
