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

use crate::firmware::types::FirmwareType;
use crate::firmware::detection::version::FirmwareVersion;
use super::database::FirmwareDatabase;
use super::metadata::FirmwareMetadata;

#[derive(Debug, Clone)]
pub struct SearchQuery { pub vendor_filter: Option<[u8; 32]>, pub version_min: Option<FirmwareVersion>, pub version_max: Option<FirmwareVersion>, pub feature_mask: u32, pub compatibility_flags: u16 }

#[derive(Debug, Clone)]
pub struct SearchResult { pub firmware_type: FirmwareType, pub metadata: FirmwareMetadata, pub relevance_score: u8 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchFilter { ByVendor, ByVersion, ByFeatures, ByCompatibility, All }

pub fn search_firmware(db: &FirmwareDatabase, query: &SearchQuery, filter: SearchFilter) -> alloc::vec::Vec<SearchResult> {
    let mut results = alloc::vec::Vec::new();
    for i in 0..256 {
        if let Some(entry) = &db.entries[i] {
            if matches_query(&entry.metadata, query, filter) {
                let score = calculate_relevance(&entry.metadata, query);
                if score > 0 { results.push(SearchResult { firmware_type: entry.firmware_type, metadata: entry.metadata.clone(), relevance_score: score }); }
            }
        }
    }
    results.sort_by(|a, b| b.relevance_score.cmp(&a.relevance_score));
    results
}

impl Default for SearchQuery {
    fn default() -> Self { Self { vendor_filter: None, version_min: None, version_max: None, feature_mask: 0, compatibility_flags: 0 } }
}

fn matches_query(metadata: &FirmwareMetadata, query: &SearchQuery, filter: SearchFilter) -> bool {
    match filter {
        SearchFilter::ByVendor => match &query.vendor_filter { Some(vendor) => metadata.vendor == *vendor, None => true },
        SearchFilter::ByVersion => { let version_match = query.version_min.as_ref().map(|min| metadata.version.major >= min.major).unwrap_or(true) && query.version_max.as_ref().map(|max| metadata.version.major <= max.major).unwrap_or(true); version_match },
        SearchFilter::ByFeatures => (metadata.features & query.feature_mask) == query.feature_mask,
        SearchFilter::ByCompatibility => (metadata.compatibility_flags & query.compatibility_flags) == query.compatibility_flags,
        SearchFilter::All => matches_query(metadata, query, SearchFilter::ByVendor) && matches_query(metadata, query, SearchFilter::ByVersion) && matches_query(metadata, query, SearchFilter::ByFeatures) && matches_query(metadata, query, SearchFilter::ByCompatibility),
    }
}

fn calculate_relevance(metadata: &FirmwareMetadata, query: &SearchQuery) -> u8 {
    let mut score = 50;
    if query.vendor_filter.as_ref().map(|v| metadata.vendor == *v).unwrap_or(false) { score += 30; }
    if let Some(min_version) = &query.version_min { if metadata.version.major >= min_version.major { score += 10; } }
    if (metadata.features & query.feature_mask) == query.feature_mask { score += 20; }
    if (metadata.compatibility_flags & query.compatibility_flags) == query.compatibility_flags { score += 15; }
    core::cmp::min(score, 255)
}