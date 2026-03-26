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

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone)]
pub enum AppError {
    InitFailed,
    RenderFailed,
    StorageError,
    NetworkError,
    PermissionDenied,
    InvalidState,
}

#[derive(Clone, Copy, PartialEq)]
pub enum AppEvent {
    Click(u32, u32),
    Key(u8),
    Scroll(i32),
    Focus,
    Blur,
    Resize(u32, u32),
    Timer(u64),
}

pub struct AppContext {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub focused: bool,
    pub app_id: u32,
}

pub trait App: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn init(&mut self, ctx: &AppContext) -> AppResult<()>;
    fn render(&self, ctx: &AppContext);
    fn handle_event(&mut self, ctx: &AppContext, event: AppEvent) -> AppResult<bool>;
    fn cleanup(&mut self);
}
