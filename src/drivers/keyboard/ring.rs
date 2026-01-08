// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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


use super::event::KeyEvent;
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct SpscU8Ring<const N: usize> {
    buf: [u8; N],
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl<const N: usize> SpscU8Ring<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn mask() -> usize {
        N - 1
    }

    #[inline]
    pub fn push(&mut self, byte: u8) {
        let head = self.head.load(Ordering::Relaxed);
        let next = (head.wrapping_add(1)) & Self::mask();
        let tail = self.tail.load(Ordering::Acquire);
        if next == tail {
            self.tail
                .store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        }

        self.buf[head] = byte;
        self.head.store(next, Ordering::Release);
    }

    #[inline]
    pub fn pop(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }

        let byte = self.buf[tail];
        self.tail
            .store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        Some(byte)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        (head.wrapping_sub(tail)) & Self::mask()
    }
}

pub struct SpscEvtRing<const N: usize> {
    buf: [u8; N],
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl<const N: usize> SpscEvtRing<N> {
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn mask() -> usize {
        N - 1
    }

    #[inline]
    pub fn push_evt(&mut self, e: KeyEvent) {
        let code = e.to_code();
        let head = self.head.load(Ordering::Relaxed);
        let next = (head.wrapping_add(1)) & Self::mask();
        let tail = self.tail.load(Ordering::Acquire);
        if next == tail {
            self.tail
                .store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        }

        self.buf[head] = code;
        self.head.store(next, Ordering::Release);
    }

    #[inline]
    pub fn pop_evt(&self) -> Option<KeyEvent> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }

        let code = self.buf[tail];
        self.tail
            .store((tail.wrapping_add(1)) & Self::mask(), Ordering::Release);
        KeyEvent::from_code(code)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u8_ring_empty() {
        let ring: SpscU8Ring<16> = SpscU8Ring::new();
        assert!(ring.is_empty());
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn test_u8_ring_push_pop() {
        let mut ring: SpscU8Ring<16> = SpscU8Ring::new();
        ring.push(b'a');
        ring.push(b'b');
        ring.push(b'c');

        assert!(!ring.is_empty());
        assert_eq!(ring.pop(), Some(b'a'));
        assert_eq!(ring.pop(), Some(b'b'));
        assert_eq!(ring.pop(), Some(b'c'));
        assert!(ring.is_empty());
    }

    #[test]
    fn test_u8_ring_overflow() {
        let mut ring: SpscU8Ring<4> = SpscU8Ring::new();
        ring.push(b'1');
        ring.push(b'2');
        ring.push(b'3');
        ring.push(b'4');

        assert_eq!(ring.pop(), Some(b'2'));
        assert_eq!(ring.pop(), Some(b'3'));
        assert_eq!(ring.pop(), Some(b'4'));
    }

    #[test]
    fn test_evt_ring_basic() {
        let mut ring: SpscEvtRing<8> = SpscEvtRing::new();
        ring.push_evt(KeyEvent::Up);
        ring.push_evt(KeyEvent::Down);

        assert_eq!(ring.pop_evt(), Some(KeyEvent::Up));
        assert_eq!(ring.pop_evt(), Some(KeyEvent::Down));
        assert_eq!(ring.pop_evt(), None);
    }
}
