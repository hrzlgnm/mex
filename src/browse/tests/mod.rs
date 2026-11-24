// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

mod iface;
mod listener;
mod send;
mod transmit;
mod wire;

fn test_source() -> std::net::SocketAddr {
    "192.168.178.60:5353".parse().unwrap()
}

/// Records pin/send calls; fails the configured ones.
#[derive(Default)]
struct FakeSocket {
    calls: std::cell::RefCell<Vec<String>>,
    failing_pin: Option<Egress>,
    failing_send: std::cell::Cell<bool>,
}

impl QuerySocket for FakeSocket {
    fn pin(&self, egress: Egress) -> std::io::Result<()> {
        self.calls.borrow_mut().push(format!("pin {egress:?}"));
        if self.failing_pin == Some(egress) {
            return Err(std::io::ErrorKind::AddrNotAvailable.into());
        }
        Ok(())
    }

    fn send_to(&self, _bytes: &[u8], dest: SocketAddr) -> std::io::Result<()> {
        self.calls.borrow_mut().push(format!("send {dest}"));
        if self.failing_send.get() {
            return Err(std::io::ErrorKind::NetworkUnreachable.into());
        }
        Ok(())
    }
}

/// A wire sink that accepts `budget` bytes in all, then fails every
/// write, as a full or broken buffer would: drives the encoders' error
/// handling, also on a later packet through the same sink.
struct LimitedSink {
    buf: std::io::Cursor<Vec<u8>>,
    budget: usize,
}

impl LimitedSink {
    fn new(budget: usize) -> Self {
        Self {
            buf: std::io::Cursor::new(Vec::new()),
            budget,
        }
    }
}

impl std::io::Write for LimitedSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.budget == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let n = bytes.len().min(self.budget);
        self.budget -= n;
        self.buf.write(&bytes[..n])
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for LimitedSink {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.buf.seek(pos)
    }
}

impl WireSink for LimitedSink {
    fn take_bytes(&mut self) -> Vec<u8> {
        self.buf.take_bytes()
    }
}
