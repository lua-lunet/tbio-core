//! The lifecycle marker surface over the vendored superblock copies.
//!
//! Raw surface; the lifecycle routing lives in the adapter. The marker is
//! the uVRR termination obligations' lifecycle marker
//! (`docs/uvrr-termination-obligations-v0.6.1.md` §2-§4), stored by the
//! Zig store's quorum-of-copies construction (`zig/src/marker.zig`): four
//! fixed sector-aligned Aegis-checksummed copies, hash-chained
//! sequence/parent, quorum write verified at the `.verify` threshold (3/4)
//! with forced I/O, quorum read resolving by highest sequence at the
//! `.open` threshold (2/4). One lying or stale copy cannot decide a read,
//! and a write that did not reach its quorum is invisible to the read —
//! the contract's marker-write rule, built on the vendored construction.
//!
//! The single-threaded discipline applies (the C ABI surface is driven
//! from the caller's thread; the marker store opens, drives, and closes
//! its own file per call).

use std::io;

/// The marker zone geometry, reported by the Zig side (the vendored
/// superblock layout, not hard-coded here).
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    /// The number of superblock copies in the marker zone (4).
    pub copies: usize,
    /// The per-copy zone stride in bytes (header + reserved padding).
    pub copy_size: usize,
}

/// The lifecycle marker's states, with the on-disk codes the Zig store
/// spells. The running sentinel stays spelled `unflushed` on disk — the
/// contract's `running` — so every existing rig marker boots unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerState {
    /// The running sentinel: the process has been (or is) operating.
    Unflushed = 0,
    /// Termination has begun: the wire was closed before this write, so
    /// the state beneath the marker is final.
    Stopped = 1,
    /// The durable-state write completed at the drain point.
    Flushed = 2,
}

impl MarkerState {
    pub fn from_code(code: u32) -> Option<MarkerState> {
        match code {
            0 => Some(MarkerState::Unflushed),
            1 => Some(MarkerState::Stopped),
            2 => Some(MarkerState::Flushed),
            _ => None,
        }
    }

    pub fn code(self) -> u32 {
        self as u32
    }
}

/// A boot classification: the working quorum's lifecycle state and the
/// replica's incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classified {
    pub state: MarkerState,
    pub incarnation: u64,
}

unsafe extern "C" {
    fn lunet_aof_marker_geometry(out_copies: *mut usize, out_copy_size: *mut usize) -> i32;
    fn lunet_aof_marker_write(
        path_data: *const u8,
        path_len: usize,
        incarnation: u64,
        state: u32,
    ) -> i32;
    fn lunet_aof_marker_classify(
        path_data: *const u8,
        path_len: usize,
        out_incarnation: *mut u64,
        out_state: *mut u32,
    ) -> i32;
}

/// The marker zone geometry (copy count, per-copy byte size).
pub fn geometry() -> io::Result<Geometry> {
    let mut copies: usize = 0;
    let mut copy_size: usize = 0;
    let rc = unsafe { lunet_aof_marker_geometry(&mut copies, &mut copy_size) };
    if rc != crate::ffi::OK {
        return Err(io::Error::other(format!("marker geometry FFI code {rc}")));
    }
    Ok(Geometry { copies, copy_size })
}

/// One lifecycle transition: quorum-write `(incarnation, state)` into the
/// marker file at `path` (creating it, never truncating it), forced I/O,
/// verify read-back. `INVALID` codes (a state outside the lifecycle, an
/// incarnation that would regress the marker) and every storage failure
/// surface as the FFI code.
pub fn write(path: &std::path::Path, incarnation: u64, state: MarkerState) -> Result<(), i32> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let rc =
        unsafe { lunet_aof_marker_write(bytes.as_ptr(), bytes.len(), incarnation, state.code()) };
    if rc == crate::ffi::OK {
        Ok(())
    } else {
        Err(rc)
    }
}

/// The boot classification: read the marker's working quorum and report
/// its `(incarnation, state)`. Any unreadable-marker shape (no quorum, a
/// fork, rotted copies) is an error — the caller refuses rather than
/// guessing an identity.
pub fn classify(path: &std::path::Path) -> Result<Classified, i32> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut incarnation: u64 = 0;
    let mut state: u32 = 0;
    let rc = unsafe {
        lunet_aof_marker_classify(bytes.as_ptr(), bytes.len(), &mut incarnation, &mut state)
    };
    if rc != crate::ffi::OK {
        return Err(rc);
    }
    let state = MarkerState::from_code(state).ok_or(crate::ffi::SERVICE)?;
    Ok(Classified { state, incarnation })
}
