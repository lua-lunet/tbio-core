//! The lifecycle marker surface over the vendored superblock copies.
//!
//! Raw surface; the lifecycle routing lives in the adapter. The marker is
//! the uVRR termination obligations' lifecycle marker
//! (`docs/uvrr-termination-obligations-v0.6.1.md` §2-§4), stored by the
//! Zig store's quorum-of-copies construction (`zig/src/marker.zig`): four
//! fixed sector-aligned Aegis-checksummed copies, hash-chained
//! sequence/parent, quorum write verified at the `.verify` threshold (3/4)
//! with forced I/O, quorum read resolving by highest sequence at the
//! `.open` threshold (2/4). THE BOOT-READ LAW: every block read validates
//! its checksum before any classification logic — a checksum failure on
//! ANY copy refuses with [`CORRUPT`] and the adapter PANICS on it; never
//! cleared, never repaired, never fallen back. A tear is the spread
//! writes being inconsistent across the copies (checksum-valid copies at
//! differing states), and it resolves by the stated thresholds with the
//! non-unanimity logged in full at the moment of resolution (which
//! copies, their states, their sequences). One lying or stale copy cannot
//! decide a read, and a write that did not reach its quorum is invisible
//! to it — the contract's marker-write rule, built on the vendored
//! construction.
//!
//! The single-threaded discipline applies (the C ABI surface is driven
//! from the caller's thread; the marker store opens, drives, and closes
//! its own file per call).

use std::io;

/// The FFI code the store refuses with when a readable copy fails its
/// checksum (the Zig side's `error.ChecksumRot`): THE BOOT-READ LAW's
/// distinct code. The host adapter PANICS on it — a bad block is a loud
/// log and a panic, never a hang, never a clear, never a repair, never a
/// fallback (the FFI boundary cannot panic across the ABI, so the store
/// refuses with this code and the panic lives in the host process where
/// the boot gate runs).
pub const CORRUPT: i32 = crate::ffi::CORRUPT;

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
    fn lunet_aof_marker_inspect(
        path_data: *const u8,
        path_len: usize,
        out: *mut crate::ffi::CopyInfoRaw,
    ) -> i32;
    fn lunet_aof_marker_format(
        path_data: *const u8,
        path_len: usize,
        incarnation: u64,
        state: u32,
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
/// its `(incarnation, state)`. Every readable copy's checksum is
/// validated before any classification logic: a checksum failure on ANY
/// copy surfaces as [`CORRUPT`] — the boot-read law (the adapter panics
/// on it; never cleared, never repaired, never fallen back). Any other
/// unreadable-marker shape (no quorum, a fork) is an error — the caller
/// refuses rather than guessing an identity.
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

/// One copy's raw facts as the store's inspect export reports them: the
/// `nuke` tool's view of the marker store's four copies — presence,
/// checksum status, sequence, state code, incarnation. Pure
/// diagnostics: an inspect never mutates the store.
pub type CopyInfo = crate::ffi::CopyInfoRaw;

/// The marker store's per-copy raw facts, read-only and never
/// classified: a missing or unreadable file reports SERVICE (the caller
/// distinguishes with its own existence check).
pub fn inspect(path: &std::path::Path) -> io::Result<Vec<CopyInfo>> {
    let geometry = geometry()?;
    let mut out = vec![
        CopyInfo {
            readable: 0,
            valid_checksum: 0,
            sequence: 0,
            state: 0,
            incarnation: 0,
            checksum_lo: 0,
            checksum_hi: 0,
        };
        geometry.copies
    ];
    let bytes = path.as_os_str().as_encoded_bytes();
    let rc = unsafe { lunet_aof_marker_inspect(bytes.as_ptr(), bytes.len(), out.as_mut_ptr()) };
    if rc != crate::ffi::OK {
        return Err(io::Error::other(format!(
            "marker inspect FFI code {rc} (0 = absent zones; a missing file reports SERVICE)"
        )));
    }
    Ok(out)
}

/// The nuke tool's deliberate reset: re-format the marker file FRESH at
/// sequence 1 with the named `(incarnation, state)` — an explicit
/// operator action behind the tool's own review gate, never a boot-read
/// repair (no read path formats over anything). `INVALID` for a state
/// code outside the lifecycle; [`CORRUPT`] when the store's copies are
/// rotted (the law: the tool never repairs a bad checksum either —
/// delete the file to re-seed).
pub fn format(path: &std::path::Path, incarnation: u64, state: MarkerState) -> Result<(), i32> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let rc =
        unsafe { lunet_aof_marker_format(bytes.as_ptr(), bytes.len(), incarnation, state.code()) };
    if rc == crate::ffi::OK {
        Ok(())
    } else {
        Err(rc)
    }
}
