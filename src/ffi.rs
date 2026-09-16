//! The FFI declarations over the vendored TigerBeetle AOF cdylib (built by
//! build.rs from `zig/`). Raw surface; the safe wrapper lives in
//! `lib.rs`/`retention.rs`.

use std::ffi::c_void;

/// The opaque handle the Zig side owns.
pub enum AofFileRaw {}

/// The opaque read-back iterator the Zig side owns.
pub enum AofIterRaw {}

/// The maximum record length the AOF wraps: the message body capacity
/// (`message_size_max` minus the 256-byte VSR header, `constants.zig`).
pub const RECORD_MAX: usize = (1024 * 1024) - 256;

/// C ABI result codes (aof_c.zig).
pub const OK: i32 = 0;
pub const INVALID: i32 = -1;
pub const TOO_LARGE: i32 = -6;
pub const SERVICE: i32 = -7;

unsafe extern "C" {
    pub fn lunet_aof_open(
        path_data: *const u8,
        path_len: usize,
        force_flush: u8,
        out: *mut *mut AofFileRaw,
    ) -> i32;

    pub fn lunet_aof_append(
        file: *mut AofFileRaw,
        data: *const u8,
        len: usize,
        out_op: *mut u64,
    ) -> i32;

    pub fn lunet_aof_flush(file: *mut AofFileRaw) -> i32;

    pub fn lunet_aof_close(file: *mut AofFileRaw) -> i32;

    pub fn lunet_aof_iter_open(
        path_data: *const u8,
        path_len: usize,
        out: *mut *mut AofIterRaw,
    ) -> i32;

    pub fn lunet_aof_iter_next(
        it: *mut AofIterRaw,
        out_data: *mut u8,
        cap: usize,
        out_len: *mut usize,
        out_op: *mut u64,
    ) -> i32;

    pub fn lunet_aof_iter_close(it: *mut AofIterRaw);
}

/// The safe append/flush/close surface for one open AOF file.
pub struct RawFile {
    file: *mut AofFileRaw,
}

impl RawFile {
    /// The raw constructor.
    ///
    /// # Safety
    ///
    /// `path` must be a valid UTF-8 `.aof` path whose parent directory
    /// exists; the Zig side takes an exclusive lock on the file.
    pub unsafe fn open(path: &[u8], force_flush: bool) -> Result<Self, i32> {
        let mut file: *mut AofFileRaw = std::ptr::null_mut();
        let rc = unsafe { lunet_aof_open(path.as_ptr(), path.len(), force_flush as u8, &mut file) };
        if rc != OK {
            return Err(rc);
        }
        Ok(Self { file })
    }

    pub fn append(&mut self, record: &[u8]) -> Result<u64, i32> {
        assert!(record.len() <= RECORD_MAX);
        let mut op: u64 = 0;
        let rc = unsafe { lunet_aof_append(self.file, record.as_ptr(), record.len(), &mut op) };
        if rc != OK {
            return Err(rc);
        }
        Ok(op)
    }

    pub fn flush(&mut self) -> Result<(), i32> {
        let rc = unsafe { lunet_aof_flush(self.file) };
        if rc != OK {
            return Err(rc);
        }
        Ok(())
    }

    pub fn close(mut self) -> Result<(), i32> {
        let rc = unsafe { lunet_aof_close(self.file) };
        self.file = std::ptr::null_mut();
        std::mem::forget(self);
        if rc != OK {
            return Err(rc);
        }
        Ok(())
    }
}

impl Drop for RawFile {
    fn drop(&mut self) {
        if !self.file.is_null() {
            unsafe {
                let _ = lunet_aof_close(self.file);
            }
        }
    }
}

/// One decoded record read back from the AOF.
#[derive(Debug)]
pub struct RawEntry {
    pub op: u64,
    pub bytes: Vec<u8>,
}

/// The read-back iterator over one AOF file on disk.
pub struct RawIter {
    it: *mut AofIterRaw,
}

impl RawIter {
    /// The raw iterator constructor.
    ///
    /// # Safety
    ///
    /// `path` must be a valid UTF-8 path to an existing AOF file.
    pub unsafe fn open(path: &[u8]) -> Result<Self, i32> {
        let mut it: *mut AofIterRaw = std::ptr::null_mut();
        let rc = unsafe { lunet_aof_iter_open(path.as_ptr(), path.len(), &mut it) };
        if rc != OK {
            return Err(rc);
        }
        Ok(Self { it })
    }

    /// Read back the next entry, or `None` at the end of the file (or a
    /// torn tail).
    pub fn next_entry(&mut self) -> Result<Option<RawEntry>, i32> {
        let mut buf = [0u8; RECORD_MAX];
        let mut len: usize = 0;
        let mut op: u64 = 0;
        let rc =
            unsafe { lunet_aof_iter_next(self.it, buf.as_mut_ptr(), buf.len(), &mut len, &mut op) };
        if rc == 0 {
            return Ok(None);
        }
        if rc < 0 {
            return Err(rc);
        }
        Ok(Some(RawEntry {
            op,
            bytes: buf[..len].to_vec(),
        }))
    }
}

impl Drop for RawIter {
    fn drop(&mut self) {
        unsafe { lunet_aof_iter_close(self.it) };
    }
}

/// Unused FFI plumbing kept for the ABI contract: the Zig side never
/// returns pointers the Rust side must free through a different allocator.
pub const _FFI_OK: i32 = OK;
pub type _FfiVoid = c_void;
