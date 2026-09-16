//! The safe Rust binding over the vendored TigerBeetle AOF (0.17.9).
//!
//! The AOF is TigerBeetle's append-only write-behind log, vendored as
//! stripped Zig sources (`zig/`) compiled to a cdylib through the repo's
//! mise-pinned Zig 0.14.1. One entry per appended record, hash-chained by
//! Prepare-header checksums, page-cached blocking writes, and an
//! **optional** durability force: the default (and the standby learner's
//! setting) is force OFF — amortized buffered writes, fsync on explicit
//! flush and at the vendored entry-window cap. See `AOF.md` in this crate
//! for the full system description, the upstream attribution, and the
//! licence facts.
//!
//! # Retention
//!
//! [`AofFile::open`] creates a NEW active file named
//! `{unix_epoch_seconds}.aof` in the given directory and sweeps the
//! pre-existing (full) series under the retention threshold (default
//! 10 MiB): the active file and the newest full file always survive; older
//! files are deleted oldest-first while the retained sum exceeds the
//! threshold, never below one active + one older. The retention planner is
//! pure and unit-tested in [`retention`]; the sweep runs on open.

pub mod envelope;
pub mod ffi;
pub mod marker;
pub mod retention;

use std::io;
use std::path::{Path, PathBuf};

/// The safe AOF error: an FFI result code or the filesystem errors the
/// wrapper itself can hit (directory creation, epoch naming).
#[derive(Debug)]
pub enum Error {
    /// The record exceeds the vendored message body capacity.
    TooLarge,
    /// An FFI result code from the Zig AOF (`INVALID`, `SERVICE`, ...).
    Ffi(i32),
    /// A filesystem error on the wrapper's own path work.
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooLarge => write!(f, "record exceeds the AOF message body capacity"),
            Error::Ffi(code) => write!(f, "aof FFI error code {code}"),
            Error::Io(error) => write!(f, "aof filesystem error: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// The AOF file's tuning knobs.
#[derive(Debug, Clone)]
pub struct Options {
    /// The optional durability force. OFF (the default) never fsyncs on
    /// the append path: amortized page-cached writes, fsync on explicit
    /// [`AofFile::flush`] and when the vendored unflushed-window cap
    /// (`journal_slot_count`) fills. ON fsyncs after every append — the
    /// upstream checkpoint's durability discipline per entry, for hosts
    /// that want it.
    pub force_flush: bool,
    /// The retention threshold the startup sweep enforces (bytes of
    /// `.aof` series on disk). Default 10 MiB.
    pub retention_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            force_flush: false,
            retention_bytes: retention::DEFAULT_RETENTION_BYTES,
        }
    }
}

/// One open AOF file (the active file of one learner's series).
pub struct AofFile {
    file: ffi::RawFile,
    /// The active file's absolute path (the FFI opened it by full path).
    path: PathBuf,
}

impl AofFile {
    /// Open the series at `dir` with the default options: a NEW
    /// `{unix_epoch_seconds}.aof` active file, force OFF, 10 MiB
    /// retention.
    pub fn open(dir: &Path) -> Result<Self, Error> {
        Self::open_with(dir, Options::default())
    }

    /// Open the series at `dir` with explicit knobs. On startup this:
    /// 1. creates the directory (first boot),
    /// 2. sweeps the pre-existing `.aof` series under the retention
    ///    threshold (active file + newest full file survive; older files
    ///    go oldest-first while the sum is over the threshold),
    /// 3. creates the NEW active file `{epoch}.aof` (same-second
    ///    collisions pick `{epoch}-1.aof`, `-2.aof`, ... — create-new
    ///    never truncates),
    /// 4. opens it through the Zig cdylib with the force knob set.
    pub fn open_with(dir: &Path, options: Options) -> Result<Self, Error> {
        std::fs::create_dir_all(dir)?;

        // The retention sweep: plan over the pre-existing series (the new
        // active file does not exist yet, so active_size is 0), then
        // unlink in the planned (oldest-first) order.
        let listed = retention::list_aof_files(dir)?;
        let files: Vec<retention::AofSeriesFile> = listed
            .iter()
            .map(|(path, key, size)| retention::AofSeriesFile {
                epoch: key.0,
                seq: key.1,
                name: path.file_name().unwrap().to_string_lossy().to_string(),
                size: *size,
            })
            .collect();
        for name in retention::retention_plan(&files, 0, options.retention_bytes) {
            std::fs::remove_file(dir.join(&name))?;
        }

        // The NEW active file: {epoch}.aof, or {epoch}-1.aof, -2.aof, ...
        // on a same-second collision (create-new, never truncate).
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut seq: u64 = 0;
        let path = loop {
            let name = if seq == 0 {
                retention::epoch_file_name(epoch)
            } else {
                format!("{epoch}-{seq}.aof")
            };
            let path = dir.join(&name);
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => break path,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    seq += 1;
                }
                Err(error) => return Err(error.into()),
            }
        };

        let file =
            unsafe { ffi::RawFile::open(path.as_os_str().as_encoded_bytes(), options.force_flush) }
                .map_err(Error::Ffi)?;
        Ok(Self { file, path })
    }

    /// Append one record. The record bytes become the body of a fresh
    /// Prepare entry in the TigerBeetle AOF format: the vendored Zig side
    /// stamps the chain (parent = the previous entry's checksum), a
    /// monotonic op, the timestamp, and the Aegis checksums, then writes
    /// page-cached. With the force knob ON the entry is fsynced before
    /// this returns. Returns the entry's op number.
    pub fn append(&mut self, record: &[u8]) -> Result<u64, Error> {
        if record.len() > ffi::RECORD_MAX {
            return Err(Error::TooLarge);
        }
        self.file.append(record).map_err(Error::Ffi)
    }

    /// The explicit flush: one fsync through the vendored checkpoint path.
    /// The default (force OFF) durability contract: everything appended
    /// before this call is durable once it returns.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.file.flush().map_err(Error::Ffi)
    }

    /// Close: flush (the graceful-shutdown flush) and release the file.
    pub fn close(self) -> Result<(), Error> {
        self.file.close().map_err(Error::Ffi)
    }

    /// The active file's path (for operators: which file is being
    /// appended to).
    pub fn path(&self) -> &Path {
        &self.path
    }
}
