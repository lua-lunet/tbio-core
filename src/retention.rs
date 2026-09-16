//! The retention policy for the standby's `{unix_epoch_seconds}.aof`
//! series: on startup the wrapper opens a NEW active file in the AOF
//! directory and sweeps the pre-existing (full) files under the retention
//! threshold.
//!
//! Policy (item21, as implemented):
//! 1. Keep the active file — never deleted.
//! 2. Keep the newest full (pre-existing) file — the freshest restart
//!    history always survives.
//! 3. Delete OLDER files (oldest-to-newest walk) while the sum of all
//!    retained AOF sizes exceeds the threshold — but never below
//!    "one active + one older" (min retention 2 files total). More old
//!    files survive only while their sum stays under the threshold.
//!
//! Boundary semantics: sum == threshold keeps everything; one byte over
//! deletes the oldest file.

use std::path::{Path, PathBuf};

/// Default retention threshold: 10 MiB of `.aof` series on disk.
pub const DEFAULT_RETENTION_BYTES: u64 = 10 * 1024 * 1024;

/// The minimum number of `.aof` files the policy keeps: the active file
/// plus one older.
pub const MIN_RETAINED: usize = 2;

/// One pre-existing AOF file: its numeric epoch key (the leading unix
/// seconds, with any `-n` same-second disambiguator) and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AofSeriesFile {
    pub epoch: u64,
    pub seq: u64,
    pub name: String,
    pub size: u64,
}

/// The retention decision, exposed for TDD: which files (oldest first) to
/// delete so the retained series fits the threshold, never dropping below
/// `MIN_RETAINED` files. `active_size` is the size of the active file
/// (0 at creation; the caller's active file is never in `files`).
///
/// `files` are the pre-existing (full) AOF files in any order. The result
/// lists names to delete in oldest-first order.
pub fn retention_plan(files: &[AofSeriesFile], active_size: u64, threshold: u64) -> Vec<String> {
    // Newest first (higher epoch wins; on a same-second collision the
    // later sequence number is the newer file).
    let mut files = files.to_vec();
    files.sort_by_key(|file| std::cmp::Reverse((file.epoch, file.seq)));

    // The newest full file always survives: min retention is one active
    // plus one older, and this is that older.
    let Some(newest_full) = files.first() else {
        return Vec::new();
    };
    let mut sum = active_size + newest_full.size;
    sum += files[1..].iter().map(|file| file.size).sum::<u64>();

    // Oldest-to-newest walk over the remainder: delete while the retained
    // sum is over the threshold. The newest full file is never in the
    // walk - it is the floor.
    let mut deletions: Vec<String> = Vec::new();
    for file in files[1..].iter().rev() {
        if sum <= threshold {
            break;
        }
        deletions.push(file.name.clone());
        sum -= file.size;
    }
    deletions
}

/// The active file's name for a unix-epoch seconds value: `{epoch}.aof`.
/// Same-second collisions (two starts within one second) pick a sequence
/// suffix `{epoch}-1.aof`, `-2.aof`, ... so the new-active-file rule
/// (create NEW, never truncate) holds regardless of clock granularity.
pub fn epoch_file_name(epoch: u64) -> String {
    format!("{epoch}.aof")
}

/// Parses a `.aof` file name into its (epoch, sequence) sort key. Returns
/// `None` for anything that is not an AOF series file (including the
/// `ev-open-*.bin` LKE1 series the console feed reads).
pub fn parse_aof_name(name: &str) -> Option<(u64, u64)> {
    let stem = name.strip_suffix(".aof")?;
    let (epoch_text, seq) = match stem.split_once('-') {
        Some((epoch_text, seq_text)) => (epoch_text, seq_text.parse::<u64>().ok()?),
        None => (stem, 0),
    };
    let epoch = epoch_text.parse::<u64>().ok()?;
    Some((epoch, seq))
}

/// The (path, epoch-key, size) listing of one `.aof` series file.
pub type ListedAofFile = (PathBuf, (u64, u64), u64);

/// Lists the `.aof` series files in `dir` (any subdirectory noise and the
/// LKE1 `.bin` series ignored), sorted oldest first.
pub fn list_aof_files(dir: &Path) -> std::io::Result<Vec<ListedAofFile>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(key) = parse_aof_name(&name) {
            let size = entry.metadata()?.len();
            result.push((entry.path(), key, size));
        }
    }
    result.sort_by_key(|(_, key, _)| *key);
    Ok(result)
}
