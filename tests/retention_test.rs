//! Retention policy tests (item21, TDD): epoch filename, threshold
//! arithmetic, min-2 rule, delete-oldest-first order, and the threshold
//! boundary. The planner is pure; the on-disk integration (open sweeps the
//! directory) is covered by the wrapper test.

use lunet_locks_aof::retention::{
    AofSeriesFile, DEFAULT_RETENTION_BYTES, MIN_RETAINED, epoch_file_name, list_aof_files,
    parse_aof_name, retention_plan,
};

fn file(epoch: u64, size: u64) -> AofSeriesFile {
    AofSeriesFile {
        epoch,
        seq: 0,
        name: epoch_file_name(epoch),
        size,
    }
}

/// The working example series across these tests, oldest first:
/// o1=10 B, o2=20 B, o3=30 B; the active file is 100 B and not in the list.
/// Sum with the active file: 160 B.
fn series() -> Vec<AofSeriesFile> {
    vec![file(101, 10), file(102, 20), file(103, 30)]
}

// ------------------------------------------------------------ epoch name ----

#[test]
fn epoch_filename_is_unix_seconds_dot_aof() {
    assert_eq!(epoch_file_name(1_789_186_905), "1789186905.aof");
}

#[test]
fn aof_name_parse_rejects_non_series_files() {
    assert_eq!(parse_aof_name("1789186905.aof"), Some((1_789_186_905, 0)));
    assert_eq!(parse_aof_name("1789186905-3.aof"), Some((1_789_186_905, 3)));
    assert_eq!(parse_aof_name("ev-open-1789186905.bin"), None);
    assert_eq!(parse_aof_name("something.meta"), None);
    assert_eq!(parse_aof_name("1789186905.aof.bak"), None);
    assert_eq!(parse_aof_name(".aof"), None);
    assert_eq!(parse_aof_name("nope.aof"), None);
}

// ------------------------------------------------- threshold arithmetic ----

/// The default threshold is 10 MiB.
#[test]
fn default_retention_threshold_is_ten_mib() {
    assert_eq!(DEFAULT_RETENTION_BYTES, 10 * 1024 * 1024);
}

/// Under the threshold everything stays.
#[test]
fn retention_under_threshold_deletes_nothing() {
    // 160 < 200.
    assert!(retention_plan(&series(), 100, 200).is_empty());
}

/// The boundary: sum == threshold keeps everything; one byte over deletes
/// exactly the oldest file (the one deletion that brings it back under).
#[test]
fn retention_at_threshold_keeps_everything() {
    // 160 == 160: the boundary keeps everything.
    assert!(retention_plan(&series(), 100, 160).is_empty());
}

#[test]
fn retention_one_byte_over_deletes_the_oldest_only() {
    // 160 > 159: delete o1 (10 B) -> 150 <= 159, stop.
    let plan = retention_plan(&series(), 100, 159);
    assert_eq!(plan, vec!["101.aof".to_string()]);
}

/// Deletions happen oldest-first and stop as soon as the sum fits.
#[test]
fn retention_deletes_oldest_first_until_under_threshold() {
    // 160 > 125: delete o1 (->150), delete o2 (->130), stop at o3 (the
    // newest full file is the floor).
    let plan = retention_plan(&series(), 100, 125);
    assert_eq!(plan, vec!["101.aof".to_string(), "102.aof".to_string()]);
}

// ----------------------------------------------------------- min-2 rule ----

/// The newest full file is never deleted even when the floor keeps the sum
/// above the threshold: min retention is active + one older.
#[test]
fn retention_min_two_files_newest_full_survives() {
    // 160 > 120, and deleting o1 (->150) and o2 (->130) still leaves the
    // sum over 120 — the floor (active + o3) binds and o3 survives.
    let plan = retention_plan(&series(), 100, 120);
    assert_eq!(plan, vec!["101.aof".to_string(), "102.aof".to_string()]);
}

/// With only one pre-existing file there is nothing older than the floor:
/// nothing is ever deleted, whatever the threshold says.
#[test]
fn retention_min_two_files_single_full_file_survives_any_threshold() {
    let files = vec![file(103, 30)];
    // Even a threshold of 1 byte cannot delete the only older file.
    assert!(retention_plan(&files, 100, 1).is_empty());
}

/// A huge active file cannot push its own deletion: the active file is
/// never in the plan's input and never deleted.
#[test]
fn retention_active_file_is_never_deleted() {
    let plan = retention_plan(&series(), 100_000, 1);
    // Only the oldest files go; the newest full file stays (min-2).
    assert_eq!(plan, vec!["101.aof".to_string(), "102.aof".to_string()]);
}

/// An empty series (first boot) plans nothing.
#[test]
fn retention_empty_series_deletes_nothing() {
    assert!(retention_plan(&[], 0, 0).is_empty());
}

/// The min-2 constant is exactly the documented floor.
#[test]
fn min_retained_is_two() {
    assert_eq!(MIN_RETAINED, 2);
}

// ------------------------------------------------------------ FS listing ----

#[test]
fn list_aof_files_lists_only_aof_series_sorted_oldest_first() {
    let dir = std::env::temp_dir().join(format!(
        "lunet-locks-aof-list-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _ = std::fs::write(dir.join("104.aof"), [0u8; 5]);
    std::fs::write(dir.join("101.aof"), [0u8; 15]).unwrap();
    std::fs::write(dir.join("103.aof"), [0u8; 10]).unwrap();
    std::fs::write(dir.join("ev-open-99.bin"), [0u8; 61]).unwrap(); // LKE1 series: ignored
    std::fs::write(dir.join("1809186905.meta"), [0u8; 40]).unwrap(); // noise: ignored

    let listed = list_aof_files(&dir).unwrap();
    let keys: Vec<(u64, u64)> = listed.iter().map(|(_, key, _)| *key).collect();
    assert_eq!(keys, vec![(101, 0), (103, 0), (104, 0)]);
    let sizes: Vec<u64> = listed.iter().map(|(_, _, size)| *size).collect();
    assert_eq!(sizes, vec![15, 10, 5]);

    std::fs::remove_dir_all(&dir).unwrap();
}
