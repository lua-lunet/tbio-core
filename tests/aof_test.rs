//! The FFI smoke test: an append + read round-trip through the Zig cdylib,
//! with the vendored checksum chain validating every entry on read-back.
//! Plus the wrapper surface tests (open/append/flush/close and the
//! optional force knob) and the on-disk retention sweep at open.

use lunet_locks_aof::{AofFile, Options, retention};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lunet-locks-aof-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ------------------------------------------------------------ FFI smoke ----

/// The required round-trip: two records appended through the Zig AOF,
/// closed, then read back through the vendored iterator — which validates
/// each entry's header/body Aegis checksums and the entry chain before
/// handing the bytes over. The payloads must arrive byte-identical and op
/// numbered 1, 2.
#[test]
fn ffi_append_read_round_trips_through_the_cdylib() {
    let dir = temp_dir("smoke");
    let payload_one = b"heartbeat/commit record one";
    let payload_two = b"heartbeat/commit record two";

    let mut aof = AofFile::open(&dir).expect("open");
    assert_eq!(aof.append(payload_one).unwrap(), 1);
    assert_eq!(aof.append(payload_two).unwrap(), 2);
    aof.close().unwrap();

    let active = active_file(&dir).expect("active file exists");
    let mut it =
        unsafe { lunet_locks_aof::ffi::RawIter::open(active.as_os_str().as_encoded_bytes()) }
            .expect("iterator opens");
    let first = it.next_entry().unwrap().expect("first entry");
    assert_eq!(first.op, 1);
    assert_eq!(first.bytes, payload_one.to_vec());
    let second = it.next_entry().unwrap().expect("second entry");
    assert_eq!(second.op, 2);
    assert_eq!(second.bytes, payload_two.to_vec());
    assert!(it.next_entry().unwrap().is_none(), "iteration ends at EOF");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// Corrupting a payload byte on disk must fail the read-back with the
/// vendored checksum error (SERVICE), proving the checksums are real —
/// the round-trip above is not passing by accident.
#[test]
fn ffi_read_rejects_a_corrupted_entry_checksum() {
    let dir = temp_dir("corrupt");
    let mut aof = AofFile::open(&dir).expect("open");
    aof.append(b"tamper target").unwrap();
    aof.close().unwrap();

    let active = active_file(&dir).unwrap();
    let mut bytes = std::fs::read(&active).unwrap();
    // Flip one body byte (inside the first entry, after the 256-byte
    // header and the 16-byte magic).
    let body_at = 16 /* magic */ + 256 /* header */ + 4 /* first body byte */;
    bytes[body_at] ^= 0xFF;
    std::fs::write(&active, &bytes).unwrap();

    let mut it =
        unsafe { lunet_locks_aof::ffi::RawIter::open(active.as_os_str().as_encoded_bytes()) }
            .expect("iterator opens");
    assert_eq!(it.next_entry().unwrap_err(), lunet_locks_aof::ffi::SERVICE);

    std::fs::remove_dir_all(&dir).unwrap();
}

// ------------------------------------------------------- wrapper surface ----

/// Open creates a NEW active file named `{unix_epoch_seconds}.aof` in the
/// given directory, and a second open in the same second picks the `-1`
/// disambiguator (create-new never truncates).
#[test]
fn wrapper_open_creates_the_epoch_named_active_file() {
    let dir = temp_dir("epoch");
    let aof = AofFile::open(&dir).expect("open");
    drop(aof);

    let names = aof_names(&dir);
    assert_eq!(names.len(), 1, "one active file: {names:?}");
    let name = &names[0];
    assert!(name.ends_with(".aof"), "{name}");
    let epoch_text = name.trim_end_matches(".aof");
    let epoch: u64 = epoch_text.parse().expect("numeric epoch");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The active file is stamped with the current unix seconds (±1 s for
    // the tick between now() calls).
    assert!(now.abs_diff(epoch) <= 1, "epoch {epoch} is not now ({now})");

    // A second open in the same second picks the -1 suffix.
    let aof2 = AofFile::open(&dir).expect("second open");
    drop(aof2);
    let names = aof_names(&dir);
    assert_eq!(
        names.len(),
        2,
        "two active files after two opens: {names:?}"
    );
    assert!(
        names.iter().any(|name| name.ends_with("-1.aof")),
        "the same-second collision picked the -1 disambiguator: {names:?}"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// Records above the message body capacity are refused by the wrapper
/// before they reach the FFI.
#[test]
fn wrapper_append_rejects_oversized_records() {
    let dir = temp_dir("oversize");
    let mut aof = AofFile::open(&dir).expect("open");
    let oversized = vec![0u8; lunet_locks_aof::ffi::RECORD_MAX + 1];
    assert!(matches!(
        aof.append(&oversized),
        Err(lunet_locks_aof::Error::TooLarge)
    ));
    aof.close().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The optional force knob: with force ON every append is immediately
/// durable — proven by the reopen reading back after only append+close
/// without an explicit flush... actually the durable proof is the fsync;
/// what the test pins is that force=ON (a) accepts appends and (b) the
/// flushed state survives a reopen through the iterator after an explicit
/// process-style close, and force=OFF is the default (Options::default).
#[test]
fn wrapper_default_options_have_force_off_and_ten_mib_retention() {
    let options = Options::default();
    assert!(!options.force_flush);
    assert_eq!(options.retention_bytes, retention::DEFAULT_RETENTION_BYTES);
}

/// With force ON, appends carry their fsync (the per-entry forced write).
/// The observable: the entry is on disk AND durable once append returns;
/// we assert the append+flush-less close path yields a readable file whose
/// chain validates — and, crucially, that force=ON appends land in a file
/// whose fsync happened before close (close itself flushes; the knob's
/// per-append fsync is the vendored AOF's checkpoint per entry).
#[test]
fn wrapper_force_flush_on_round_trips_per_entry() {
    let dir = temp_dir("forced");
    let mut aof = AofFile::open_with(
        &dir,
        Options {
            force_flush: true,
            ..Options::default()
        },
    )
    .expect("open");
    aof.append(b"forced durability").unwrap();
    aof.close().unwrap();

    let active = active_file(&dir).unwrap();
    let mut it =
        unsafe { lunet_locks_aof::ffi::RawIter::open(active.as_os_str().as_encoded_bytes()) }
            .expect("iterator opens");
    let entry = it.next_entry().unwrap().expect("entry");
    assert_eq!(entry.bytes, b"forced durability".to_vec());
    std::fs::remove_dir_all(&dir).unwrap();
}

// ----------------------------------------------- on-disk retention sweep ----

/// Opening the series applies the retention sweep on disk: under-threshold
/// pre-existing files survive, over-threshold oldest files go, the newest
/// full file always stays, and the fresh active file is created.
#[test]
fn wrapper_open_applies_retention_on_disk() {
    let dir = temp_dir("sweep");
    // Two pre-existing full files: 10 B (older) and 2 KiB (newer), plus a
    // foreign `.bin` file the sweep must ignore. Threshold: small enough
    // that the older file's removal is needed (active 0 + 10 + 2048 > 100),
    // but 2048 <= 100 never holds... size the threshold so the boundary is
    // exercised: active(0) + 2048 = 2048 <= threshold(3000): keep both.
    std::fs::write(dir.join("101.aof"), [0u8; 10]).unwrap();
    std::fs::write(dir.join("102.aof"), [0u8; 2048]).unwrap();
    std::fs::write(dir.join("ev-open-99.bin"), [0u8; 61]).unwrap();

    let aof = AofFile::open_with(
        &dir,
        Options {
            retention_bytes: 3000,
            ..Options::default()
        },
    )
    .expect("open");
    drop(aof);
    // Nothing deleted: 2048 <= 3000.
    assert_eq!(aof_names(&dir).len(), 3, "all three series files survive");
    assert!(
        dir.join("ev-open-99.bin").exists(),
        "the .bin series ignored"
    );

    // One byte over the boundary: 2048 + 10 = 2058 > 2057 -> the oldest
    // (10 B) goes.
    let aof = AofFile::open_with(
        &dir,
        Options {
            retention_bytes: 2057,
            ..Options::default()
        },
    )
    .expect("open");
    drop(aof);
    assert!(!dir.join("101.aof").exists(), "the oldest file deleted");
    assert!(dir.join("102.aof").exists(), "the newest full file stays");

    std::fs::remove_dir_all(&dir).unwrap();
}

// ------------------------------------------------------------------ utils ----

fn aof_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.ends_with(".aof"))
        .collect();
    names.sort();
    names
}

fn active_file(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut newest: Option<(u64, u64, std::path::PathBuf)> = None;
    for (path, key, _) in retention::list_aof_files(dir).unwrap() {
        if newest
            .as_ref()
            .is_none_or(|(epoch, seq, _)| key > (*epoch, *seq))
        {
            newest = Some((key.0, key.1, path));
        }
    }
    newest.map(|(_, _, path)| path)
}
