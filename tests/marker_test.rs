//! The C ABI's marker surface, driven end to end from Rust: the quorum
//! write/read round trip, and the marker's fault model — a torn or rotted
//! copy cannot decide the read, a stale copy cannot drag the
//! classification back, a single advanced copy without a quorum cannot
//! fake a clean stop. The forged-fork (fail-closed) shape lives in the
//! Zig store's own tests, which can recompute the vendored checksum.
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use lunet_locks_aof::marker::{self, MarkerState};

fn workdir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "lunet-locks-aof-marker-{name}-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("marker workdir");
    dir
}

#[test]
fn marker_write_then_classify_round_trips_the_lifecycle() {
    let dir = workdir("roundtrip");
    let path = dir.join("state.superblock");

    marker::write(&path, 7, MarkerState::Unflushed).expect("first write");
    assert_eq!(
        marker::classify(&path).expect("classify"),
        marker::Classified {
            state: MarkerState::Unflushed,
            incarnation: 7,
        }
    );
    marker::write(&path, 7, MarkerState::Stopped).expect("stopped");
    marker::write(&path, 7, MarkerState::Flushed).expect("flushed");
    assert_eq!(
        marker::classify(&path).expect("flushed classification"),
        marker::Classified {
            state: MarkerState::Flushed,
            incarnation: 7,
        }
    );
    marker::write(&path, 8, MarkerState::Unflushed).expect("bump writes the running sentinel");
    assert_eq!(
        marker::classify(&path).expect("running sentinel"),
        marker::Classified {
            state: MarkerState::Unflushed,
            incarnation: 8,
        }
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn marker_refuses_an_invalid_state_and_a_regressing_incarnation() {
    let dir = workdir("refuse");
    let path = dir.join("state.superblock");
    assert_eq!(marker::write(&path, 9, MarkerState::Flushed), Ok(()));
    assert_eq!(marker::write(&path, 8, MarkerState::Stopped), Err(-1));
    assert_eq!(
        marker::classify(&path).expect("the marker is unchanged"),
        marker::Classified {
            state: MarkerState::Flushed,
            incarnation: 9,
        }
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// (The raw state-code validation lives behind the safe enum; the Zig
/// side's own guard is exercised there.)
///
/// The contract's whole point: a rotted copy is detectable rather than
/// trusted — garbage over one copy's zone leaves the classification to
/// the surviving quorum.
#[test]
fn marker_a_rotted_copy_cannot_flip_the_classification() {
    let dir = workdir("rot");
    let path = dir.join("state.superblock");
    let geometry = marker::geometry().expect("geometry");
    assert_eq!(geometry.copies, 4);

    marker::write(&path, 5, MarkerState::Flushed).expect("flushed");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("marker file");
        file.seek(SeekFrom::Start((geometry.copy_size * 2) as u64))
            .expect("seek copy 2");
        file.write_all(&[0xA5; 4096]).expect("rot copy 2");
    }
    assert_eq!(
        marker::classify(&path).expect("the quorum decides"),
        marker::Classified {
            state: MarkerState::Flushed,
            incarnation: 5,
        }
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The min-progress rule: a stale (valid-checksummed) copy at the previous
/// sequence cannot outvote the advanced copies — and, mirrored, a single
/// advanced copy without a quorum cannot fake a clean stop.
#[test]
fn marker_a_stale_copy_cannot_drag_the_classification_back() {
    let dir = workdir("stale");
    let path = dir.join("state.superblock");
    let geometry = marker::geometry().expect("geometry");

    marker::write(&path, 5, MarkerState::Unflushed).expect("sentinel");
    let stale = read_copy(&path, 1, geometry);
    marker::write(&path, 5, MarkerState::Flushed).expect("the stop's flush");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("marker file");
        file.seek(SeekFrom::Start(geometry.copy_size as u64))
            .expect("seek slot 1");
        file.write_all(&stale).expect("restore the stale copy");
    }
    assert_eq!(
        marker::classify(&path).expect("the advanced quorum decides"),
        marker::Classified {
            state: MarkerState::Flushed,
            incarnation: 5,
        }
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// One copy's leading zone bytes (the header lives at the zone start;
/// `copy_size` also carries the zone's reserved padding). Reads never
/// cross into the next copy: the copy zones are `copy_size` apart.
fn read_copy(path: &std::path::Path, slot: usize, geometry: marker::Geometry) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .expect("marker file");
    file.seek(SeekFrom::Start((geometry.copy_size * slot) as u64))
        .expect("seek");
    let mut header = vec![0u8; 4096.min(geometry.copy_size)];
    file.read_exact(&mut header).expect("read copy");
    header
}

/// A write that did not reach its quorum is invisible: a death after
/// exactly one copy of the `stopped` write leaves the read at the running
/// sentinel (DIRTY), never at a half-written clean stop.
#[test]
fn marker_a_single_advanced_copy_cannot_fake_a_clean_stop() {
    let dir = workdir("single-advanced");
    let path = dir.join("state.superblock");
    let geometry = marker::geometry().expect("geometry");

    marker::write(&path, 5, MarkerState::Unflushed).expect("sentinel");
    let snapshots: Vec<Vec<u8>> = (1..geometry.copies)
        .map(|slot| read_copy(&path, slot, geometry))
        .collect();
    marker::write(&path, 5, MarkerState::Stopped).expect("the stop's first write");
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("marker file");
        for (index, snapshot) in snapshots.iter().enumerate() {
            let slot = index + 1;
            file.seek(SeekFrom::Start((geometry.copy_size * slot) as u64))
                .expect("seek slot");
            file.write_all(snapshot).expect("restore the older copy");
        }
    }
    assert_eq!(
        marker::classify(&path).expect("the older quorum decides"),
        marker::Classified {
            state: MarkerState::Unflushed,
            incarnation: 5,
        }
    );
    fs::remove_dir_all(&dir).unwrap();
}
