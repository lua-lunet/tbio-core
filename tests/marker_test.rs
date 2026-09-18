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

/// The inspect: a healthy store reads as four present, checksum-valid
/// copies at the same sequence and state — the raw facts the nuke tool
/// prints.
#[test]
fn marker_inspect_reports_the_healthy_copies_raw() {
    let dir = workdir("inspect");
    let path = dir.join("state.superblock");
    marker::write(&path, 7, MarkerState::Flushed).expect("flushed");

    let copies = marker::inspect(&path).expect("inspect");
    assert_eq!(copies.len(), 4);
    for (index, copy) in copies.iter().enumerate() {
        assert_eq!(copy.readable, 1, "copy {index} present");
        assert_eq!(copy.valid_checksum, 1, "copy {index} verifies");
        assert_eq!(copy.sequence, 1);
        assert_eq!(copy.incarnation, 7);
        assert_eq!(copy.state, MarkerState::Flushed.code());
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// The nuke tool's reset: a fresh format at sequence 1 with the named
/// `(incarnation, state)`, over whatever the store held — an explicit
/// operator action, and the classification reads exactly what it wrote.
#[test]
fn marker_format_resets_the_store_to_a_named_state() {
    let dir = workdir("format");
    let path = dir.join("state.superblock");

    marker::write(&path, 9, MarkerState::Flushed).expect("flushed");
    marker::write(&path, 9, MarkerState::Stopped).expect("stopped");
    marker::format(&path, 3, MarkerState::Unflushed).expect("reset");
    assert_eq!(
        marker::classify(&path).expect("the reset state"),
        marker::Classified {
            state: MarkerState::Unflushed,
            incarnation: 3,
        }
    );
    let copies = marker::inspect(&path).expect("inspect");
    for copy in copies.iter() {
        assert_eq!(copy.sequence, 1, "the reset formats fresh at sequence 1");
        assert_eq!(copy.incarnation, 3);
        assert_eq!(copy.state, MarkerState::Unflushed.code());
    }
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
/// THE BOOT-READ LAW: a readable copy whose checksum fails is a loud
/// refusal (`CORRUPT`, the adapter's panic code) — never quorum-decided,
/// never cleared, never repaired: the rotted bytes stand unchanged after
/// the refused read.
#[test]
fn marker_a_rotted_copy_refuses_loud_and_is_never_healed() {
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
    let before = fs::read(&path).expect("the copies file");
    assert_eq!(marker::classify(&path), Err(marker::CORRUPT));
    assert_eq!(
        marker::write(&path, 5, MarkerState::Stopped),
        Err(marker::CORRUPT)
    );
    let after = fs::read(&path).expect("the copies file");
    assert_eq!(
        before, after,
        "the boot read never clears, repairs, or rewrites a bad block"
    );

    // The inspect reports the rot as DATA without refusing: copy 2 is
    // readable with a failed checksum, the other three verify.
    let copies = marker::inspect(&path).expect("inspect reads the raw copies");
    assert_eq!(copies.len(), 4);
    for (index, copy) in copies.iter().enumerate() {
        assert_eq!(copy.readable, 1);
        if index == 2 {
            assert_eq!(copy.valid_checksum, 0, "the rotted copy's checksum fails");
        } else {
            assert_eq!(copy.valid_checksum, 1);
            assert_eq!(copy.sequence, 1);
            assert_eq!(copy.incarnation, 5);
            assert_eq!(copy.state, MarkerState::Flushed.code());
        }
    }
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

/// The operator's law, the block half, read back through the C ABI: each
/// copy of a written block carries the fixed-width space-padded state
/// name at the reported offset — a raw hexdump reads the state directly —
/// and the Rust side's const table spells exactly the bytes the Zig store
/// stamped, so the two sides' tables can never disagree.
#[test]
fn marker_the_block_carries_the_readable_state_string() {
    let dir = workdir("state-string");
    let path = dir.join("state.superblock");
    let geometry = marker::geometry().expect("geometry");
    let offset = marker::state_string_offset();

    let lifecycle = [
        (MarkerState::Unflushed, "unflushed"),
        (MarkerState::Stopped, "stopped"),
        (MarkerState::Flushed, "flushed"),
    ];
    for (state, name) in lifecycle {
        marker::write(&path, 7, state).expect("the transition writes");
        let expected =
            marker::state_string_padded(state.code()).expect("a lifecycle state has a string");
        for slot in 0..geometry.copies {
            let bytes = read_copy(&path, slot, geometry);
            let stamped = &bytes[offset..offset + marker::STATE_STRING_LEN];
            assert_eq!(
                stamped,
                expected.as_slice(),
                "copy {slot}: the padded name is stamped from the shared table"
            );
            assert_eq!(&stamped[..name.len()], name.as_bytes());
            assert!(
                stamped[name.len()..].iter().all(|byte| *byte == b' '),
                "copy {slot}: the tail is spaces, the name is the head"
            );
        }
    }

    // The code paths a human reads spell names, not codes.
    assert_eq!(marker::state_name(2), Some("flushed"));
    assert_eq!(marker::state_name(3), None);
    assert_eq!(
        MarkerState::from_code(2).map(MarkerState::name),
        Some("flushed")
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The block's state string is hexdump-readable: the ASCII rendering of a
/// copy's leading zone carries the padded name in place, and the string
/// sits inside the checksummed header (tampering with it rots the
/// checksum — the disagreement case itself is refused by the store and
/// pinned in the Zig suite, which can recompute the vendored checksum).
#[test]
fn marker_the_state_string_reads_in_a_hexdump() {
    let dir = workdir("hexdump");
    let path = dir.join("state.superblock");
    marker::write(&path, 5, MarkerState::Flushed).expect("flushed");

    let bytes = read_copy(&path, 0, marker::geometry().expect("geometry"));
    let offset = marker::state_string_offset();
    let mut hexdump = String::new();
    for (index, byte) in bytes[..offset + marker::STATE_STRING_LEN]
        .iter()
        .enumerate()
    {
        if index % 16 == 0 {
            hexdump.push_str(&format!("{index:08x}  "));
        }
        hexdump.push_str(&format!("{byte:02x} "));
        if index % 16 == 15 {
            hexdump.push('\n');
        }
    }
    let ascii: String = bytes[offset..offset + marker::STATE_STRING_LEN]
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect();
    assert!(
        ascii.starts_with("flushed"),
        "the name reads in place: {ascii:?}"
    );
    assert!(
        hexdump.contains("66 6c 75 73") && hexdump.contains("68 65 64"),
        "the hexdump spells 'flushed':\n{hexdump}"
    );
    fs::remove_dir_all(&dir).unwrap();
}
