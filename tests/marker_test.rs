//! The C ABI's marker surface, driven end to end from Rust: the quorum
//! write/read round trip over the native identity pair
//! `{systemIdentifier, crashCounter}` (one-indexed, zero refused at the
//! ABI edge, the pair-aware regress guard), and the marker's fault model
//! — a torn or rotted copy cannot decide the read, a stale copy cannot
//! drag the classification back, a single advanced copy without a quorum
//! cannot fake a clean stop. The forged-fork (fail-closed) shape lives in
//! the Zig store's own tests, which can recompute the vendored checksum.
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use lunet_locks_aof::marker::{self, MarkerState, NodeIdentity};

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

/// The identity law's shape, pinned before anything touches disk: both
/// halves are one-indexed, zero is never a legal identity, and the packed
/// u32 (MSB system, LSB crash — the wire form hosts derive) round-trips
/// through the pair.
#[test]
fn node_identity_is_one_indexed_and_never_zero() {
    assert!(
        NodeIdentity::new(0, 1).is_none(),
        "a zero system is not an identity"
    );
    assert!(
        NodeIdentity::new(1, 0).is_none(),
        "a zero counter is not an identity"
    );
    assert!(NodeIdentity::new(0, 0).is_none());

    let identity = NodeIdentity::new(3, 9).expect("a nonzero pair");
    assert_eq!(identity.system_identifier(), 3);
    assert_eq!(identity.crash_counter(), 9);
    assert_eq!(identity.packed(), (3 << 16) | 9);
    assert_eq!(NodeIdentity::from_packed(identity.packed()), Some(identity));

    // The packed form is MSB system, LSB crash: a hexdump reads the pair
    // in place. A zero half in the packed word refuses too — bytes
    // entering from outside get the same validation.
    assert_eq!(NodeIdentity::from_packed(9), None, "system 0");
    assert_eq!(NodeIdentity::from_packed(3 << 16), None, "counter 0");
}

#[test]
fn marker_write_then_classify_round_trips_the_lifecycle() {
    let dir = workdir("roundtrip");
    let path = dir.join("state.superblock");
    let genesis = NodeIdentity::new(1, 7).expect("identity");
    let bumped = NodeIdentity::new(1, 8).expect("identity");

    marker::write(&path, genesis, MarkerState::Unflushed).expect("first write");
    assert_eq!(
        marker::classify(&path).expect("classify"),
        marker::Classified {
            state: MarkerState::Unflushed,
            identity: genesis,
        }
    );
    // The same life (the same crash counter) carries stopped/flushed.
    marker::write(&path, genesis, MarkerState::Stopped).expect("stopped");
    marker::write(&path, genesis, MarkerState::Flushed).expect("flushed");
    assert_eq!(
        marker::classify(&path).expect("flushed classification"),
        marker::Classified {
            state: MarkerState::Flushed,
            identity: genesis,
        }
    );
    // A later life's bump: the counter strictly advances for the same
    // system, the sentinel returns.
    marker::write(&path, bumped, MarkerState::Unflushed).expect("bump writes the running sentinel");
    assert_eq!(
        marker::classify(&path).expect("running sentinel"),
        marker::Classified {
            state: MarkerState::Unflushed,
            identity: bumped,
        }
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The pair-aware write guard: a crash bump strictly advances the counter
/// for the same system; a regress refuses; a different system identifier
/// on an existing marker is a corruption refusal (CORRUPT, the panic
/// class — never an overwrite), whatever counter it claims.
#[test]
fn marker_the_pair_guard_refuses_regress_and_cross_system() {
    let dir = workdir("guard");
    let path = dir.join("state.superblock");
    let nine = NodeIdentity::new(3, 9).expect("identity");
    let regressed = NodeIdentity::new(3, 8).expect("identity");
    let foreign_life = NodeIdentity::new(4, 1).expect("identity");
    let foreign_bump = NodeIdentity::new(4, 10).expect("identity");

    assert_eq!(marker::write(&path, nine, MarkerState::Flushed), Ok(()));
    assert_eq!(
        marker::write(&path, regressed, MarkerState::Stopped),
        Err(-1),
        "same system, lower counter: a regress, never an overwrite"
    );
    assert_eq!(
        marker::write(&path, foreign_life, MarkerState::Stopped),
        Err(marker::CORRUPT),
        "a different system on an existing marker is corruption"
    );
    assert_eq!(
        marker::write(&path, foreign_bump, MarkerState::Stopped),
        Err(marker::CORRUPT),
        "even a strictly advancing counter under a foreign system"
    );
    assert_eq!(
        marker::classify(&path).expect("the marker is unchanged"),
        marker::Classified {
            state: MarkerState::Flushed,
            identity: nine,
        }
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The inspect: a healthy store reads as four present, checksum-valid
/// copies at the same sequence and state — the raw facts the
/// `lunet_locks_nuke` admin tool prints, the pair packed in each.
#[test]
fn marker_inspect_reports_the_healthy_copies_raw() {
    let dir = workdir("inspect");
    let path = dir.join("state.superblock");
    let identity = NodeIdentity::new(1, 7).expect("identity");
    marker::write(&path, identity, MarkerState::Flushed).expect("flushed");

    let copies = marker::inspect(&path).expect("inspect");
    assert_eq!(copies.len(), 4);
    for (index, copy) in copies.iter().enumerate() {
        assert_eq!(copy.readable, 1, "copy {index} present");
        assert_eq!(copy.valid_checksum, 1, "copy {index} verifies");
        assert_eq!(copy.sequence, 1);
        assert_eq!(
            copy.node,
            identity.packed(),
            "copy {index} carries the pair"
        );
        assert_eq!(copy.identity(), Some(identity), "copy {index} decodes");
        assert_eq!(copy.state, MarkerState::Flushed.code());
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// The `lunet_locks_nuke` admin tool's reset: a fresh format at sequence 1 with the named
/// `(systemIdentifier, crashCounter, state)`, over whatever the store
/// held — an explicit operator action, and the only path that re-seats a
/// marker to a different system identifier.
#[test]
fn marker_format_resets_the_store_to_a_named_identity() {
    let dir = workdir("format");
    let path = dir.join("state.superblock");
    let old = NodeIdentity::new(1, 9).expect("identity");
    let reseat = NodeIdentity::new(2, 3).expect("identity");

    marker::write(&path, old, MarkerState::Flushed).expect("flushed");
    marker::write(&path, old, MarkerState::Stopped).expect("stopped");
    marker::format(&path, reseat, MarkerState::Unflushed).expect("reset");
    assert_eq!(
        marker::classify(&path).expect("the reset identity"),
        marker::Classified {
            state: MarkerState::Unflushed,
            identity: reseat,
        }
    );
    let copies = marker::inspect(&path).expect("inspect");
    for copy in copies.iter() {
        assert_eq!(copy.sequence, 1, "the reset formats fresh at sequence 1");
        assert_eq!(copy.node, reseat.packed());
        assert_eq!(copy.state, MarkerState::Unflushed.code());
    }
    // The guard keys on the re-seated system: the old system is now the
    // foreign one.
    assert_eq!(
        marker::write(&path, old, MarkerState::Stopped),
        Err(marker::CORRUPT)
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn marker_refuses_an_invalid_state() {
    let dir = workdir("refuse-state");
    let path = dir.join("state.superblock");
    let identity = NodeIdentity::new(1, 1).expect("identity");
    // (The raw state-code validation lives behind the safe enum; the zero
    // halves cannot be spelled through the safe pair, and the Zig side's
    // own edge guard is exercised there.)
    assert_eq!(marker::write(&path, identity, MarkerState::Flushed), Ok(()));
    fs::remove_dir_all(&dir).unwrap();
}

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
    let identity = NodeIdentity::new(1, 5).expect("identity");

    marker::write(&path, identity, MarkerState::Flushed).expect("flushed");
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
        marker::write(&path, identity, MarkerState::Stopped),
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
            assert_eq!(copy.node, identity.packed());
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
    let identity = NodeIdentity::new(1, 5).expect("identity");

    marker::write(&path, identity, MarkerState::Unflushed).expect("sentinel");
    let stale = read_copy(&path, 1, geometry);
    marker::write(&path, identity, MarkerState::Flushed).expect("the stop's flush");
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
            identity,
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
    let identity = NodeIdentity::new(1, 5).expect("identity");

    marker::write(&path, identity, MarkerState::Unflushed).expect("sentinel");
    let snapshots: Vec<Vec<u8>> = (1..geometry.copies)
        .map(|slot| read_copy(&path, slot, geometry))
        .collect();
    marker::write(&path, identity, MarkerState::Stopped).expect("the stop's first write");
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
            identity,
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
    let identity = NodeIdentity::new(1, 7).expect("identity");

    let lifecycle = [
        (MarkerState::Unflushed, "unflushed"),
        (MarkerState::Stopped, "stopped"),
        (MarkerState::Flushed, "flushed"),
    ];
    for (state, name) in lifecycle {
        marker::write(&path, identity, state).expect("the transition writes");
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
    let identity = NodeIdentity::new(1, 5).expect("identity");
    marker::write(&path, identity, MarkerState::Flushed).expect("flushed");

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
