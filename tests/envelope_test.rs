//! The telemetry record envelope (item22 M1): red/green tests for the
//! marker enum, the header codec, the typed reader's classification, and
//! the unknown-marker rejection.

use lunet_locks_aof::envelope::{self, Marker, Record};

/// The header is one marker byte plus eight local-clock nanoseconds.
#[test]
fn header_is_nine_bytes() {
    assert_eq!(envelope::HEADER_BYTES, 9);
}

/// Every marker survives its byte round trip.
#[test]
fn marker_byte_round_trip() {
    assert_eq!(Marker::from_byte(Marker::Wire as u8), Some(Marker::Wire));
    assert_eq!(
        Marker::from_byte(Marker::TelemetryTimeoutDecision as u8),
        Some(Marker::TelemetryTimeoutDecision)
    );
    assert_eq!(
        Marker::from_byte(Marker::TelemetryStateTransition as u8),
        Some(Marker::TelemetryStateTransition)
    );
    assert_eq!(
        Marker::from_byte(Marker::TelemetryOutbound as u8),
        Some(Marker::TelemetryOutbound)
    );
}

/// The marker bytes are distinct so a reader can classify on the first
/// byte alone.
#[test]
fn marker_bytes_are_distinct() {
    let bytes = [
        Marker::Wire as u8,
        Marker::TelemetryTimeoutDecision as u8,
        Marker::TelemetryStateTransition as u8,
        Marker::TelemetryOutbound as u8,
    ];
    for (i, a) in bytes.iter().enumerate() {
        for b in &bytes[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

/// An unknown marker byte classifies to None — the reader's rejection path.
/// Byte 5 is known: the interval-sample marker.
#[test]
fn unknown_marker_byte_rejected() {
    assert_eq!(Marker::from_byte(0), None);
    assert_eq!(Marker::from_byte(5), Some(Marker::TelemetryIntervalSample));
    assert_eq!(Marker::from_byte(0xFF), None);
    assert_eq!(Marker::from_byte(6), None);
}

/// A Wire record wraps the raw uVRR wire bytes unchanged: the payload the
/// existing wire parser consumes, byte-identical.
#[test]
fn wire_record_carries_raw_bytes() {
    let wire_bytes: &[u8] = &[
        0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    let record = Record::wire(1_700_000_000_000_000_123, wire_bytes);
    let encoded = record.encode();
    assert_eq!(encoded[0], Marker::Wire as u8);
    assert_eq!(&encoded[1..9], &1_700_000_000_000_000_123u64.to_be_bytes());
    assert_eq!(&encoded[9..], wire_bytes);

    let decoded = Record::decode(&encoded).expect("decodes");
    assert_eq!(decoded.marker, Marker::Wire);
    assert_eq!(decoded.ns, 1_700_000_000_000_000_123);
    assert_eq!(decoded.payload, wire_bytes.to_vec());
}

/// A telemetry record decodes to its JSON payload.
#[test]
fn telemetry_record_decodes_to_json() {
    let json = br#"{"phi":1.5,"now_ms":1000,"prev_wait_ms":900,"next_wait_ms":1200}"#;
    let record = Record::telemetry(Marker::TelemetryTimeoutDecision, 42, json);
    let encoded = record.encode();
    assert_eq!(encoded[0], Marker::TelemetryTimeoutDecision as u8);

    let decoded = Record::decode(&encoded).expect("decodes");
    assert_eq!(decoded.marker, Marker::TelemetryTimeoutDecision);
    assert_eq!(decoded.ns, 42);
    assert_eq!(decoded.payload, json.to_vec());
    let value: serde_json::Value = serde_json::from_slice(&decoded.payload).expect("valid JSON");
    assert_eq!(value["phi"], 1.5);
}

/// The interval-sample subsystem (the sampled heartbeat arrival + the
/// learned interval + when it was sampled): round-trips and decodes to
/// its JSON.
#[test]
fn interval_sample_record_round_trips() {
    let json = br#"{"node":88,"era":4,"leader":33,"addr":"127.0.0.1:41101","dt_ms":22,"ts_ms":1789214915000}"#;
    let record = Record::telemetry(Marker::TelemetryIntervalSample, 77, json);
    let encoded = record.encode();
    assert_eq!(encoded[0], Marker::TelemetryIntervalSample as u8);
    let decoded = Record::decode(&encoded).expect("decodes");
    assert_eq!(decoded.marker, Marker::TelemetryIntervalSample);
    assert_eq!(decoded.ns, 77);
    assert_eq!(decoded.payload, json.to_vec());
}

/// A truncated buffer (shorter than the header) is rejected, not panicked.
#[test]
fn truncated_buffer_rejected() {
    assert!(Record::decode(&[]).is_none());
    assert!(Record::decode(&[Marker::Wire as u8; 8]).is_none());
}

/// An encoded record with an unknown marker byte is rejected on decode.
#[test]
fn encoded_unknown_marker_rejected() {
    let mut encoded = vec![0u8; 9];
    encoded[0] = 0x7F;
    encoded[1..9].copy_from_slice(&7u64.to_be_bytes());
    assert!(Record::decode(&encoded).is_none());
}
