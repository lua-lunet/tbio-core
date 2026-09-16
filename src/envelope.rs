//! The telemetry record envelope (item22 M1): the typed record layer above
//! the raw AOF append. Every AOF entry the telemetry system writes is one
//! envelope record; the uVRR wire protocol itself is untouched — a Wire
//! record's payload IS the raw wire message in its existing serialization,
//! handed to the existing parser on read-back.
//!
//! Layout (little-endian machine, big-endian on purpose for the fields a
//! post-mortem aligner reads by hand):
//!
//! ```text
//! marker(1) | local_clock_ns(8, BE) | payload...
//! ```
//!
//! The local clock is the writing node's nanosecond-resolution wall clock
//! (UNIX epoch based); the three DCs' traces align afterwards by parsing
//! these headers.
//!
//! # Marker table
//!
//! | byte | marker                    | payload                                        |
//! |------|---------------------------|------------------------------------------------|
//! | 1    | `Wire`                    | a raw uVRR wire message (its own serialization, reused as-is) |
//! | 2    | `TelemetryTimeoutDecision`| JSON: phi estimate, now, previous wait, next wait |
//! | 3    | `TelemetryStateTransition`| JSON: the node's state transition               |
//! | 4    | `TelemetryOutbound`       | JSON: one outbound message the node decided to send |
//!
//! Any other marker byte is rejected on decode — a reader classifies each
//! record and either hands the raw wire bytes back or the decoded telemetry
//! JSON; it never guesses.

/// The header's size: one marker byte plus the eight-byte nanosecond clock.
pub const HEADER_BYTES: usize = 1 + 8;

/// The subsystem a record belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    /// The payload is a raw uVRR wire message in its existing serialization.
    Wire = 1,
    /// The payload is the phi-informed timeout decision's JSON.
    TelemetryTimeoutDecision = 2,
    /// The payload is a state transition's JSON.
    TelemetryStateTransition = 3,
    /// The payload is one outbound message's JSON.
    TelemetryOutbound = 4,
    /// The payload is one sampled heartbeat arrival's JSON: the monitor's
    /// node id, era, leader, address, the learned inter-arrival `dt_ms`,
    /// and the sample's `ts_ms` — the estimate-and-when evidence.
    TelemetryIntervalSample = 5,
}

impl Marker {
    /// The marker's byte, or `None` for anything the table does not name —
    /// the reader's rejection path for unknown subsystems.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Marker::Wire),
            2 => Some(Marker::TelemetryTimeoutDecision),
            3 => Some(Marker::TelemetryStateTransition),
            4 => Some(Marker::TelemetryOutbound),
            5 => Some(Marker::TelemetryIntervalSample),
            _ => None,
        }
    }
}

/// One decoded envelope record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record's subsystem.
    pub marker: Marker,
    /// The writing node's local clock at append, in nanoseconds since the
    /// UNIX epoch.
    pub ns: u64,
    /// The payload: for `Wire`, the raw wire bytes (feed them to the
    /// existing parser); for the telemetry markers, the record's JSON.
    pub payload: Vec<u8>,
}

impl Record {
    /// A Wire record: the payload is the raw uVRR wire message, unchanged.
    pub fn wire(ns: u64, raw_wire: &[u8]) -> Self {
        Record {
            marker: Marker::Wire,
            ns,
            payload: raw_wire.to_vec(),
        }
    }

    /// A telemetry record: the payload is the record's JSON text.
    pub fn telemetry(marker: Marker, ns: u64, json: &[u8]) -> Self {
        debug_assert_ne!(marker, Marker::Wire, "use Record::wire for Wire records");
        Record {
            marker,
            ns,
            payload: json.to_vec(),
        }
    }

    /// The envelope bytes to append: marker byte, big-endian ns clock,
    /// payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES + self.payload.len());
        out.push(self.marker as u8);
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode one envelope record from its bytes. `None` on a truncated
    /// buffer or an unknown marker — the reader never guesses.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_BYTES {
            return None;
        }
        let marker = Marker::from_byte(bytes[0])?;
        let ns = u64::from_be_bytes(bytes[1..9].try_into().expect("8 bytes"));
        Some(Record {
            marker,
            ns,
            payload: bytes[9..].to_vec(),
        })
    }
}

/// The local clock the headers stamp: nanoseconds since the UNIX epoch at
/// the writing node.
pub fn local_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0)
}
