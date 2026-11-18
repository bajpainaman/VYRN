//! The logical order-stream records of 01 §6.6. Their wire encoding (LEB128 deltas) is 07's and
//! lives in `vyrn-log`.

use crate::{
    AccountId, BookId, Epoch, Hash, Height, HomeCode, LaneId, LaneSeq, Nanos, PktHash, SessionId,
    StepId, StepKind,
};

/// An Ed25519 signature.
pub type Ed25519Sig = [u8; 64];
/// An Ed25519 public key.
pub type PubKey = [u8; 32];

/// `PacketRecord.flags` bits (01 §6.6; `MID` and `PASS2` are 05 §17 R11).
pub struct PacketFlags;

impl PacketFlags {
    pub const SHED: u8 = 1 << 0;
    pub const ADVANCE: u8 = 1 << 1;
    pub const MID: u8 = 1 << 2;
    pub const PASS2: u8 = 1 << 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketRecord {
    pub lane: LaneId,
    /// 0 for an advance record.
    pub count: u8,
    pub flags: u8,
    pub session: SessionId,
    pub pkt_seq: u32,
    pub rx_ts: Nanos,
    pub pkt_hash: PktHash,
    pub first_lane_seq: LaneSeq,
    /// The last step whose fill events this lane applied before it processed this packet.
    pub fills_applied: StepId,
}

/// `StepRecord.flags` bits (01 §6.6). They use `StepEntry.flags`' numbering (05 §4.15).
pub struct StepFlags;

impl StepFlags {
    /// The source's lane classified it `Cross` (05 §6.5); clear = `Improve`. Only on a step
    /// with a source (`Cross`, `Improve`, `Shed`). Replay charges risk by this route, not by
    /// the kind (05 §10, 10 M8).
    pub const CROSS: u8 = 1 << 1;
}

/// The route a lane classified a `New` or new-priority `Replace` with (05 §6.5), logged for
/// every such op, forwarded or rejected by the lane itself (01 §6.6, 07 §3.6). Replay forces
/// that route, so risk charges and rejects as live did (10 M8); a forwarded op's step also
/// carries it as `StepFlags::CROSS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRecord {
    pub lane: LaneId,
    pub lane_seq: LaneSeq,
    /// `true` = `Cross`, `false` = `Improve`.
    pub cross: bool,
}

/// One BBO-core step and the cut it used. `N` is the box's lane count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepRecord<const N: usize> {
    pub step: StepId,
    pub kind: StepKind,
    pub src_lane: LaneId,
    /// 0 means "no source" (05 §8.1).
    pub src_lane_seq: LaneSeq,
    /// [`StepFlags`]; 0 without a source.
    pub flags: u8,
    pub cut: [LaneSeq; N],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub height: Height,
    pub epoch: Epoch,
    pub book: BookId,
    pub first_step: StepId,
    pub last_step: StepId,
    pub prev: Hash,
    pub order_root: Hash,
    pub data_root: Hash,
    pub seq_sig: Ed25519Sig,
}

/// Pooled lanes only: one per account-token take (01 §14.17.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcctTake {
    pub lane: LaneId,
    pub account: AccountId,
    pub ver: u32,
    pub lane_seq: LaneSeq,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandoffRecord {
    pub book: BookId,
    pub epoch: Epoch,
    pub last_step: StepId,
    pub last_height: Height,
    pub state_root: Hash,
    pub log_hash: Hash,
    pub next_home: HomeCode,
    pub next_seq_key: PubKey,
}
