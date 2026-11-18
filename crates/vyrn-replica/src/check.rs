//! `check_step`: the structural step rules S1–S5 a vote needs (07 §3.12).
//!
//! It is a pure function of the half-record, the half-cut before it and the lane states of its
//! half. Another client can therefore check it against the vectors without any of this crate.

use vyrn_log::stream::{has_payload, has_src};
use vyrn_log::{Layout, StepHalf};
use vyrn_types::{LaneId, LaneSeq, StepKind};

use crate::lane::LaneState;

const NO_SRC: u8 = 0xFF;

/// Why a step half-record fails. [`code`](Self::code) gives its `REP_E_*` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StepErr {
    /// The half-cut or lane states do not match this substream's half.
    #[error("half-record does not match the layout")]
    Layout,
    /// S1: `cut[lane]` moved back (`INV-CUT-MONO`).
    #[error("cut of lane {lane:?} moves back")]
    CutBack { lane: LaneId },
    /// S2: `cut[lane]` is above the lane's decoded prefix.
    #[error("cut {cut:?} of lane {lane:?} is beyond its decoded prefix {prefix:?}")]
    CutBeyondPrefix {
        lane: LaneId,
        cut: LaneSeq,
        prefix: LaneSeq,
    },
    /// S3: a source or payload that the kind does not allow.
    #[error("source or payload not allowed for {kind:?}")]
    KindShape { kind: StepKind },
    /// S4: `src_lane_seq` is not a decoded op of `src_lane`.
    #[error("source {seq:?} of lane {lane:?} is not a decoded op")]
    SrcNotDecoded { lane: LaneId, seq: LaneSeq },
    /// S5: the source op belongs to a packet that carries `SHED`.
    #[error("source {seq:?} of lane {lane:?} is in a shed packet")]
    SrcShed { lane: LaneId, seq: LaneSeq },
}

impl StepErr {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::KindShape { .. } | Self::SrcShed { .. } => "REP_E_KIND",
            _ => "REP_E_CUT",
        }
    }
}

/// Checks one step half-record decoded from substream `stream`.
///
/// `prev_cut` is this half's cut before the record, and `lanes` holds the states of this half's
/// lanes, in lane order, after every lane record that precedes the step on this substream.
pub fn check_step(
    layout: &Layout,
    stream: u8,
    half: &StepHalf,
    prev_cut: &[LaneSeq],
    lanes: &[LaneState],
) -> Result<(), StepErr> {
    let range = layout.half(stream);
    let n = usize::from(range.end.saturating_sub(range.start));
    if half.cut.len() != n || prev_cut.len() != n || lanes.len() != n {
        return Err(StepErr::Layout);
    }
    for ((lane, (c, p)), st) in range.clone().zip(half.cut.iter().zip(prev_cut)).zip(lanes) {
        if c < p {
            return Err(StepErr::CutBack { lane: LaneId(lane) });
        }
        if *c > st.prefix() {
            return Err(StepErr::CutBeyondPrefix {
                lane: LaneId(lane),
                cut: *c,
                prefix: st.prefix(),
            });
        }
    }
    let Some(home) = &half.home else {
        return Ok(());
    };
    let kind = half.kind;
    let sourced = home.src_lane.0 != NO_SRC;
    if sourced != has_src(kind) || (!has_payload(kind) && !home.payload.is_empty()) {
        return Err(StepErr::KindShape { kind });
    }
    if !sourced {
        return if home.src_lane_seq.0 == 0 {
            Ok(())
        } else {
            Err(StepErr::KindShape { kind })
        };
    }
    let lane = home.src_lane;
    let seq = home.src_lane_seq;
    let st = range
        .clone()
        .position(|l| l == lane.0)
        .and_then(|i| lanes.get(i))
        .ok_or(StepErr::KindShape { kind })?;
    if seq.0 == 0 || seq > st.prefix() {
        return Err(StepErr::SrcNotDecoded { lane, seq });
    }
    if st.is_shed(seq) {
        return Err(StepErr::SrcShed { lane, seq });
    }
    Ok(())
}
