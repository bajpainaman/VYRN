//! What the lane hands to the engine after each call: response packets (01 §6.3, 05 §8.10) and
//! order-stream records (01 §6.6). Both are logical; framing, MAC (`K_out`) and the 07
//! encoding belong to the TX path and `vyrn-log`.

use vyrn_bbo::{MAX_RECORDS, Record};
use vyrn_types::{LaneSeq, PacketRecord, RouteRecord, SessionId, StepId};

/// When a response may leave (`INV-FRAME-FIRST`, `INV-ACK-AFTER-CUT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Out of stream (04 §3.2): not engine output, no frame to wait for.
    None,
    /// After the stream core framed the `PacketRecord` whose `first_lane_seq` this is (immediate
    /// rejects and `BUSY`, 05 §8.10 rule 3).
    Packet(LaneSeq),
    /// After step `f` is framed: the lane read `LaneCut = (f, C_f)`, which the stream core writes
    /// only after the frame (05 §4.15), so the gate is already open (B3 output, rule 4).
    Step(StepId),
}

/// One response packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RespPkt {
    pub session: SessionId,
    /// 0 = out of stream.
    pub resp_seq: u32,
    /// `pkt_seq` answered, 0 for unsolicited records.
    pub echo_pkt: u32,
    pub gate: Gate,
    n: u8,
    recs: [Record; MAX_RECORDS],
}

impl RespPkt {
    pub(crate) fn new(session: SessionId, resp_seq: u32, echo_pkt: u32, gate: Gate) -> Self {
        Self {
            session,
            resp_seq,
            echo_pkt,
            gate,
            n: 0,
            recs: [Record::default(); MAX_RECORDS],
        }
    }
    pub fn records(&self) -> &[Record] {
        self.recs.get(..usize::from(self.n)).unwrap_or(&[])
    }
    pub(crate) fn full(&self) -> bool {
        usize::from(self.n) >= MAX_RECORDS
    }
    pub(crate) fn push(&mut self, r: Record) -> bool {
        match self.recs.get_mut(usize::from(self.n)) {
            Some(x) => {
                *x = r;
                self.n = self.n.saturating_add(1);
                true
            }
            None => false,
        }
    }
}

/// An order-stream record the lane produced (01 §6.6), in production order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogRec {
    Packet(PacketRecord),
    /// The route of an op the lane classified Cross or Improve, forwarded or rejected by the
    /// lane itself (01 §6.6, 07 §3.6).
    Route(RouteRecord),
}

/// Bounded output buffers, preallocated (`INV-NOALLOC`). The engine drains them after each call;
/// a full buffer is a fault (05 §14.3).
pub(crate) struct Outbox {
    pub resp: Vec<RespPkt>,
    pub log: Vec<LogRec>,
    cap: usize,
    pub overflow: bool,
}

impl Outbox {
    pub fn new(cap: usize) -> Self {
        Self {
            resp: Vec::with_capacity(cap),
            log: Vec::with_capacity(cap),
            cap,
            overflow: false,
        }
    }
    pub fn resp(&mut self, p: RespPkt) {
        if self.resp.len() < self.cap {
            self.resp.push(p);
        } else {
            self.overflow = true;
        }
    }
    pub fn log(&mut self, r: LogRec) {
        if self.log.len() < self.cap {
            self.log.push(r);
        } else {
            self.overflow = true;
        }
    }
}
