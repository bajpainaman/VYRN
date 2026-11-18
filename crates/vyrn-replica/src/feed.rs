//! The data RX path (07 §5.3, §5.4, §5.7 step 1; 03 F7): `vyrn-data` frames into [`DataJoin`].
//!
//! **Writer.** The data RX core calls [`DataFeed::on_frame`] with the UDP payload of each frame
//! it receives from a data box (`DATA`, `DATA_HB` or `FETCH_RESP`, `vyrn_data::frame`). Nothing
//! else writes the feed; the join it fills is the one the vote and replay read.
//!
//! **Per packet.** A packet is stored by its own header's `(session, pkt_seq)` once it parses
//! (01 §6.1 V1 and the header half of V9, `vyrn_wire::Request`) and names the served book. The
//! join hashes it itself (07 §5.4: a replica never trusts a data box's hash), and a record joins
//! it only by its `pkt_hash`, so a wrong packet from a data box can delay a block but never enter
//! it. The replica holds no `K_seq` and checks no tag.
//!
//! **Per data box** (indexed by the frame's `src`). `DATA` frames to one destination carry
//! `data_seq` 1, 2, … with no gap, and a `DATA_HB` carries the last `DATA` sent (`vyrn-data` crate
//! docs). The feed keeps the highest `data_seq` seen and returns a missing run as
//! [`Fed::gap`]: the box's `src` and the `DataFetch{from, to}` (a RANGE fetch) to send it, whose
//! `dst` is this replica's index in the box's destination list, given at [`DataFeed::new`]. A `DATA` frame at
//! or below the highest is a resend that a RANGE fetch asked for: its packets are stored and the
//! position stays. `FETCH_RESP` frames carry no stream position. [`DataFeed::silent`] lists the
//! boxes heard from once and silent for `REP_DATA_SILENCE_MS` (07 §5.3), for `DataDown{d}`.
//!
//! **Rejects** ([`FeedErr`]): a frame that `vyrn_data::frame::decode` refuses, and a `src` beyond
//! the configured boxes. A rejected frame changes nothing. A data box sends every book it serves
//! on one `data_seq` per destination, so a frame of another book still moves the box's position
//! and liveness; its packets, like any that do not parse or name another book, are dropped and
//! counted in [`Fed::dropped`].

use vyrn_data::frame::{Fetch, FrameErr, Kind, decode};
use vyrn_types::BookId;
use vyrn_wire::Request;

use crate::data::DataJoin;

/// `REP_DATA_SILENCE_MS` = 1 ms (07 §5.3), in nanoseconds.
pub const REP_DATA_SILENCE_NS: u64 = 1_000_000;

/// Why a frame was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FeedErr {
    #[error("data frame: {0}")]
    Frame(FrameErr),
    #[error("data box {0} is not configured")]
    Src(u8),
}

/// What one frame did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fed {
    /// Packets put into the join (a byte-identical repeat counts, and is stored once).
    pub stored: u32,
    /// Packets that did not parse or named another book.
    pub dropped: u32,
    /// `(src, fetch)`: `DATA` frames of data box `src` were never received; `fetch` is the
    /// `Fetch::Range` that asks it for them.
    pub gap: Option<(u8, Fetch)>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Source {
    /// The highest `data_seq` this box has announced, by `DATA` or `DATA_HB`.
    high: u64,
    /// The receive time of its last frame; `None` before the first.
    heard: Option<u64>,
}

/// Data frames from `n` data boxes into one [`DataJoin`].
#[derive(Clone, Debug)]
pub struct DataFeed {
    book: BookId,
    /// This replica's index in every data box's destination list (the RANGE fetch's `dst`).
    me: u8,
    sources: Vec<Source>,
}

impl DataFeed {
    /// A feed for `book` from data boxes `0..n_boxes` (the frames' `src`), for the replica at
    /// index `me` of their destination lists.
    pub fn new(book: BookId, n_boxes: u8, me: u8) -> Self {
        Self {
            book,
            me,
            sources: vec![Source::default(); usize::from(n_boxes)],
        }
    }

    /// Takes one frame's UDP payload, received at `now` (the replica's monotonic clock, ns).
    pub fn on_frame(
        &mut self,
        join: &mut DataJoin,
        payload: &[u8],
        now: u64,
    ) -> Result<Fed, FeedErr> {
        let f = decode(payload).map_err(FeedErr::Frame)?;
        let src = f.hdr.src;
        let (book, me) = (self.book, self.me);
        let s = self
            .sources
            .get_mut(usize::from(src))
            .ok_or(FeedErr::Src(src))?;
        let mut fed = Fed::default();
        let announced = match f.hdr.kind {
            Kind::Data | Kind::DataHb => Some(f.hdr.data_seq),
            Kind::FetchResp => None,
        };
        if let Some(seq) = announced {
            // DATA n reveals a gap above `high` up to n − 1; DATA_HB n up to n itself.
            let last_missing = match f.hdr.kind {
                Kind::Data => seq.saturating_sub(1),
                _ => seq,
            };
            if last_missing > s.high {
                let (from, to) = (s.high.saturating_add(1), last_missing);
                fed.gap = Some((src, Fetch::Range { dst: me, from, to }));
            }
            s.high = s.high.max(seq);
        }
        s.heard = Some(now);
        for p in f.packets() {
            let key = Request::parse(p).ok().and_then(|r| {
                let h = r.header();
                let ok = r.check_header().is_ok() && h.book() == book && h.pkt_seq.get() != 0;
                ok.then(|| (h.session(), h.pkt_seq.get()))
            });
            match key {
                Some((session, pkt_seq)) => {
                    join.put(session, pkt_seq, p.to_vec());
                    fed.stored = fed.stored.saturating_add(1);
                }
                None => fed.dropped = fed.dropped.saturating_add(1),
            }
        }
        Ok(fed)
    }

    /// The data boxes heard from at least once and silent for [`REP_DATA_SILENCE_NS`] at `now`
    /// (07 §5.7 step 1: each is a `DataDown{d}` to gossip).
    pub fn silent(&self, now: u64) -> impl Iterator<Item = u8> + '_ {
        self.sources.iter().zip(0u8..).filter_map(move |(s, i)| {
            s.heard
                .filter(|&t| now.saturating_sub(t) >= REP_DATA_SILENCE_NS)
                .map(|_| i)
        })
    }
}
