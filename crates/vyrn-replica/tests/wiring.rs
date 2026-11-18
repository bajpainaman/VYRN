//! The replica's wiring to vyrn-epoch and the data tier: `ActiveEpoch` as an `EpochView`, the
//! `EpochJournal` across restarts, and the data join's vote-rule item 3.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use vyrn_consensus::{Committee, Genesis};
use vyrn_epoch::{Activation, Fence, Signed};
use vyrn_log::LaneRec;
use vyrn_log::block::data_root;
use vyrn_replica::{
    ActiveEpoch, BlockInputs, DataErr, DataJoin, EpochJournal, EpochView, JournalErr, full_hash,
};
use vyrn_types::{
    BlockHeader, BookId, Epoch, HandoffRecord, Hash, Height, HomeCode, LaneId, LaneSeq, Mode,
    Nanos, PacketFlags, PacketRecord, PktHash, SessionId, StepId,
};

fn key(b: u8) -> [u8; 32] {
    vyrn_crypto::ed25519::public_key(&[b; 32])
}

fn record(epoch: u32, last_height: u64) -> HandoffRecord {
    HandoffRecord {
        book: BookId(1),
        epoch: Epoch(epoch),
        last_step: StepId(100),
        last_height: Height(last_height),
        state_root: Hash([1; 32]),
        log_hash: Hash([2; 32]),
        next_home: HomeCode::Ldn,
        next_seq_key: key(9),
    }
}

fn activation() -> Activation {
    let voters = (1..=Mode::Base.n()).map(|i| key(i as u8)).collect();
    Activation {
        epoch: Epoch(2),
        home: HomeCode::Ldn,
        committee: Committee::new(Mode::Base, voters, &[key(9), key(10)]).unwrap(),
        seq_key: key(9),
        standby_key: key(10),
        fence: Fence::from_record(&record(1, 50)),
        genesis: Genesis {
            height: Height(50),
            hash: Hash([2; 32]),
            last_step: StepId(0),
        },
    }
}

#[test]
fn active_epoch_is_the_epoch_view() {
    let mut e = ActiveEpoch::new(activation(), BookId(1));
    assert_eq!(e.epoch(), Epoch(2));
    assert_eq!(e.seq_key(0), Some(key(9)));
    assert_eq!(e.seq_key(1), Some(key(10)));
    assert_eq!(e.seq_key(2), None, "a spare has no key in the activation");
    // The activation's fence is epoch 1's: it fences nothing of epoch 2.
    assert!(!e.fenced(Height(10_000)));
    assert!(
        !e.set_fence(Fence::from_record(&record(1, 50))),
        "another epoch's fence"
    );
    assert!(e.set_fence(Fence::from_record(&record(2, 80))));
    assert!(!e.fenced(Height(80)));
    assert!(e.fenced(Height(81)));
    let cfg = e.voter_config([1; 32], (), vyrn_consensus::voter::Timeouts::SPEC);
    assert_eq!(
        (cfg.epoch, cfg.seq_key, cfg.genesis.height),
        (Epoch(2), key(9), Height(50))
    );
}

#[test]
fn journal_survives_restart_and_drops_a_torn_tail() {
    let dir = std::env::temp_dir().join(format!("vyrn-replica-journal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("epoch.journal");
    let _ = std::fs::remove_file(&path);
    let r = record(2, 80);
    {
        let mut j = EpochJournal::open(&path).unwrap();
        assert!(
            matches!(EpochJournal::open(&path), Err(JournalErr::Locked)),
            "a second guard over one journal"
        );
        assert_eq!(j.admit(&r).unwrap(), Signed::Fresh);
        assert_eq!(j.admit(&r).unwrap(), Signed::Repeat);
        j.arm(Epoch(3)).unwrap();
    }
    // A crash in the middle of a write leaves a line with no newline.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut f, b"armed 4").unwrap();
    drop(f);
    let mut j = EpochJournal::open(&path).unwrap();
    assert!(j.is_armed(Epoch(3)));
    assert!(!j.is_armed(Epoch(4)), "a torn line was never durable");
    assert_eq!(
        j.admit(&r).unwrap(),
        Signed::Repeat,
        "the admission survived"
    );
    let other = HandoffRecord {
        last_height: Height(81),
        ..r
    };
    assert!(
        matches!(j.admit(&other), Err(JournalErr::Handoff(_))),
        "one record per epoch"
    );
    j.arm(Epoch(4)).unwrap();
    drop(j);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.ends_with("armed 3\narmed 4\n"), "{text:?}");
    std::fs::write(&path, "armed x\n").unwrap();
    assert!(matches!(
        EpochJournal::open(&path),
        Err(JournalErr::Line(1))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

fn packet(session: u32, pkt_seq: u32, bytes: &[u8], flags: u8) -> PacketRecord {
    let h = full_hash(bytes);
    PacketRecord {
        lane: LaneId(0),
        count: 1,
        flags,
        session: SessionId(session),
        pkt_seq,
        rx_ts: Nanos(1),
        pkt_hash: PktHash(u64::from_le_bytes(h.0[..8].try_into().unwrap())),
        first_lane_seq: LaneSeq(1),
        fills_applied: StepId(0),
    }
}

/// A 1-message request packet (16-byte header with count 1 at byte 8, one message) plus tags.
fn bytes(tag: u8) -> Vec<u8> {
    let mut b = vec![tag; 48];
    b[8] = 1;
    b
}

#[test]
fn data_join_checks_data_root_per_half() {
    let (pa, pb) = (bytes(0xA0), bytes(0xB0));
    let a = packet(7, 1, &pa, 0);
    let b = packet(9, 1, &pb, 0);
    // A SHED record (05 §18 Q17): never joined and outside data_root, so its payload is
    // never put and the block still checks.
    let shed = packet(11, 4, &bytes(0xC0), PacketFlags::SHED);
    let adv = PacketRecord {
        flags: PacketFlags::ADVANCE,
        count: 0,
        ..a
    };
    let root = data_root(&[full_hash(&pa)], &[full_hash(&pb)]);
    let blk = |root| BlockInputs::<4> {
        header: BlockHeader {
            height: Height(0),
            epoch: Epoch(1),
            book: BookId(1),
            first_step: StepId(1),
            last_step: StepId(0),
            prev: Hash([0; 32]),
            order_root: Hash([0; 32]),
            data_root: root,
            seq_sig: [0; 64],
        },
        lanes: vec![
            LaneRec::Pkt(a),
            LaneRec::Pkt(adv),
            LaneRec::Pkt(shed),
            LaneRec::Pkt(b),
        ],
        split: 3,
        steps: Vec::new(),
    };
    let mut j = DataJoin::default();
    j.put(SessionId(7), 1, pa.clone());
    assert_eq!(
        j.check(&blk(root)),
        Err(DataErr::Missing {
            session: SessionId(9),
            pkt_seq: 1
        })
    );
    // A resend whose tag bytes differ: same signed bytes, same hash, stored once.
    let mut resend = pb.clone();
    resend[40] ^= 0xFF;
    j.put(SessionId(9), 1, resend);
    assert_eq!(
        j.check(&blk(root)),
        Ok(()),
        "the SHED record needs no payload"
    );
    // A root that wrongly covers the SHED record's hash does not check.
    assert_eq!(
        j.check(&blk(data_root(
            &[full_hash(&pa), full_hash(&bytes(0xC0))],
            &[full_hash(&pb)]
        ))),
        Err(DataErr::Root)
    );
    // The halves are hashed apart: the same hashes all in A give another root.
    assert_eq!(
        j.check(&blk(data_root(&[full_hash(&pa), full_hash(&pb)], &[]))),
        Err(DataErr::Root)
    );
    assert_eq!(vyrn_engine::Payloads::get(&j, &a), Some(pa.as_slice()));
    // A record whose count disagrees with its payload's numbered messages (07 §5.4).
    let mut bad = a;
    bad.count = 2;
    assert_eq!(
        j.resolve(&bad).map(|(_, h)| h),
        Err(DataErr::Count {
            session: SessionId(7),
            pkt_seq: 1
        })
    );
    assert_eq!(vyrn_engine::Payloads::get(&j, &bad), None);
}

#[test]
fn release_keeps_what_a_shed_retry_still_needs() {
    use vyrn_replica::data::REP_SHED_KEEP_BLOCKS;
    let p = bytes(0xC0);
    let shed = packet(7, 1, &p, PacketFlags::SHED);
    // The retry has the same signed bytes, so the same hash and variant.
    let retry = packet(7, 1, &p, 0);
    let other = bytes(0xD0);
    let variant = packet(7, 1, &other, 0);
    let mut j = DataJoin::default();
    j.put(SessionId(7), 1, p.clone());
    j.put(SessionId(7), 1, other.clone());
    j.release(Height(10), &[LaneRec::Pkt(shed)]);
    assert!(
        j.resolve(&retry).is_ok(),
        "the shed block's release keeps the retry's payload"
    );
    j.release(Height(11), &[LaneRec::Pkt(variant)]);
    assert!(
        j.resolve(&retry).is_ok(),
        "releasing one variant keeps the others"
    );
    assert!(j.resolve(&variant).is_err());
    // A retry that never comes: the payload goes REP_SHED_KEEP_BLOCKS after the shed block.
    j.release(Height(10 + REP_SHED_KEEP_BLOCKS - 1), &[]);
    assert!(j.resolve(&retry).is_ok());
    j.release(Height(10 + REP_SHED_KEEP_BLOCKS), &[]);
    assert!(j.resolve(&retry).is_err());
    // A retry shed again: the first shed entry's expiry keeps the payload for the second's window.
    j.put(SessionId(7), 1, p.clone());
    j.release(Height(300), &[LaneRec::Pkt(shed)]);
    j.release(Height(350), &[LaneRec::Pkt(shed)]);
    j.release(Height(300 + REP_SHED_KEEP_BLOCKS), &[]);
    assert!(
        j.resolve(&retry).is_ok(),
        "the second shed record's window is still open"
    );
    j.release(Height(350 + REP_SHED_KEEP_BLOCKS), &[]);
    assert!(j.resolve(&retry).is_err());
    // An accepted packet's unused resend variant expires instead of staying forever.
    let mut j2 = DataJoin::default();
    j2.put(SessionId(8), 1, p.clone());
    j2.put(SessionId(8), 1, other.clone());
    let accepted = packet(8, 1, &p, 0);
    let unused = packet(8, 1, &other, 0);
    j2.release(Height(600), &[LaneRec::Pkt(accepted)]);
    assert!(j2.resolve(&accepted).is_err());
    assert!(j2.resolve(&unused).is_ok(), "kept for the window");
    j2.release(Height(600 + REP_SHED_KEEP_BLOCKS), &[]);
    assert!(
        j2.resolve(&unused).is_err(),
        "no record ever releases it, so it expires"
    );
    // A retry released in a later block frees it at once.
    j.put(SessionId(7), 1, p);
    j.release(Height(500), &[LaneRec::Pkt(shed)]);
    j.release(Height(501), &[LaneRec::Pkt(retry)]);
    assert!(j.resolve(&retry).is_err());
}

/// A ready block naming `recs`, for the retention test.
fn block_of(recs: &[PacketRecord]) -> BlockInputs<4> {
    BlockInputs {
        header: BlockHeader {
            height: Height(0),
            epoch: Epoch(1),
            book: BookId(1),
            first_step: StepId(1),
            last_step: StepId(0),
            prev: Hash([0; 32]),
            order_root: Hash([0; 32]),
            data_root: Hash([0; 32]),
            seq_sig: [0; 64],
        },
        lanes: recs.iter().map(|r| LaneRec::Pkt(*r)).collect(),
        split: recs.len(),
        steps: Vec::new(),
    }
}

#[test]
fn unreferenced_payloads_expire_after_finality_and_are_capped() {
    use vyrn_replica::Evictions;
    use vyrn_replica::data::REP_SHED_KEEP_BLOCKS as K;
    let (pa, pb, pc) = (bytes(0xA1), bytes(0xB1), bytes(0xC1));
    let (a, b, c) = (
        packet(1, 1, &pa, 0),
        packet(2, 1, &pb, 0),
        packet(3, 1, &pc, 0),
    );
    let mut j = DataJoin::default();
    // `a` arrives while height 50 is final; nothing names it.
    j.finalized(Height(50));
    j.put(SessionId(1), 1, pa.clone());
    // `b` is named by a ready block before its payload arrives; `c` after.
    j.reference(&block_of(&[b]));
    j.put(SessionId(2), 1, pb.clone());
    j.put(SessionId(3), 1, pc.clone());
    j.reference(&block_of(&[c]));
    // K blocks after the arrival's final height, not after height 0.
    j.finalized(Height(50 + K - 1));
    assert!(j.resolve(&a).is_ok(), "one block short of K final blocks");
    j.finalized(Height(50 + K));
    assert!(j.resolve(&a).is_err(), "K final blocks after it arrived");
    // Referenced payloads stay, however many blocks are final.
    j.finalized(Height(10_000));
    assert!(j.resolve(&b).is_ok() && j.resolve(&c).is_ok());
    assert_eq!(
        j.evictions(),
        Evictions {
            expired: 1,
            capped: 0
        }
    );

    // The cap counts only unreferenced payloads and drops the oldest first.
    let mut j = DataJoin::with_cap(2);
    j.reference(&block_of(&[c]));
    j.put(SessionId(3), 1, pc.clone());
    j.put(SessionId(1), 1, pa.clone());
    j.put(SessionId(2), 1, pb.clone());
    assert!(j.resolve(&a).is_ok() && j.resolve(&b).is_ok() && j.resolve(&c).is_ok());
    let pd = bytes(0xD1);
    let d = packet(4, 1, &pd, 0);
    j.put(SessionId(4), 1, pd);
    assert!(
        j.resolve(&a).is_err(),
        "the oldest unreferenced payload goes"
    );
    assert!(j.resolve(&b).is_ok() && j.resolve(&d).is_ok() && j.resolve(&c).is_ok());
    assert_eq!(
        j.evictions(),
        Evictions {
            expired: 0,
            capped: 1
        }
    );
    // A key named after its payload arrived leaves the unreferenced set: it no longer counts.
    j.reference(&block_of(&[b]));
    j.put(SessionId(1), 1, pa);
    assert!(j.resolve(&a).is_ok() && j.resolve(&b).is_ok() && j.resolve(&d).is_ok());
    assert_eq!(j.evictions().capped, 1);

    // A SHED record and its retry share a key: releasing the SHED block keeps the retry's
    // reference, so the retry's payload arriving afterwards is not capped.
    let p = bytes(0xE1);
    let shed = packet(5, 1, &p, PacketFlags::SHED);
    let retry = packet(5, 1, &p, 0);
    let mut j = DataJoin::with_cap(1);
    j.reference(&block_of(&[shed]));
    j.reference(&block_of(&[retry]));
    j.release(Height(1), &[LaneRec::Pkt(shed)]);
    j.put(SessionId(5), 1, p.clone());
    j.put(SessionId(6), 1, bytes(0xF1));
    j.put(SessionId(6), 2, bytes(0xF2));
    assert!(
        j.resolve(&retry).is_ok(),
        "still referenced by the retry's block"
    );

    // Released without `reference`: the released key leaves the unreferenced set, so it neither
    // counts toward the cap nor is evicted by it inside its SHED window.
    let mut j = DataJoin::with_cap(1);
    j.put(SessionId(5), 1, p.clone());
    j.release(Height(1), &[LaneRec::Pkt(shed)]);
    j.put(SessionId(6), 1, bytes(0xF1));
    assert!(j.resolve(&retry).is_ok(), "the SHED window keeps it");
    assert_eq!(j.evictions().capped, 0);
}

#[test]
fn count_follows_the_lane_numbering() {
    // Two messages: a New (0x01) and a Heartbeat (0x10).
    let mut p = vec![0u8; 16 + 32 + 16];
    p[8] = 2;
    p[16] = 0x01;
    p[32] = 0x10;
    assert!(
        vyrn_replica::data::count_fits(1, &p),
        "the heartbeat takes no LaneSeq"
    );
    assert!(
        vyrn_replica::data::count_fits(2, &p),
        "a header reject numbers every message"
    );
    assert!(!vyrn_replica::data::count_fits(0, &p));
    // A third message with the Heartbeat type byte that does not decode as one: the lane rejects
    // it, so it takes a LaneSeq (two numbered messages, or three under a packet-level reject).
    let mut q = vec![0u8; 16 + 48 + 16];
    q[8] = 3;
    q[16] = 0x01;
    q[32] = 0x10;
    q[48] = 0x10;
    q[63] = 1;
    assert!(vyrn_wire::Msg::decode(q[48..64].try_into().unwrap()).is_err());
    assert!(vyrn_replica::data::count_fits(2, &q));
    assert!(vyrn_replica::data::count_fits(3, &q));
    assert!(
        !vyrn_replica::data::count_fits(1, &q),
        "the malformed one is numbered"
    );
}

#[test]
fn a_running_order_core_takes_its_epoch_fence() {
    let layout = vyrn_log::Layout::new(4, 2, 0).unwrap();
    let mut core =
        vyrn_replica::OrderCore::<4, _>::new(layout, ActiveEpoch::new(activation(), BookId(1)))
            .unwrap();
    assert_eq!(
        core.verdict(Height(81), Height(81)),
        vyrn_consensus::Verdict::Pending
    );
    assert!(
        core.view_mut()
            .set_fence(Fence::from_record(&record(2, 80)))
    );
    assert_eq!(
        core.verdict(Height(81), Height(81)),
        vyrn_consensus::Verdict::Invalid
    );
}

/// The data feed's rejects and stream position: a heartbeat reveals a lost tail frame, a frame of
/// another book moves the box's position (one `data_seq` per destination over every book) but
/// stores nothing, a frame from an unconfigured box is refused, and a bad packet inside a good
/// frame is dropped alone.
#[test]
fn data_feed_tracks_each_box_and_refuses_what_is_not_its_own() {
    use vyrn_data::frame::{DataHdr, Fetch, FrameBuf, Kind};
    use vyrn_replica::{DataFeed, Fed, FeedErr};
    let k = [7u8; 16];
    let req = |session: u32, pkt_seq: u32, book: u16| {
        let mut out = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
        let h = vyrn_wire::ReqHeader::new(SessionId(session), pkt_seq, 0, BookId(book), false);
        let n =
            vyrn_wire::encode_request(&mut out, h, &[vyrn_wire::Msg::Heartbeat], &k, None).unwrap();
        out[..n].to_vec()
    };
    let frame = |kind, book, data_seq, src, pkts: &[&[u8]]| {
        let mut b = FrameBuf::default();
        for p in pkts {
            assert!(b.push(p));
        }
        b.finish(&DataHdr {
            kind,
            book: BookId(book),
            epoch16: 0,
            data_seq,
            src,
        })
        .to_vec()
    };
    let (good, other_book, seq0) = (req(5, 1, 1), req(5, 2, 2), req(5, 0, 1));
    let mut feed = DataFeed::new(BookId(1), 2, 3);
    let range = |from, to| {
        Some(vyrn_replica::Gap {
            src: 1,
            dst: 3,
            from,
            to,
        })
    };
    let mut j = DataJoin::default();
    let f = frame(Kind::Data, 1, 1, 1, &[&good, &other_book, &seq0, b"short"]);
    assert_eq!(
        feed.on_frame(&mut j, &f, 10),
        Ok(Fed {
            stored: 1,
            dropped: 3,
            gap: None
        })
    );
    // Box 0 was never heard from; box 1 is silent from 10 + 1 ms.
    assert_eq!(feed.silent(10 + 999_999).count(), 0);
    assert_eq!(feed.silent(10 + 1_000_000).collect::<Vec<_>>(), vec![1]);
    // A heartbeat naming DATA 3 after DATA 1: frames 2 and 3 were lost.
    let hb = frame(Kind::DataHb, 0, 3, 1, &[]);
    assert_eq!(feed.on_frame(&mut j, &hb, 20).unwrap().gap, range(2, 3));
    assert_eq!(
        feed.on_frame(&mut j, &hb, 30).unwrap().gap,
        None,
        "reported once"
    );
    assert_eq!(
        feed.on_frame(&mut j, &frame(Kind::Data, 2, 4, 1, &[&other_book]), 40),
        Ok(Fed {
            stored: 0,
            dropped: 1,
            gap: None
        })
    );
    let f5 = frame(Kind::Data, 1, 5, 1, &[&good]);
    assert_eq!(
        feed.on_frame(&mut j, &f5, 50).unwrap().gap,
        None,
        "book 2's DATA 4 is no gap"
    );
    assert_eq!(
        feed.silent(40 + 999_999).count(),
        0,
        "book 2 keeps the box alive"
    );
    assert_eq!(
        feed.on_frame(&mut j, &frame(Kind::Data, 1, 1, 2, &[&good]), 40),
        Err(FeedErr::Src(2))
    );
    assert!(matches!(
        feed.on_frame(&mut j, b"PD", 40),
        Err(FeedErr::Frame(_))
    ));
    // A FETCH_RESP needs no configured src: the sequencer answers SeqDataReq as 0xFF.
    let seq_answer = frame(Kind::FetchResp, 1, (5 << 32) | 3, 0xFF, &[&req(5, 3, 1)]);
    assert_eq!(feed.on_frame(&mut j, &seq_answer, 40).unwrap().stored, 1);
    assert_eq!(
        feed.on_frame(&mut j, &frame(Kind::DataHb, 0, 9, 0xFF, &[]), 40),
        Err(FeedErr::Src(0xFF)),
        "a stream frame still does"
    );
    let f7 = frame(Kind::Data, 1, 7, 1, &[&good]);
    assert_eq!(feed.on_frame(&mut j, &f7, 60).unwrap().gap, range(6, 6));
    // A gap longer than a box's max_range splits into fetches it accepts, oldest first.
    let g = range(6, 6 + 600).unwrap();
    let qs: Vec<Fetch> = g.fetches(256).collect();
    let r3 = |from, to| Fetch::Range { dst: 3, from, to };
    assert_eq!(qs, vec![r3(6, 261), r3(262, 517), r3(518, 606)]);
    assert_eq!(g.fetches(0).count(), 601, "max_range 0 is taken as 1");
    let top = vyrn_replica::Gap {
        from: u64::MAX - 1,
        to: u64::MAX,
        ..g
    };
    assert_eq!(
        top.fetches(1).collect::<Vec<_>>(),
        vec![r3(u64::MAX - 1, u64::MAX - 1), r3(u64::MAX, u64::MAX)]
    );
    let r = packet(5, 1, &good, 0);
    assert_eq!(j.resolve(&r).map(|x| x.0), Ok(good.as_slice()));
}
