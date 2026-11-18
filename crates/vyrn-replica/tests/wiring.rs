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
    let b = packet(9, 1, &pb, PacketFlags::SHED);
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
        lanes: vec![LaneRec::Pkt(a), LaneRec::Pkt(adv), LaneRec::Pkt(b)],
        split: 2,
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
    assert_eq!(j.check(&blk(root)), Ok(()), "the shed packet is joined too");
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
    // A retry released in a later block frees it at once.
    j.put(SessionId(7), 1, p);
    j.release(Height(200), &[LaneRec::Pkt(shed)]);
    j.release(Height(201), &[LaneRec::Pkt(retry)]);
    assert!(j.resolve(&retry).is_err());
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
