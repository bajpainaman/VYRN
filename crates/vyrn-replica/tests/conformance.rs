//! Conformance vectors for the replica's order core (07 §3.7, §3.10, §3.12).
//!
//! `tests/golden/vyrn_replica_vectors.txt` at the repository root is the contract: frame bytes
//! in delivery order and the verdict a conforming replica must reach. [`vectors_hold`] runs the
//! file through [`OrderCore`]. [`vectors_are_current`] rebuilds the file with `vyrn-log`'s
//! encoder, so a change to either side shows up as a diff. Run with `VYRN_BLESS=1` to rewrite it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::fmt::Write as _;

use vyrn_consensus::Verdict;
use vyrn_log::block::sign_header;
use vyrn_log::{
    BlockAssembler, BlockMark, Body, Home, Ident, LaneBase, LaneRec, Layout, Section, SessionBind,
    StepHalf, StreamEncoder, TenureStart,
};
use vyrn_replica::{EpochView, OrderCore};
use vyrn_types::{
    BookId, Epoch, Hash, Height, LaneId, LaneSeq, Nanos, PacketFlags, PacketRecord, PktHash,
    PubKey, SessionId, StepId, StepKind,
};

const N: usize = 4;
const SEED: [u8; 32] = [0x40; 32];
const OTHER_SEED: [u8; 32] = [0x41; 32];
const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/vyrn_replica_vectors.txt"
);

fn layout() -> Layout {
    Layout::new(4, 2, 0).unwrap()
}

#[derive(Clone)]
struct View(PubKey);

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        Epoch(1)
    }
    fn book(&self) -> BookId {
        BookId(1)
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        (sender == 0).then_some(self.0)
    }
    fn fenced(&self, _: Height) -> bool {
        false
    }
}

// ---- Building vectors with vyrn-log's encoder ----

fn ident() -> Ident {
    Ident {
        book: BookId(1),
        epoch: Epoch(1),
        tenure: 0,
        sender: 0,
    }
}

fn tenure_start() -> TenureStart {
    TenureStart {
        epoch: Epoch(1),
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: Height(0),
        prev_header_hash: Hash([0; 32]),
        lanes: vec![
            LaneBase {
                next_lane_seq: LaneSeq(1),
                rx_ts: Nanos(1000),
                fills_applied: StepId(0),
            };
            2
        ],
        prev_cut: vec![LaneSeq(0); 2],
    }
}

fn bind(lane: u8, session: u32) -> Section {
    Section::SessionBind(SessionBind {
        lane: LaneId(lane),
        slot: 0,
        session: SessionId(session),
        next_pkt_seq: 1,
    })
}

fn pkt(lane: u8, session: u32, count: u8, flags: u8) -> Section {
    Section::LaneRun {
        lane: LaneId(lane),
        recs: vec![LaneRec::Pkt(PacketRecord {
            lane: LaneId(lane),
            count,
            flags,
            session: SessionId(session),
            pkt_seq: 1,
            rx_ts: Nanos(1100),
            pkt_hash: PktHash(0),
            first_lane_seq: LaneSeq(1),
            fills_applied: StepId(0),
        })],
    }
}

fn step(n: u64, kind: StepKind, src: Option<(u8, u64)>, other: bool, cut: [u64; 2]) -> StepHalf {
    StepHalf {
        step: StepId(n),
        kind,
        other,
        home: Some(Home {
            src_lane: LaneId(src.map_or(0xFF, |s| s.0)),
            src_lane_seq: LaneSeq(src.map_or(0, |s| s.1)),
            flags: 0,
            payload: Vec::new(),
        }),
        cut: cut.map(LaneSeq).to_vec(),
    }
}

fn cut_only(n: u64, kind: StepKind, cut: [u64; 2]) -> StepHalf {
    StepHalf {
        step: StepId(n),
        kind,
        other: true,
        home: None,
        cut: cut.map(LaneSeq).to_vec(),
    }
}

fn order(first: bool, sections: Vec<Section>) -> Body {
    Body::Order {
        tenure_start: first.then(tenure_start),
        sections,
    }
}

fn mark(last_step: u64, bounds: [u64; 2]) -> Section {
    Section::BlockMark(BlockMark {
        height: Height(0),
        last_step: StepId(last_step),
        lane_bounds: bounds.map(LaneSeq).to_vec(),
    })
}

fn hash_run(lane: u8, h: u64) -> Body {
    Body::Hash(vec![Section::HashRun {
        lane: LaneId(lane),
        entries: vec![(LaneSeq(1), PktHash(h))],
    }])
}

enum Ev {
    Frame(u64, Vec<u8>),
    Tick(u64),
}

struct Vector {
    name: &'static str,
    about: &'static str,
    events: Vec<Ev>,
    expect: Vec<String>,
}

struct Two {
    a: StreamEncoder,
    b: StreamEncoder,
}

impl Two {
    fn new() -> Self {
        Self {
            a: StreamEncoder::new(layout(), 0, ident()).unwrap(),
            b: StreamEncoder::new(layout(), 1, ident()).unwrap(),
        }
    }
    fn a(&mut self, body: &Body) -> Vec<u8> {
        self.a.encode(body).unwrap()
    }
    fn b(&mut self, body: &Body) -> Vec<u8> {
        self.b.encode(body).unwrap()
    }
    /// The signed header of block 0, after both marks; `tamper` edits it before signing.
    fn header(
        &mut self,
        seed: &[u8; 32],
        tamper: impl Fn(&mut vyrn_types::BlockHeader),
    ) -> Vec<u8> {
        let a = self.a.take_closed().pop().unwrap();
        let b = self.b.take_closed().pop().unwrap();
        let full_a = vec![Hash([0xAA; 32]); a.packets.len()];
        let full_b = vec![Hash([0xBB; 32]); b.packets.len()];
        let mut h = BlockAssembler::from_tenure(BookId(1), &tenure_start())
            .assemble(&a, Some(&b), &full_a, &full_b)
            .unwrap();
        tamper(&mut h);
        let h = sign_header(&h, seed);
        self.a(&Body::Header(h))
    }
}

/// Block 0: lane 0 has a 3-message packet, lane 2 a 2-message packet; step 1 is a Cross from
/// lane 0 with half-cut A = [3, 0], step 2 an Improve from lane 2 with half-cut B = [2, 0].
/// `a_steps` and `b_steps` replace those steps.
fn block0(a_flags: u8, a_steps: Vec<StepHalf>, b_steps: Vec<StepHalf>) -> (Two, Vec<Ev>) {
    let mut t = Two::new();
    let ev = vec![
        Ev::Frame(
            0,
            t.a(&order(
                true,
                vec![bind(0, 7), pkt(0, 7, 3, a_flags), Section::StepRun(a_steps)],
            )),
        ),
        Ev::Frame(
            100,
            t.b(&order(
                true,
                vec![bind(2, 9), pkt(2, 9, 2, 0), Section::StepRun(b_steps)],
            )),
        ),
    ];
    (t, ev)
}

fn good_steps() -> (Vec<StepHalf>, Vec<StepHalf>) {
    (
        vec![step(1, StepKind::Cross, Some((0, 1)), false, [3, 0])],
        vec![step(2, StepKind::Improve, Some((2, 2)), false, [2, 0])],
    )
}

/// The rest of a good block 0 after `block0`: marks, hash runs, then the header.
fn finish(
    t: &mut Two,
    ev: &mut Vec<Ev>,
    seed: &[u8; 32],
    tamper: impl Fn(&mut vyrn_types::BlockHeader),
) {
    ev.push(Ev::Frame(200, t.a(&order(false, vec![mark(2, [3, 0])]))));
    ev.push(Ev::Frame(300, t.b(&order(false, vec![mark(2, [2, 0])]))));
    ev.push(Ev::Frame(400, t.a(&hash_run(0, 0x1111))));
    ev.push(Ev::Frame(500, t.b(&hash_run(2, 0x2222))));
    let h = t.header(seed, tamper);
    ev.push(Ev::Frame(600, h));
}

fn fault(code: &str, stream: u8, frame: u64) -> String {
    format!("fault {code} stream {stream} frame {frame} height 0")
}

fn vectors() -> Vec<Vector> {
    let mut out = Vec::new();

    let (a, b) = good_steps();
    let (mut t, mut ev) = block0(0, a, b);
    finish(&mut t, &mut ev, &SEED, |_| {});
    out.push(Vector {
        name: "ok",
        about: "a good block 0; the cut of lane 0 equals its prefix (3), which is allowed",
        events: ev,
        expect: vec![
            "ready 1".into(),
            "verdict 0 0 Valid".into(),
            "verdict 0 1 Pending".into(),
        ],
    });

    let (_, b) = good_steps();
    let (_, ev) = block0(
        0,
        vec![step(1, StepKind::Cross, Some((0, 1)), false, [4, 0])],
        b,
    );
    out.push(Vector {
        name: "cut_beyond_prefix",
        about: "S2: half-cut A moves lane 0 to 4, but lane 0's decoded prefix is 3",
        events: ev,
        expect: vec![fault("REP_E_CUT", 0, 1), "verdict 0 0 Invalid".into()],
    });

    let (_, b) = good_steps();
    let (_, ev) = block0(
        0,
        vec![step(1, StepKind::Cross, Some((0, 1)), false, [3, 1])],
        b,
    );
    out.push(Vector {
        name: "cut_on_empty_lane",
        about: "S2: half-cut A moves lane 1 to 1, but lane 1 has no decoded record (prefix 0)",
        events: ev,
        expect: vec![fault("REP_E_CUT", 0, 1)],
    });

    let (a, _) = good_steps();
    let mut a = a;
    a[0].other = true;
    let (_, ev) = block0(0, a, vec![cut_only(1, StepKind::Cross, [3, 0])]);
    out.push(Vector {
        name: "cut_only_beyond_prefix",
        about: "S2 on a cut-only record: half-cut B moves lane 2 to 3, but its prefix is 2",
        events: ev,
        expect: vec![fault("REP_E_CUT", 1, 1)],
    });

    let (_, b) = good_steps();
    let (_, ev) = block0(
        0,
        vec![step(1, StepKind::Cross, Some((0, 4)), false, [3, 0])],
        b,
    );
    out.push(Vector {
        name: "src_not_decoded",
        about: "S4: the Cross names lane 0 op 4, above lane 0's prefix 3",
        events: ev,
        expect: vec![fault("REP_E_CUT", 0, 1)],
    });

    let (_, b) = good_steps();
    let (_, ev) = block0(
        PacketFlags::SHED,
        vec![step(1, StepKind::Shed, Some((0, 2)), false, [3, 0])],
        b,
    );
    out.push(Vector {
        name: "src_shed",
        about: "S5: a Shed step names op 2 of a packet that carries SHED",
        events: ev,
        expect: vec![fault("REP_E_KIND", 0, 1)],
    });

    for (name, at, expect) in [
        ("hashlag_at_limit", 1_000_000, "ready 0".to_owned()),
        ("hashlag_late", 1_000_001, fault("REP_E_HASHLAG", 0, 1)),
    ] {
        let (a, b) = good_steps();
        let (_, mut ev) = block0(0, a, b);
        ev.push(Ev::Tick(at));
        out.push(Vector {
            name,
            about: "INV-REP-8: lane 0's record arrived at 0 and its HashRun never came",
            events: ev,
            expect: vec![expect],
        });
    }

    let (a, b) = good_steps();
    let (mut t, mut ev) = block0(0, a, b);
    ev.push(Ev::Frame(200, t.a(&order(false, vec![mark(2, [3, 0])]))));
    ev.push(Ev::Frame(1_000_001, t.a(&hash_run(0, 0x1111))));
    out.push(Vector {
        name: "hashlag_late_hash",
        about: "INV-REP-8: lane 0's HashRun arrives 1 ms + 1 ns after its record, with no tick between",
        events: ev,
        expect: vec![fault("REP_E_HASHLAG", 0, 1)],
    });

    let (mut t, mut ev) = block0(
        0,
        vec![step(2, StepKind::Cross, Some((0, 1)), false, [3, 0])],
        vec![step(1, StepKind::Improve, Some((2, 2)), false, [2, 0])],
    );
    finish(&mut t, &mut ev, &SEED, |_| {});
    out.push(Vector {
        name: "merge_from_tenure_cut",
        about: "A delivers step 2 before B delivers step 1: step 1 keeps A's TenureStart half-cut",
        events: ev,
        expect: vec!["cuts 0.0.2.0 3.0.2.0".into()],
    });

    let mut t = Two::new();
    let mut ts = tenure_start();
    ts.prev_cut = vec![LaneSeq(3), LaneSeq(0)];
    let ev = vec![Ev::Frame(
        0,
        t.b(&Body::Order {
            tenure_start: Some(ts),
            sections: vec![bind(2, 9)],
        }),
    )];
    out.push(Vector {
        name: "tenure_cut_beyond_base",
        about: "S2 at the base: B's TenureStart sets lane 2's cut to 3 but its next_lane_seq to 1",
        events: ev,
        expect: vec![fault("REP_E_CUT", 1, 1)],
    });

    let (a, b) = good_steps();
    let (mut t, mut ev) = block0(0, a, b);
    ev.push(Ev::Frame(200, t.a(&order(false, vec![mark(3, [3, 0])]))));
    ev.push(Ev::Frame(300, t.b(&order(false, vec![mark(3, [2, 0])]))));
    out.push(Vector {
        name: "missing_step",
        about: "both marks close block 0 at step 3, but no substream carried step 3",
        events: ev,
        expect: vec![fault("DECODE", 1, 2)],
    });

    let (a, b) = good_steps();
    let (mut t, mut ev) = block0(0, a, b);
    finish(&mut t, &mut ev, &OTHER_SEED, |_| {});
    out.push(Vector {
        name: "header_bad_sig",
        about: "the header is signed by a key that REP_Membership does not register",
        events: ev,
        expect: vec![fault("HEADER", 0, 4)],
    });

    let (a, b) = good_steps();
    let (mut t, mut ev) = block0(0, a, b);
    finish(&mut t, &mut ev, &SEED, |h| h.order_root.0[0] ^= 1);
    out.push(Vector {
        name: "header_order_root",
        about: "a validly signed header whose order_root differs from the ORDER bytes",
        events: ev,
        expect: vec![fault("HEADER", 0, 4)],
    });

    out
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn render(vs: &[Vector]) -> String {
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    let mut s = String::new();
    s.push_str(
        "# vyrn-replica order-core vectors (spec/07-replication.md §3.7, §3.10, §3.12).\n\
         # Generated by crates/vyrn-replica/tests/conformance.rs; VYRN_BLESS=1 rewrites it.\n\
         #\n\
         # Setup for every vector: 4 lanes on 2 substreams (A = lanes 0-1, B = lanes 2-3), no\n\
         # pool, epoch 1, book 1, tenure 0, sequencer index 0 with the seq_key below, no fence.\n\
         # `frame <now_ns> <hex>` delivers one frame received at now_ns; `tick <now_ns>` runs\n\
         # the REP_E_HASHLAG timer (1 ms). Then every `expect` must hold:\n\
         #   ready <k>                 k blocks are ready for replay and there is no fault\n\
         #   fault <code> stream <s> frame <n> height <h>\n\
         #                             the first fault: its REP_E_* code (HEADER for header\n\
         #                             rules), the frame that showed it, the first height that\n\
         #                             loses its vote\n\
         #   verdict <first> <last> <Valid|Invalid|Pending>   07 §6.4 items 2 and 5\n\
         #   cuts <c0.c1.c2.c3> ...    the full cut of each step of the first ready block\n",
    );
    let _ = writeln!(s, "seq_key {}", hex(&key));
    for v in vs {
        let _ = writeln!(s, "\nvector {}\n# {}", v.name, v.about);
        for e in &v.events {
            match e {
                Ev::Frame(t, b) => {
                    let _ = writeln!(s, "frame {t} {}", hex(b));
                }
                Ev::Tick(t) => {
                    let _ = writeln!(s, "tick {t}");
                }
            }
        }
        for x in &v.expect {
            let _ = writeln!(s, "expect {x}");
        }
        s.push_str("end\n");
    }
    s
}

#[test]
fn vectors_are_current() {
    let want = render(&vectors());
    if std::env::var_os("VYRN_BLESS").is_some() {
        std::fs::write(PATH, &want).unwrap();
    }
    let have = std::fs::read_to_string(PATH).unwrap();
    assert!(have == want, "{PATH} is stale; rerun with VYRN_BLESS=1");
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn vectors_hold() {
    let text = std::fs::read_to_string(PATH).unwrap();
    let mut key = [0u8; 32];
    let mut core: Option<OrderCore<N, View>> = None;
    let mut name = String::new();
    let mut ran = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let w: Vec<&str> = line.split(' ').collect();
        match w[0] {
            "seq_key" => key.copy_from_slice(&unhex(w[1])),
            "vector" => {
                name = w[1].to_owned();
                core = Some(OrderCore::new(layout(), View(key)).unwrap());
            }
            "frame" => {
                let c = core.as_mut().unwrap();
                let _ = c.on_frame(&unhex(w[2]), w[1].parse().unwrap());
            }
            "tick" => {
                let _ = core.as_mut().unwrap().tick(w[1].parse().unwrap());
            }
            "expect" => {
                let c = core.as_mut().unwrap();
                match w[1] {
                    "ready" => {
                        assert_eq!(c.fault(), None, "{name}");
                        let mut k = 0;
                        while let Some(b) = c.take_ready() {
                            assert_eq!(b.header.height, Height(k), "{name}");
                            k += 1;
                        }
                        assert_eq!(k.to_string(), w[2], "{name}");
                    }
                    "fault" => {
                        let f = c
                            .fault()
                            .copied()
                            .unwrap_or_else(|| panic!("{name}: no fault"));
                        let got = format!(
                            "{} stream {} frame {} height {}",
                            f.kind.code(),
                            f.stream,
                            f.frame_seq,
                            f.height.0
                        );
                        assert_eq!(got, w[2..].join(" "), "{name}: {f}");
                    }
                    "cuts" => {
                        let b = c
                            .take_ready()
                            .unwrap_or_else(|| panic!("{name}: not ready"));
                        let got: Vec<String> = b
                            .steps
                            .iter()
                            .map(|s| s.rec.cut.map(|x| x.0.to_string()).join("."))
                            .collect();
                        assert_eq!(got.join(" "), w[2..].join(" "), "{name}");
                    }
                    "verdict" => {
                        let v =
                            c.verdict(Height(w[2].parse().unwrap()), Height(w[3].parse().unwrap()));
                        let want = match w[4] {
                            "Valid" => Verdict::Valid,
                            "Invalid" => Verdict::Invalid,
                            _ => Verdict::Pending,
                        };
                        assert_eq!(v, want, "{name}: {line}");
                    }
                    x => panic!("unknown expect {x}"),
                }
            }
            "end" => ran += 1,
            x => panic!("unknown line {x}"),
        }
    }
    assert_eq!(ran, vectors().len());
}

/// A tenure that starts at height 5 has checked nothing below it (07 §6.4).
#[test]
fn verdict_starts_at_the_tenure() {
    let ts = TenureStart {
        first_height: Height(5),
        ..tenure_start()
    };
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    let mut core: OrderCore<N, View> = OrderCore::new(layout(), View(key)).unwrap();
    for (s, lane) in [(0, 0), (1, 2)] {
        let mut e = StreamEncoder::new(layout(), s, ident()).unwrap();
        let f = e
            .encode(&Body::Order {
                tenure_start: Some(ts.clone()),
                sections: vec![bind(lane, 7)],
            })
            .unwrap();
        core.on_frame(&f, 0).unwrap();
    }
    assert_eq!(core.next_height(), Height(5));
    assert_eq!(core.verdict(Height(0), Height(3)), Verdict::Pending);
    assert_eq!(core.verdict(Height(4), Height(5)), Verdict::Pending);
}
