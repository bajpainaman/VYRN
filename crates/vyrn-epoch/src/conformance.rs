//! Conformance vectors: `vectors/handoff.txt` and `vectors/schedule.txt`.
//!
//! Plain `key = value` lines, one blank line between cases, so an implementation in any language
//! can run them without this crate. Keys come from the seeds in the file headers. The tests
//! rebuild both files from first principles and fail on any difference; `VYRN_BLESS=1` rewrites
//! them.

use crate::handoff::{
    HandoffCert, HandoffErr, encode_record, handoff_message, record_hash, verify_cert,
};
use crate::notice::Notifier;
use crate::schedule::{Boundary, ScheduleRecord, Timetable};
use crate::{Domain, EPO_HOLD_S, NS_PER_S, testkit};
use std::fmt::Write as _;
use vyrn_types::{Epoch, Hash, HomeCode, Mode, Nanos};

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn check(name: &str, text: &str) {
    let path = format!("{}/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("VYRN_BLESS").is_some() {
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("{path}: {e}"));
        return;
    }
    let file = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert!(
        file == text,
        "{path} differs from the generator; VYRN_BLESS=1 rewrites it"
    );
}

fn verdict(r: Result<(), HandoffErr>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(HandoffErr::Count { .. }) => "count",
        Err(HandoffErr::Order) => "order",
        Err(HandoffErr::Unknown(_)) => "unknown_voter",
        Err(HandoffErr::BadSig(_)) => "bad_sig",
        Err(_) => "other",
    }
}

fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Base => "base",
        Mode::Chain => "chain",
    }
}

fn handoff() -> String {
    let mut s = String::from(
        "# vyrn-epoch handoff vectors (spec/08-epochs.md §5.1-5.4).\n\
         # Voter i (0-based) of R_e has Ed25519 seed [i+1; 32]. mode byte: base 0, chain 1.\n\
         # message = derive_key(\"vyrn      v1 handoff\", genesis_hash || mode || record).\n\
         # cert = record || Q x (index u8, sig [64]); verdict is check 1 of §5.4.\n\n",
    );
    let r = testkit::record();
    let _ = writeln!(s, "case = record");
    let _ = writeln!(s, "record = {}", hex(&encode_record(&r)));
    let _ = writeln!(s, "record_hash = {}\n", hex(&record_hash(&r).0));
    let other = Hash([0xEE; 32]);
    for mode in [Mode::Base, Mode::Chain] {
        let domain = testkit::domain(mode);
        let old = testkit::old(mode);
        let q = u8::try_from(mode.quorum()).unwrap_or(0);
        let quorum: Vec<u8> = (0..q).collect();
        let mut reversed = quorum.clone();
        reversed.swap(0, 1);
        let wrong_genesis = Domain {
            genesis_hash: other,
            ..domain
        };
        let cases: [(&str, HandoffCert); 4] = [
            ("quorum", testkit::cert(&domain, &quorum)),
            ("below_quorum", testkit::cert(&domain, &quorum[1..])),
            ("unordered", testkit::cert(&domain, &reversed)),
            ("wrong_genesis", testkit::cert(&wrong_genesis, &quorum)),
        ];
        for (name, cert) in cases {
            let _ = writeln!(s, "case = {}_{name}", mode_name(mode));
            let _ = writeln!(s, "mode = {}", mode_name(mode));
            let _ = writeln!(s, "genesis_hash = {}", hex(&domain.genesis_hash.0));
            let _ = writeln!(s, "message = {}", hex(&handoff_message(&domain, &r)));
            let _ = writeln!(s, "cert = {}", hex(&cert.encode()));
            let _ = writeln!(
                s,
                "verdict = {}\n",
                verdict(verify_cert(&cert, &domain, &old))
            );
        }
    }
    s
}

fn home(h: HomeCode) -> &'static str {
    match h {
        HomeCode::Tyo => "TYO",
        HomeCode::Ldn => "LDN",
        HomeCode::Nyc => "NYC",
    }
}

fn line(b: &Boundary) -> String {
    format!(
        "{} {} {} {} {}",
        b.from.0,
        b.to.0,
        b.t.0,
        home(b.from_home),
        home(b.to_home)
    )
}

fn schedule() -> String {
    let g = Nanos(1_000 * NS_PER_S);
    let mut s = format!(
        "# vyrn-epoch schedule vectors (spec/08-epochs.md §2.1-2.5, §2.4).\n\
         # genesis = {} ns TAI. boundary = from to T home(from) home(to); records apply in order.\n\
         # notice = rx_ts -> next home secs flags | none.\n\n",
        g.0
    );
    let tt = || Timetable::new(g).unwrap_or_else(|e| panic!("{e}"));

    // Default rotation: activate each target on time.
    let _ = writeln!(s, "case = rotation");
    let mut t = tt();
    for _ in 0..4 {
        let b = t.boundary();
        let _ = writeln!(s, "boundary = {}", line(&b));
        let _ = t.apply(ScheduleRecord::Activated { epoch: b.to }, b.t);
    }

    // Hold at the go/no-go, then a skip and an override of the next target.
    let _ = writeln!(s, "\ncase = revisions");
    let mut t = tt();
    let t0 = t.boundary().t;
    let go = Nanos(t0.0 - 10 * NS_PER_S);
    let records = [
        (
            ScheduleRecord::Skip { epoch: Epoch(1) },
            Nanos(t0.0 - 3_600 * NS_PER_S),
        ),
        (
            ScheduleRecord::HomeOverride {
                epoch: Epoch(2),
                home: HomeCode::Tyo,
            },
            go,
        ),
        (ScheduleRecord::Skip { epoch: Epoch(2) }, go),
    ];
    for (r, at) in records {
        let res = t
            .apply(r, at)
            .map_or_else(|e| format!("{e:?}"), |()| "ok".into());
        let _ = writeln!(s, "apply = {r:?} at {} -> {res}", at.0);
        let _ = writeln!(s, "boundary = {}", line(&t.boundary()));
    }
    let t2 = t.boundary().t;
    let hold = ScheduleRecord::Hold {
        epoch: Epoch(0),
        t_new: Nanos(t2.0 + EPO_HOLD_S * NS_PER_S),
    };
    let at = Nanos(t2.0 - 10 * NS_PER_S);
    let res = t
        .apply(hold, at)
        .map_or_else(|e| format!("{e:?}"), |()| "ok".into());
    let _ = writeln!(s, "apply = {hold:?} at {} -> {res}", at.0);
    let _ = writeln!(s, "boundary = {}", line(&t.boundary()));

    // Notices of one lane over the last hour.
    let _ = writeln!(s, "\ncase = notices");
    let b = tt().boundary();
    let mut n = Notifier::new(&b, 5);
    let _ = writeln!(s, "boundary = {}", line(&b));
    for back_ms in [
        3_700_000u64,
        3_600_000,
        3_599_999,
        600_000,
        59_000,
        9_500,
        4_000,
        1_000,
        999,
        0,
    ] {
        let rx = Nanos(b.t.0 - back_ms * 1_000_000);
        let out = n.on_packet(rx).map_or_else(
            || "none".into(),
            |x| format!("{} {} {} {}", x.next.0, home(x.home), x.secs, x.flags),
        );
        let _ = writeln!(s, "notice = {} -> {out}", rx.0);
    }
    s
}

fn roster_verdict(r: Result<(), crate::RosterErr>) -> String {
    use crate::RosterErr as E;
    match r {
        Ok(()) => "ok".into(),
        Err(e) => match e {
            E::Hash => "hash",
            E::Version(_) => "version",
            E::NotLive(_) => "not_live",
            E::Scheme { .. } => "scheme",
            E::Short => "short",
            E::Trailing(_) => "trailing",
            E::Early { .. } => "early",
            E::Field(_) => "field",
            E::ClientSplit(_) => "client_split",
            E::DuplicateKey(_) => "duplicate_key",
            E::Recovery(_) => "recovery",
            E::OperatorBoxes(_) => "operator_boxes",
            E::SeqCount(_) => "seq_count",
            E::Bridge => "bridge",
            E::SeqOrder(_) => "seq_order",
            E::Unsupported(_) => "unsupported",
            E::Membership(_) => "membership",
        }
        .into(),
    }
}

fn roster() -> String {
    use crate::{EpoConfig, Membership, Roster};
    let mut s = String::from(
        "# vyrn-epoch roster vectors (spec/08-epochs.md §9.6).\n\
         # roster_hash = derive_key(\"vyrn      v1 roster\", genesis_hash || mode || roster).\n\
         # Fixture: testkit::roster. LDN voter i has vote seed [0x41+i; 32] and GXK seed [2, i, 0xC7 x 30];\n\
         # LDN vyrn-seq box j has seq seed [0x90+j; 32] and XK seed [0x98+j; 32].\n\
         # EpoConfig(8) is LDN with seq_order BASE [n, n+1], CHAIN [n, n+3].\n\
         # verdict is Membership::from_roster; CHAIN passes a signer table whose rotation 0 is the\n\
         # roster's bridge set. A reject_ case edits the fixture as its name says;\n\
         # its roster_hash is the hash of the edited bytes unless the case edits the hash itself.\n\n",
    );
    for (mode, scheme) in [(Mode::Base, 0u8), (Mode::Chain, 0), (Mode::Chain, 1)] {
        let domain = testkit::domain(mode);
        let r = testkit::roster(mode, scheme);
        let bytes = r.encode();
        assert_eq!(Roster::decode(mode, &bytes).as_ref(), Ok(&r), "round trip");
        let cfg = testkit::config(&domain, &r);
        let name = format!("{}_scheme{scheme}", mode_name(mode));
        let _ = writeln!(s, "case = {name}");
        let _ = writeln!(s, "mode = {}", mode_name(mode));
        let _ = writeln!(s, "genesis_hash = {}", hex(&domain.genesis_hash.0));
        let _ = writeln!(s, "len = {}", bytes.len());
        if scheme == 0 {
            let _ = writeln!(s, "roster = {}", hex(&bytes));
        }
        let _ = writeln!(s, "roster_hash = {}", hex(&cfg.roster_hash.0));
        let table = testkit::bridge_table(&r);
        let got = Membership::from_roster(&cfg, &bytes, &domain, table.as_ref());
        let _ = writeln!(
            s,
            "verdict = {}",
            roster_verdict(got.as_ref().map(|_| ()).map_err(|e| *e))
        );
        if let Ok((m, _)) = &got {
            for i in 0..m.committee().n() {
                let k = m
                    .committee()
                    .voter(u8::try_from(i).unwrap_or(0))
                    .copied()
                    .unwrap_or_default();
                let _ = writeln!(s, "voter{i} = {}", hex(&k));
            }
            for b in m.seq().iter().chain(m.spares()) {
                let _ = writeln!(
                    s,
                    "seq{} = {} {}",
                    b.index,
                    hex(&b.seq_key),
                    hex(&b.xchg_key)
                );
            }
        }
        s.push('\n');
    }

    // Rejects on the BASE scheme-0 fixture. Each case edits the roster, then its bytes, then the
    // config; the config names the hash of the edited bytes unless the config edit changes it.
    let mode = Mode::Base;
    let domain = testkit::domain(mode);
    let none_r: fn(&mut Roster) = |_| {};
    let none_b: fn(&mut Vec<u8>) = |_| {};
    let none_c: fn(&mut EpoConfig) = |_| {};
    type Case = (
        &'static str,
        fn(&mut Roster),
        fn(&mut Vec<u8>),
        fn(&mut EpoConfig),
    );
    let cases: [Case; 11] = [
        ("wrong_hash", none_r, none_b, |c| c.roster_hash.0[0] ^= 1),
        ("cfg_scheme_1", none_r, none_b, |c| c.sig_scheme = 1),
        (
            "epoch_before_from",
            |r| r.epoch_from = Epoch(9),
            none_b,
            none_c,
        ),
        ("seq_order_same_box", none_r, none_b, |c| {
            c.seq_order = [4, 4]
        }),
        ("seq_order_swapped_facilities", none_r, none_b, |c| {
            c.seq_order = [5, 4]
        }),
        ("seq_order_voter", none_r, none_b, |c| c.seq_order = [3, 4]),
        (
            "rust_quorum",
            |r| r.homes[1].voters[1].client = 0,
            none_b,
            none_c,
        ),
        (
            "vote_key_is_seq_key",
            |r| r.homes[2].seq[0].seq_key = r.homes[2].voters[3].vote_key.clone(),
            none_b,
            none_c,
        ),
        (
            "recovery_on_vx",
            |r| r.homes[0].recovery = 1,
            none_b,
            none_c,
        ),
        ("trailing_byte", none_r, |b| b.push(0), none_c),
        ("version_2", none_r, |b| b[0] = 2, none_c),
    ];
    for (name, edit_r, edit_b, edit_c) in cases {
        let mut r = testkit::roster(mode, 0);
        edit_r(&mut r);
        let mut bytes = r.encode();
        edit_b(&mut bytes);
        let mut cfg = testkit::config(&domain, &r);
        cfg.roster_hash = Roster::hash_bytes(&domain, &bytes);
        edit_c(&mut cfg);
        let _ = writeln!(s, "case = reject_{name}");
        let _ = writeln!(s, "mode = base");
        let _ = writeln!(s, "roster_hash = {}", hex(&cfg.roster_hash.0));
        let _ = writeln!(s, "seq_order = {} {}", cfg.seq_order[0], cfg.seq_order[1]);
        let _ = writeln!(s, "sig_scheme = {}", cfg.sig_scheme);
        let got = Membership::from_roster(&cfg, &bytes, &domain, None).map(|_| ());
        let _ = writeln!(s, "verdict = {}\n", roster_verdict(got));
    }
    s
}

#[test]
fn roster_vectors_match() {
    check("roster.txt", &roster());
}

#[test]
fn handoff_vectors_match() {
    check("handoff.txt", &handoff());
}

#[test]
fn schedule_vectors_match() {
    check("schedule.txt", &schedule());
}
