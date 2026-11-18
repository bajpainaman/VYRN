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

#[test]
fn handoff_vectors_match() {
    check("handoff.txt", &handoff());
}

#[test]
fn schedule_vectors_match() {
    check("schedule.txt", &schedule());
}
