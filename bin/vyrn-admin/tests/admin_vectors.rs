//! `vyrn_admin::codec` against `tests/golden/vyrn_admin_vectors.out` (04 §4.4), whose bytes come
//! from the spec tables alone, and the `CtlDone` layout of 10 §2.4.

use core::net::{Ipv4Addr, SocketAddrV4};

use vyrn_admin::codec::{AdminMsg, CtlDone, decode, encode, frame_len};
use vyrn_types::{AccountId, BookId, HomeCode, LaneId, RejectReason};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> Vec<(String, String, String, Vec<u8>)> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/vyrn_admin_vectors.out"
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f[0].into(), f[1].into(), f[2].into(), unhex(f[3]))
        })
        .collect()
}

#[test]
fn every_admin_vector_gets_its_verdict() {
    let v = vectors();
    assert_eq!(v.len(), 10, "A01, A02, B01–B08");
    for (id, name, verdict, raw) in &v {
        assert_eq!(frame_len(raw), Some(raw.len()), "{id}: len prefix");
        let got = decode(raw);
        match verdict.as_str() {
            "ok" => {
                let m = got.unwrap_or_else(|e| panic!("{id}: refused {e:?}"));
                let kind = match &m {
                    AdminMsg::OpenSessionReq(_) => "OpenSessionReq",
                    AdminMsg::OpenSessionResp(_) => "OpenSessionResp",
                    _ => "other",
                };
                assert_eq!(kind, name, "{id}");
                assert_eq!(&encode(&m).unwrap(), raw, "{id}: encode(decode(x)) == x");
            }
            "refuse" => assert!(got.is_err(), "{id}: accepted {got:?}"),
            _ => panic!("{id}: verdict {verdict}"),
        }
    }
}

#[test]
fn a01_and_a02_decode_to_the_fields_the_script_wrote() {
    let v = vectors();
    let AdminMsg::OpenSessionReq(r) = decode(&v[0].3).unwrap() else {
        panic!("A01")
    };
    assert_eq!(r.account, AccountId(7));
    assert!(r.cod && r.attest);
    assert_eq!((r.rate_tier, r.timeout_ms, r.proto_version), (1, 350, 2));
    assert_eq!(r.src, SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 40000));
    assert_eq!(r.books, [BookId(1), BookId(2)]);

    let AdminMsg::OpenSessionResp(s) = decode(&v[1].3).unwrap() else {
        panic!("A02")
    };
    assert_eq!(
        (s.session.0, s.lane, s.epoch.0, s.active_from_step.0),
        (0x0010_3007, LaneId(3), 1000, 1)
    );
    assert_eq!(
        s.limits.iter().map(|l| (l.id, l.value)).collect::<Vec<_>>(),
        [(1, 10_000), (5, 1_000_000)]
    );
    let b = &s.bundle;
    assert_eq!(
        (b.home, b.next_home, b.seq_index, b.lane_move),
        (HomeCode::Tyo, HomeCode::Ldn, 0, None)
    );
    assert_eq!(b.boundary_ts.0, 28_800_000_000_000);
    assert_eq!(b.failover_order, [1, 2, 0]);
    assert_eq!(
        b.data[7],
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 1, 8), 9000)
    );
    assert_eq!(b.boxes.len(), 3);
    assert_eq!(
        b.boxes[0].k_seq,
        core::array::from_fn::<u8, 16, _>(|i| i as u8)
    );
    assert_eq!(
        b.boxes[2].recovery,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 3, 3), 7001)
    );
}

#[test]
fn ctl_done_bytes_follow_10_2_4() {
    // CtlSetLimit (0x22) refused: BAD_QTY (5), account 0x01020304, detail = limit id 3.
    let d = CtlDone {
        op: 0x22,
        reason: Some(RejectReason::BadQty),
        account: AccountId(0x0102_0304),
        detail: 3,
    };
    let want = [0xA2, 0x22, 5, 0, 4, 3, 2, 1, 3, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(d.encode().unwrap(), want);
    assert_eq!(CtlDone::decode(&want).unwrap(), d);

    let done = CtlDone {
        op: 0x26,
        reason: None,
        account: AccountId(9),
        detail: 0,
    };
    assert_eq!(CtlDone::decode(&done.encode().unwrap()).unwrap(), done);

    let mut bad = want;
    bad[15] = 1; // bytes 12–15 must be 0
    assert!(CtlDone::decode(&bad).is_err());
    let mut bad = want;
    bad[0] = 0xA1; // not CtlDone
    assert!(CtlDone::decode(&bad).is_err());
    let mut bad = want;
    bad[2] = 25; // reason 25 is reserved, not defined
    assert!(CtlDone::decode(&bad).is_err());
}

/// V20 of the 04 §11 protocol vectors: the `DataTierStatus` push (04 §4.4) for session A, epoch
/// 1000, `seq` 1, `data[0]` down. `seq` 0 and a nonzero reserved byte are refused.
#[test]
fn v20_data_tier_status_round_trips_and_its_neighbours_are_refused() {
    use vyrn_admin::codec::DataTierStatus;
    use vyrn_types::Epoch;
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/vyrn_proto_vectors.out"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut rows = text.lines().skip_while(|l| !l.starts_with("V20 "));
    assert!(rows.next().unwrap().ends_with("(18 B)"));
    let raw: Vec<u8> = rows
        .take_while(|l| l.starts_with("  0"))
        .flat_map(|l| l.trim().split_once(": ").unwrap().1.split(' '))
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();
    assert_eq!(frame_len(&raw), Some(18));
    let want = AdminMsg::DataTierStatus(DataTierStatus {
        epoch: Epoch(1000),
        seq: 1,
        down: 0b1,
    });
    assert_eq!(decode(&raw).unwrap(), want);
    assert_eq!(encode(&want).unwrap(), raw);
    let mut zero_seq = raw.clone();
    zero_seq[10] = 0;
    assert!(decode(&zero_seq).is_err());
    let mut reserved = raw.clone();
    reserved[17] = 1;
    assert!(decode(&reserved).is_err());
    assert!(decode(&raw[..17]).is_err());
}
