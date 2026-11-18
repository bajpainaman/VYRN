//! Conformance: vyrn-chain against `contracts/vectors/*.json`, which eth-account, `cast`,
//! `@openzeppelin/merkle-tree` and Python `blake3` computed without this crate or the contract
//! (contracts/README.md §Conformance vectors). The files are read as they are on main; any edit to
//! them or to this crate's formats that breaks agreement fails here.
//!
//! serde_json is a tools-only crate (spec/11-build.md §2.2), so a minimal JSON reader is below.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;

use vyrn_chain::eip712::{self, Address, Domain, Post, SigError, SignerSet, Unpause};
use vyrn_chain::smt::{self, AccountLeaf, BalanceLeaf, Proof, Smt};
use vyrn_chain::wdtree::{self, Withdrawal};
use vyrn_chain::{Checkpoint, Epochs, Guardian, Replica, Verdict, VetoReason, build_post};
use vyrn_types::Hash;

// ---- a minimal JSON reader (objects, arrays, strings without escapes, integers) ----

#[derive(Clone, Debug)]
enum J {
    Obj(BTreeMap<String, J>),
    Arr(Vec<J>),
    Str(String),
    Num(String),
}

impl J {
    fn get(&self, k: &str) -> &J {
        match self {
            J::Obj(m) => m.get(k).unwrap_or_else(|| panic!("missing key {k}")),
            _ => panic!("not an object at {k}"),
        }
    }
    fn arr(&self) -> &[J] {
        match self {
            J::Arr(v) => v,
            _ => panic!("not an array"),
        }
    }
    fn s(&self) -> &str {
        match self {
            J::Str(s) | J::Num(s) => s,
            _ => panic!("not a scalar"),
        }
    }
    fn u128(&self) -> u128 {
        self.s().parse().unwrap()
    }
    fn u64(&self) -> u64 {
        self.s().parse().unwrap()
    }
    fn bytes(&self) -> Vec<u8> {
        let s = self.s().strip_prefix("0x").unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn b32(&self) -> [u8; 32] {
        self.bytes().try_into().unwrap()
    }
    fn h(&self) -> Hash {
        Hash(self.b32())
    }
    fn addr(&self) -> Address {
        self.bytes().try_into().unwrap()
    }
}

fn parse(src: &str) -> J {
    fn ws(b: &[u8], i: &mut usize) {
        while b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    }
    fn val(b: &[u8], i: &mut usize) -> J {
        ws(b, i);
        match b[*i] {
            b'{' => {
                *i += 1;
                let mut m = BTreeMap::new();
                loop {
                    ws(b, i);
                    if b[*i] == b'}' {
                        *i += 1;
                        return J::Obj(m);
                    }
                    let J::Str(k) = val(b, i) else { panic!("key") };
                    ws(b, i);
                    assert_eq!(b[*i], b':');
                    *i += 1;
                    m.insert(k, val(b, i));
                    ws(b, i);
                    if b[*i] == b',' {
                        *i += 1;
                    }
                }
            }
            b'[' => {
                *i += 1;
                let mut v = Vec::new();
                loop {
                    ws(b, i);
                    if b[*i] == b']' {
                        *i += 1;
                        return J::Arr(v);
                    }
                    v.push(val(b, i));
                    ws(b, i);
                    if b[*i] == b',' {
                        *i += 1;
                    }
                }
            }
            b'"' => {
                let start = *i + 1;
                *i = start;
                while b[*i] != b'"' {
                    assert_ne!(b[*i], b'\\', "escapes are not used by the vectors");
                    *i += 1;
                }
                *i += 1;
                J::Str(String::from_utf8(b[start..*i - 1].to_vec()).unwrap())
            }
            _ => {
                let start = *i;
                while b[*i].is_ascii_digit() || b[*i] == b'-' {
                    *i += 1;
                }
                J::Num(String::from_utf8(b[start..*i].to_vec()).unwrap())
            }
        }
    }
    let mut i = 0;
    val(src.as_bytes(), &mut i)
}

fn load(name: &str) -> J {
    let path = format!(
        "{}/../../contracts/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    parse(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")))
}

fn keys5(j: &J) -> [Address; 5] {
    let v: Vec<Address> = j.arr().iter().map(J::addr).collect();
    v.try_into().unwrap()
}

fn domain(v: &J) -> Domain {
    let d = v.get("domain");
    Domain {
        chain_id: d.get("chainId").u64(),
        verifying_contract: d.get("verifyingContract").addr(),
    }
}

fn post_of(m: &J) -> Post {
    Post {
        post_no: m.get("postNo").u64(),
        chain_id: m.get("chainId").u64() as u32,
        prev_post: m.get("prevPost").b32(),
        commit: m.get("commit").b32(),
        smt_root: m.get("smtRoot").b32(),
        deposit_nonce: m.get("depositNonce").u64(),
        wd_root: m.get("wdRoot").b32(),
        wd_count: m.get("wdCount").u64() as u32,
        wd_totals: m
            .get("wdTotals")
            .arr()
            .iter()
            .map(|t| eip712::word(t.u128()))
            .collect(),
    }
}

fn struct_hash(v: &J) -> [u8; 32] {
    let m = v.get("message");
    match v.get("primaryType").s() {
        "Post" => post_of(m).struct_hash(),
        "Unpause" => Unpause {
            pause_no: m.get("pauseNo").u64(),
        }
        .struct_hash(),
        "SignerSet" => SignerSet {
            rotation_no: m.get("rotationNo").u64(),
            bridge_keys: keys5(m.get("bridgeKeys")),
            guardian_keys: keys5(m.get("guardianKeys")),
        }
        .struct_hash(),
        t => panic!("type {t}"),
    }
}

// ---- eip712.json ----

#[test]
fn eip712_domain_type_hashes_digests() {
    let v = load("eip712.json");
    let d = domain(&v);
    assert_eq!(d.separator(), v.get("domainSeparator").b32());
    let th = v.get("typeHashes");
    for (name, s) in [
        ("Post", eip712::POST_TYPE),
        ("Unpause", eip712::UNPAUSE_TYPE),
        ("SignerSet", eip712::SIGNER_SET_TYPE),
    ] {
        assert_eq!(v.get("typeStrings").get(name).s(), s);
        assert_eq!(
            vyrn_chain::keccak::keccak256(s.as_bytes()),
            th.get(name).b32()
        );
    }
    let vs = v.get("vectors").arr();
    assert_eq!(vs.len(), 4);
    for vec in vs {
        let sh = struct_hash(vec);
        assert_eq!(sh, vec.get("structHash").b32(), "{}", vec.get("name").s());
        assert_eq!(
            d.digest(&sh),
            vec.get("digest").b32(),
            "{}",
            vec.get("name").s()
        );
    }
    // 09 §6.2: post 2's prevPost is post 1's struct hash.
    assert_eq!(
        post_of(vs[1].get("message")).prev_post,
        vs[0].get("structHash").b32()
    );
}

#[test]
fn eip712_signatures_recover_and_reproduce() {
    let v = load("eip712.json");
    let bks = keys5(v.get("bridgeKeys"));
    let secrets: Vec<[u8; 32]> = v.get("bridgeKeyPrivate").arr().iter().map(J::b32).collect();
    for (i, s) in secrets.iter().enumerate() {
        assert_eq!(eip712::address_of_secret(s), Some(bks[i]));
    }
    for vec in v.get("vectors").arr() {
        let digest = vec.get("digest").b32();
        let sigs: Vec<Vec<u8>> = vec.get("signatures").arr().iter().map(J::bytes).collect();
        let signers = keys5(vec.get("signers"));
        for (i, sig) in sigs.iter().enumerate() {
            assert_eq!(eip712::recover(&digest, sig), Ok(signers[i]));
            // RFC 6979 is deterministic, so the reference signer reproduces `cast wallet sign`.
            assert_eq!(
                eip712::sign(&digest, &secrets[i]).unwrap().as_slice(),
                sig.as_slice()
            );
        }
        assert_eq!(eip712::count_sigs(&digest, &sigs, &bks), Ok(0b1_1111));
        assert_eq!(eip712::count_sigs(&digest, &sigs[1..], &bks), Ok(0b1_1110));
    }
}

#[test]
fn eip712_rejects_like_the_contract() {
    let v = load("eip712.json");
    let bks = keys5(v.get("bridgeKeys"));
    let vec = &v.get("vectors").arr()[0];
    let digest = vec.get("digest").b32();
    let sigs: Vec<Vec<u8>> = vec.get("signatures").arr().iter().map(J::bytes).collect();
    let err = |s: &[Vec<u8>]| eip712::count_sigs(&digest, s, &bks).unwrap_err();

    assert_eq!(err(&sigs[..3]), SigError::NotEnoughSignatures);
    let mut dup = sigs[..4].to_vec();
    dup.push(sigs[0].clone());
    assert_eq!(err(&dup), SigError::DuplicateSigner);
    // A fifth bad signature rejects a set that already holds four good ones: nothing is skipped.
    let mut short = sigs[..4].to_vec();
    short.push(sigs[4][..64].to_vec());
    assert_eq!(err(&short), SigError::BadSignature);
    let mut bad_v = sigs.clone();
    bad_v[4][64] = 29;
    assert_eq!(err(&bad_v), SigError::BadSignature);
    // High s: s' = n − s with v flipped recovers the same key, and EIP-2 still rejects it.
    let n: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let mut high = sigs.clone();
    let mut borrow = 0i16;
    for k in (0..32).rev() {
        let d = i16::from(n[k]) - i16::from(high[4][32 + k]) - borrow;
        high[4][32 + k] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    high[4][64] ^= 1; // 27 <-> 28
    assert_eq!(err(&high), SigError::BadSignature);
    // A key outside the set.
    let mut stranger = sigs.clone();
    stranger[4] = eip712::sign(&digest, &[0x77; 32]).unwrap().to_vec();
    assert_eq!(err(&stranger), SigError::UnknownSigner);
    // A signature over another digest recovers some other key.
    let other = v.get("vectors").arr()[1].get("signatures").arr()[0].bytes();
    let mut wrong = sigs[..4].to_vec();
    wrong.push(other);
    assert_eq!(err(&wrong), SigError::UnknownSigner);

    let rotation = &v.get("vectors").arr()[3];
    assert!(
        SignerSet {
            rotation_no: 1,
            bridge_keys: keys5(rotation.get("message").get("bridgeKeys")),
            guardian_keys: keys5(rotation.get("message").get("guardianKeys")),
        }
        .is_well_formed()
    );
    let mut dup_set = SignerSet {
        rotation_no: 1,
        bridge_keys: bks,
        guardian_keys: keys5(v.get("guardianKeys")),
    };
    assert!(dup_set.is_well_formed());
    dup_set.guardian_keys[3] = dup_set.guardian_keys[0];
    assert!(!dup_set.is_well_formed());
}

// ---- wdtree.json ----

fn withdrawals(v: &J) -> Vec<Withdrawal> {
    v.get("leaves")
        .arr()
        .iter()
        .map(|l| Withdrawal {
            wd_id: l.get("wdId").u64(),
            token: l.get("token").addr(),
            amount: l.get("amount").u128(),
            recipient: l.get("recipient").addr(),
        })
        .collect()
}

#[test]
fn wdtree_matches_openzeppelin() {
    let v = load("wdtree.json");
    let ws = withdrawals(&v);
    let root = v.get("root").b32();
    assert_eq!(wdtree::root(&ws), root);
    // Input order does not matter: leaves are sorted by hash.
    let mut rev = ws.clone();
    rev.reverse();
    assert_eq!(wdtree::root(&rev), root);
    for (i, (w, l)) in ws.iter().zip(v.get("leaves").arr()).enumerate() {
        assert_eq!(w.leaf_hash(), l.get("leafHash").b32());
        let want: Vec<[u8; 32]> = l.get("proof").arr().iter().map(J::b32).collect();
        assert_eq!(wdtree::proof(&ws, i).unwrap(), want);
        assert!(wdtree::verify(&root, &w.leaf_hash(), &want));
        let mut bad = *w;
        bad.amount += 1;
        assert!(!wdtree::verify(&root, &bad.leaf_hash(), &want));
    }
    let assets = [ws[0].token, ws[1].token];
    let totals: Vec<[u8; 32]> = v
        .get("totals")
        .arr()
        .iter()
        .map(|t| eip712::word(t.u128()))
        .collect();
    assert_eq!(wdtree::totals(&ws, &assets).unwrap(), totals);
    assert_eq!(wdtree::totals(&ws, &assets[..1]), None);
    // A total over many accounts exceeds u128 and is still postable: three of u128::MAX sum to
    // 3·2^128 − 3 = 0x02 ‖ ff…fd (low 16 bytes) in the uint256 word.
    let big: Vec<Withdrawal> = (0..3)
        .map(|i| Withdrawal {
            wd_id: 100 + i,
            amount: u128::MAX,
            ..ws[0]
        })
        .collect();
    let mut want = [0u8; 32];
    want[15] = 0x02;
    want[16..].copy_from_slice(&(u128::MAX - 2).to_be_bytes());
    assert_eq!(wdtree::totals(&big, &assets).unwrap()[0], want);
    // Carry across a byte boundary: 0xff + 0x01 = 0x0100.
    let carry: Vec<Withdrawal> = [0xff, 0x01]
        .iter()
        .enumerate()
        .map(|(i, &a)| Withdrawal {
            wd_id: 200 + i as u64,
            amount: a,
            ..ws[0]
        })
        .collect();
    assert_eq!(
        wdtree::totals(&carry, &assets).unwrap()[0],
        eip712::word(0x100)
    );
    assert_eq!(wdtree::root(&[]), [0u8; 32]);
}

// ---- smt.json ----

fn proof_of(j: &J) -> Proof {
    Proof {
        bitmap: j.get("bitmap").b32(),
        siblings: j.get("siblings").arr().iter().map(J::h).collect(),
    }
}

fn accounts(v: &J) -> Vec<AccountLeaf> {
    v.get("accounts")
        .arr()
        .iter()
        .map(|a| AccountLeaf {
            account: a.get("account").u64() as u32,
            owner_kind: a.get("ownerKind").u64() as u8,
            owner: a.get("owner").b32(),
            nonce: a.get("nonce").u64(),
            exit_address: a.get("exitAddress").addr(),
        })
        .collect()
}

fn balances(v: &J) -> Vec<BalanceLeaf> {
    v.get("balances")
        .arr()
        .iter()
        .map(|b| BalanceLeaf {
            account: b.get("account").u64() as u32,
            asset: b.get("asset").u64() as u16,
            free: b.get("free").u128(),
            alloc_sum: b.get("allocSum").u128(),
            transit: b.get("transit").u128(),
            pending_unposted: b.get("pendingUnposted").u128(),
            pending_posted: b.get("pendingPosted").u128(),
        })
        .collect()
}

#[test]
fn smt_empty_and_contexts() {
    let v = load("smt.json");
    assert_eq!(v.get("leafContext").s(), smt::LEAF_CONTEXT);
    assert_eq!(v.get("nodeContext").s(), smt::NODE_CONTEXT);
    let e = v.get("empty").arr();
    for (i, h) in [0usize, 1, 2, 3, 255, 256].into_iter().enumerate() {
        assert_eq!(smt::empty(h), e[i].h(), "E[{h}]");
    }
    assert_eq!(
        smt::node_hash(&Hash([0; 32]), &Hash([0; 32])),
        v.get("nodeHashOfZeros").h()
    );
    assert_eq!(Smt::new().root(), smt::empty(256));
}

#[test]
fn smt_leaves_root_and_proofs() {
    let v = load("smt.json");
    let root = v.get("root").h();
    let mut tree = Smt::new();
    let mut checks = Vec::new();
    for (a, j) in accounts(&v).iter().zip(v.get("accounts").arr()) {
        assert_eq!(a.key(), j.get("key").h());
        assert_eq!(a.value().as_slice(), j.get("value").bytes().as_slice());
        assert_eq!(a.leaf_hash(), j.get("leafHash").h());
        tree.insert(a.key(), a.leaf_hash());
        checks.push((a.key(), a.leaf_hash(), proof_of(j)));
    }
    for (b, j) in balances(&v).iter().zip(v.get("balances").arr()) {
        assert_eq!(b.key(), j.get("key").h());
        assert_eq!(b.value().as_slice(), j.get("value").bytes().as_slice());
        assert_eq!(b.leaf_hash(), j.get("leafHash").h());
        tree.insert(b.key(), b.leaf_hash());
        checks.push((b.key(), b.leaf_hash(), proof_of(j)));
    }
    assert_eq!(checks.len(), 9);
    assert_eq!(tree.root(), root);
    for (key, leaf, want) in &checks {
        assert_eq!(&tree.proof(key), want);
        assert!(want.verify(&root, key, leaf));
        // The wrong leaf, the wrong key, and a dropped sibling all fail.
        assert!(!want.verify(&root, key, &Hash([1; 32])));
        let other = checks.iter().find(|c| c.0 != *key).unwrap();
        assert!(!want.verify(&root, &other.0, leaf));
        let mut short = want.clone();
        short.siblings.pop();
        assert_eq!(short.root(key, leaf), None);
    }
    // Absent key: its proof shows E[0] under the same root, and the tree without a leaf differs.
    let absent = AccountLeaf {
        account: 999,
        ..accounts(&v)[0]
    }
    .key();
    assert!(tree.proof(&absent).verify(&root, &absent, &smt::empty(0)));
    tree.insert(checks[0].0, smt::empty(0));
    assert_ne!(tree.root(), root);
}

#[test]
fn smt_27_sibling_proofs() {
    let v = load("smt.json");
    let b0 = balances(&v)[0];
    let a0 = accounts(&v)[0];
    let p27 = v.get("proof27");
    let p = proof_of(p27);
    assert_eq!(p.siblings.len(), 27);
    assert!(p.verify(&p27.get("root").h(), &b0.key(), &b0.leaf_hash()));
    let e27 = v.get("escape27");
    let root = e27.get("root").h();
    assert!(proof_of(e27.get("account")).verify(&root, &a0.key(), &a0.leaf_hash()));
    assert!(proof_of(e27.get("balance")).verify(&root, &b0.key(), &b0.leaf_hash()));
    assert_eq!(
        b0.escape_amount(),
        Some(b0.free + b0.alloc_sum + b0.transit + b0.pending_unposted)
    );
}

// ---- bridge: post building and the guardian, through the Replica and Epochs traits ----

struct FakeReplica {
    checkpoints: Vec<Checkpoint>,
    posts: BTreeMap<u64, [u8; 32]>,
}
impl Replica for FakeReplica {
    fn checkpoint(&self, commit: &Hash) -> Option<Checkpoint> {
        self.checkpoints
            .iter()
            .find(|c| c.commit == *commit)
            .cloned()
    }
    fn post_hash(&self, post_no: u64) -> Option<[u8; 32]> {
        self.posts.get(&post_no).copied()
    }
}
struct FakeEpochs(SignerSet);
impl Epochs for FakeEpochs {
    fn bridge_signers(&self, rotation_no: u64) -> Option<SignerSet> {
        (rotation_no == self.0.rotation_no).then_some(self.0)
    }
}

#[test]
fn post1_rebuilds_from_its_checkpoint_and_guardian_accepts() {
    let e = load("eip712.json");
    let wd = load("wdtree.json");
    let sm = load("smt.json");
    let vec = &e.get("vectors").arr()[0];
    let m = vec.get("message");
    let ws = withdrawals(&wd);
    let assets = [ws[0].token, ws[1].token];
    let cp = Checkpoint {
        commit: m.get("commit").h(),
        smt_root: sm.get("root").h(),
        deposit_nonce: 3,
        withdrawals: ws.clone(),
    };
    let post = build_post(7, 1, [0; 32], &cp, &assets).unwrap();
    assert_eq!(post, post_of(m));
    assert_eq!(post.struct_hash(), vec.get("structHash").b32());

    // Post 2 chains from post 1 and carries no withdrawals: zero root, zero totals.
    let m2 = e.get("vectors").arr()[1].get("message");
    let cp2 = Checkpoint {
        commit: m2.get("commit").h(),
        smt_root: sm.get("proof27").get("root").h(),
        deposit_nonce: 3,
        withdrawals: Vec::new(),
    };
    let post2 = build_post(7, 2, post.struct_hash(), &cp2, &assets).unwrap();
    assert_eq!(post2, post_of(m2));

    let canonical = BTreeMap::from([(1, post.struct_hash()), (2, post2.struct_hash())]);
    let replica = FakeReplica {
        checkpoints: vec![cp.clone(), cp2.clone()],
        posts: canonical.clone(),
    };
    let epochs = FakeEpochs(SignerSet {
        rotation_no: 0,
        bridge_keys: keys5(e.get("bridgeKeys")),
        guardian_keys: keys5(e.get("guardianKeys")),
    });
    let guardian = |replica| Guardian {
        replica,
        epochs: &epochs,
        domain: domain(&e),
        chain_id: 7,
        assets: &assets,
    };
    let g = guardian(&replica);
    let secrets: Vec<[u8; 32]> = e.get("bridgeKeyPrivate").arr().iter().map(J::b32).collect();
    // Signatures by BK_0..BK_3 over `p`: four stolen keys.
    let four = |p: &Post| -> Vec<[u8; 65]> {
        let digest = domain(&e).digest(&p.struct_hash());
        secrets[..4]
            .iter()
            .map(|s| eip712::sign(&digest, s).unwrap())
            .collect()
    };
    let veto = |reason| Verdict::Veto {
        reason,
        signers: 0b1111,
    };

    let sigs: Vec<Vec<u8>> = vec.get("signatures").arr().iter().map(J::bytes).collect();
    assert_eq!(g.review(0, &post, &sigs), Verdict::Accept);
    assert_eq!(g.review(0, &post2, &four(&post2)), Verdict::Accept);
    assert_eq!(g.review(1, &post, &sigs), Verdict::UnknownSignerSet);
    assert_eq!(
        g.review(0, &post, &sigs[..3]),
        Verdict::Ignore(SigError::NotEnoughSignatures)
    );

    // A post that moves one withdrawal to another recipient.
    let mut forged_cp = cp.clone();
    forged_cp.withdrawals[0].recipient = [0xee; 20];
    let forged = build_post(7, 1, [0; 32], &forged_cp, &assets).unwrap();
    assert_eq!(
        g.review(0, &forged, &four(&forged)),
        veto(VetoReason::NotCanonical)
    );
    // An older finalized checkpoint reposted under the next number: well formed and chained to
    // post 1, and still not the chain's post 2.
    let replay = build_post(7, 2, post.struct_hash(), &cp, &assets).unwrap();
    assert_eq!(
        g.review(0, &replay, &four(&replay)),
        veto(VetoReason::NotCanonical)
    );
    // A number the chain has not reached.
    let mut ahead = post2.clone();
    ahead.post_no = 3;
    assert_eq!(
        g.review(0, &ahead, &four(&ahead)),
        veto(VetoReason::UnknownPost)
    );

    // The recompute still runs when the replica's post record and its checkpoints disagree.
    let no_cp = FakeReplica {
        checkpoints: Vec::new(),
        posts: canonical.clone(),
    };
    assert_eq!(
        guardian(&no_cp).review(0, &post, &four(&post)),
        veto(VetoReason::UnknownCommit)
    );
    let no_prev = FakeReplica {
        checkpoints: vec![cp2],
        posts: BTreeMap::from([(2, post2.struct_hash())]),
    };
    assert_eq!(
        guardian(&no_prev).review(0, &post2, &four(&post2)),
        veto(VetoReason::UnknownPrev)
    );
    let bad_record = FakeReplica {
        checkpoints: vec![cp],
        posts: BTreeMap::from([(1, forged.struct_hash())]),
    };
    assert_eq!(
        guardian(&bad_record).review(0, &forged, &four(&forged)),
        veto(VetoReason::Differs)
    );
}
