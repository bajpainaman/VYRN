//! Checks the statement leaf and tree against `dc_stmt_vectors.txt`, which
//! `gen_dc_stmt_vectors.py` wrote from spec 10 §10 with no Rust involved:
//! `python3 -I crates/vyrn-md/tests/gen_dc_stmt_vectors.py crates/vyrn-md/tests`.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeMap;

use vyrn_md::dropcopy::statement::{Section, Statement, StmtTree};
use vyrn_md::dropcopy::{DC_REC_BYTES, DcRecord};
use vyrn_types::{AccountId, BookId, Hash};

const VECTORS: &str = include_str!("dc_stmt_vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hash(s: &str) -> Hash {
    Hash(unhex(s).try_into().unwrap())
}

#[test]
fn statement_tree_matches_the_published_vectors() {
    let mut sections = Vec::new();
    let mut by: BTreeMap<u32, Vec<Section>> = BTreeMap::new();
    let mut leaves = Vec::new();
    let mut root = None;
    let mut proofs = Vec::new();
    let mut empty = None;
    for l in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let w: Vec<&str> = l.split(' ').collect();
        match w[0] {
            "eod" => {
                let recs: [DcRecord; 4] = w[3..7]
                    .iter()
                    .map(|h| {
                        let b: [u8; DC_REC_BYTES] = unhex(h).try_into().unwrap();
                        DcRecord::decode(&b).unwrap()
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let s = Section::from_eod(BookId(w[2].parse().unwrap()), recs).unwrap();
                by.entry(w[1].parse().unwrap()).or_default().push(s);
                sections.push(s);
            }
            "leaf" => leaves.push((w[1].parse::<u32>().unwrap(), unhex(w[2]), hash(w[3]))),
            "root" => root = Some(hash(w[1])),
            "proof" => proofs.push((w[1].parse::<u32>().unwrap(), w[2].to_owned())),
            "empty" => empty = Some(hash(w[1])),
            x => panic!("unknown line {x}"),
        }
    }
    let tree = StmtTree::build(sections).unwrap();
    assert_eq!(Some(tree.root()), root, "ACC_STMT_ROOT");
    for (a, bytes, h) in &leaves {
        let st = Statement {
            account: AccountId(*a),
            sections: by[a].clone(),
        };
        assert_eq!(&st.leaf_bytes(), bytes, "leaf bytes of {a}");
        assert_eq!(st.leaf_hash(), *h, "leaf hash of {a}");
    }
    for (a, want) in &proofs {
        let p = tree.proof(AccountId(*a)).unwrap();
        let got: Vec<String> = p
            .siblings
            .iter()
            .map(|(r, h)| format!("{}{}", if *r { 'R' } else { 'L' }, hex(&h.0)))
            .collect();
        let got = if got.is_empty() {
            "-".to_owned()
        } else {
            got.join(",")
        };
        assert_eq!(&got, want, "proof of {a}");
        let (_, _, leaf) = leaves.iter().find(|x| x.0 == *a).unwrap();
        assert!(p.verify(*leaf, tree.root()));
    }
    assert_eq!(
        Some(StmtTree::build(Vec::new()).unwrap().root()),
        empty,
        "empty tree"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
