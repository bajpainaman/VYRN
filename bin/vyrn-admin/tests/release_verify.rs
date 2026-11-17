//! Conformance suite for deploy/release/MANIFEST.md, run against `vyrn-admin release verify`.
//! The signing seeds are the public RFC 8032 §7.1 test vectors, never release keys.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SEED_1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const SEED_2: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const SEED_3: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";

fn seed(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Bundle {
    dir: PathBuf,
    keys: PathBuf,
}

impl Bundle {
    /// A two-file workspace bundle, unsigned, with keys a and b trusted.
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("release-verify-{name}"));
        let _ = fs::remove_dir_all(&root);
        let dir = root.join("bundle");
        fs::create_dir_all(&dir).unwrap();
        let files = [
            (
                "vyrn-seq.x86_64-unknown-linux-gnu",
                b"\x7fELF seq".as_slice(),
            ),
            ("CHANGELOG.md", b"# v0.1.0\n".as_slice()),
        ];
        let mut manifest = String::from(
            "manifest_version = 1\nkind = \"workspace\"\nname = \"vyrn\"\nversion = \"0.1.0\"\n\
             tag = \"v0.1.0\"\ncommit = \"e54c379a6b1c2d3e4f5061728394a5b6c7d8e9f0\"\n\
             source_date_epoch = 1763416800\nprotocol_version = 1\nconfig_schema_version = 0\n\n\
             [[crate]]\nname = \"vyrn-wire\"\nversion = \"0.1.0\"\n",
        );
        for (path, bytes) in files {
            fs::write(dir.join(path), bytes).unwrap();
            let hash = hex(&vyrn_crypto::hash::hash(bytes).0);
            manifest.push_str(&format!(
                "\n[[file]]\npath = \"{path}\"\nsize = {}\nblake3 = \"{hash}\"\n",
                bytes.len()
            ));
        }
        fs::write(dir.join("manifest.toml"), manifest).unwrap();
        let keys = root.join("keys.toml");
        fs::write(
            &keys,
            format!(
                "[[key]]\nid = \"a\"\ned25519 = \"{}\"\n\n[[key]]\nid = \"b\"\ned25519 = \"{}\"\n",
                hex(&vyrn_crypto::ed25519::public_key(&seed(SEED_1))),
                hex(&vyrn_crypto::ed25519::public_key(&seed(SEED_2))),
            ),
        )
        .unwrap();
        Bundle { dir, keys }
    }

    fn sign(&self, id: &str, seed_hex: &str) -> &Self {
        let manifest = fs::read(self.dir.join("manifest.toml")).unwrap();
        let sig = vyrn_crypto::ed25519::sign(&seed(seed_hex), &manifest);
        fs::write(
            self.dir.join(format!("manifest.toml.{id}.sig")),
            hex(&sig) + "\n",
        )
        .unwrap();
        self
    }

    fn verify(&self) -> (bool, String) {
        let keys = self.keys.to_str().unwrap();
        self.run(&["--keys", keys])
    }

    fn run(&self, trust: &[&str]) -> (bool, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_vyrn-admin"))
            .args(["release", "verify"])
            .arg(&self.dir)
            .args(trust)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.success(), text)
    }

    fn edit_manifest(&self, from: &str, to: &str) {
        let path = self.dir.join("manifest.toml");
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(from));
        fs::write(path, text.replacen(from, to, 1)).unwrap();
    }
}

#[test]
fn two_trusted_signatures_and_matching_hashes_verify() {
    let b = Bundle::new("good");
    b.sign("a", SEED_1).sign("b", SEED_2);
    let (ok, out) = b.verify();
    assert!(ok, "{out}");
    assert!(
        out.contains("verified v0.1.0") && out.contains("signed by a, b"),
        "{out}"
    );
}

#[test]
fn a_tampered_file_is_rejected_even_with_valid_signatures() {
    let b = Bundle::new("tampered");
    b.sign("a", SEED_1).sign("b", SEED_2);
    // Same size, one byte changed: only the hash can catch it.
    fs::write(
        b.dir.join("vyrn-seq.x86_64-unknown-linux-gnu"),
        b"\x7fELF sEq",
    )
    .unwrap();
    let (ok, out) = b.verify();
    assert!(
        !ok && out.contains("vyrn-seq.x86_64-unknown-linux-gnu: BLAKE3"),
        "{out}"
    );
}

#[test]
fn one_signature_is_not_enough() {
    let b = Bundle::new("one-sig");
    b.sign("a", SEED_1);
    let (ok, out) = b.verify();
    assert!(
        !ok && out.contains("1 valid signature(s); a release needs 2"),
        "{out}"
    );
}

#[test]
fn a_signature_over_another_manifest_is_rejected() {
    let b = Bundle::new("resigned");
    b.sign("a", SEED_1).sign("b", SEED_2);
    // Re-point the release at another commit after signing.
    b.edit_manifest("e54c379a", "e54c379b");
    let (ok, out) = b.verify();
    assert!(!ok && out.contains("signature does not verify"), "{out}");
}

#[test]
fn an_untrusted_signer_fails_the_bundle() {
    let b = Bundle::new("untrusted");
    b.sign("a", SEED_1).sign("b", SEED_2).sign("c", SEED_3);
    let (ok, out) = b.verify();
    assert!(!ok && out.contains("key \"c\" is not trusted"), "{out}");
}

#[test]
fn an_unlisted_file_is_rejected() {
    let b = Bundle::new("unlisted");
    fs::write(b.dir.join("extra.so"), b"x").unwrap();
    let (ok, out) = b.run(&["--unsigned"]);
    assert!(
        !ok && out.contains("extra.so is in the bundle but not in the manifest"),
        "{out}"
    );
}

#[test]
fn unsigned_mode_checks_hashes_and_says_unsigned() {
    let b = Bundle::new("unsigned");
    let (ok, out) = b.run(&["--unsigned"]);
    assert!(ok && out.contains("UNSIGNED"), "{out}");
    fs::write(b.dir.join("CHANGELOG.md"), b"# v0.1.1\n").unwrap();
    assert!(!b.run(&["--unsigned"]).0);
}

#[test]
fn an_unknown_format_or_field_is_rejected() {
    let b = Bundle::new("format");
    b.edit_manifest("manifest_version = 1", "manifest_version = 2");
    let (ok, out) = b.run(&["--unsigned"]);
    assert!(
        !ok && out.contains("manifest_version 2 is not supported"),
        "{out}"
    );

    let b = Bundle::new("field");
    b.edit_manifest(
        "protocol_version = 1",
        "protocol_version = 1\nbuilder = \"ci\"",
    );
    let (ok, out) = b.run(&["--unsigned"]);
    assert!(!ok && out.contains("unknown field"), "{out}");
}

#[test]
fn a_path_outside_the_bundle_is_rejected() {
    let b = Bundle::new("escape");
    b.edit_manifest("path = \"CHANGELOG.md\"", "path = \"../keys.toml\"");
    let (ok, out) = b.run(&["--unsigned"]);
    assert!(!ok && out.contains("is not a bundle file name"), "{out}");
}

#[test]
fn one_key_trusted_under_two_ids_is_rejected() {
    let b = Bundle::new("dup-key");
    let public = hex(&vyrn_crypto::ed25519::public_key(&seed(SEED_1)));
    fs::write(
        &b.keys,
        format!("[[key]]\nid = \"a\"\ned25519 = \"{public}\"\n\n[[key]]\nid = \"b\"\ned25519 = \"{public}\"\n"),
    )
    .unwrap();
    // The same signature under both ids would otherwise count twice.
    b.sign("a", SEED_1).sign("b", SEED_1);
    let (ok, out) = b.verify();
    assert!(
        !ok && out.contains("the same public key is trusted twice"),
        "{out}"
    );
}
