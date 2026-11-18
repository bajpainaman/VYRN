//! A JSON reader for the golden vectors' JSON form (tests/golden/README.md), shared by
//! the tests of `vyrn-lane`, `vyrn-sim`, `vyrn-data`, `vyrn-admin` and `vyrn-log`. *Reading:* `serde_json` is not on the 11 §2.2
//! allowlist and engine crates take no new dev-dependencies, so this accepts only the subset
//! the generators print: objects, arrays, ASCII strings (`json.dumps` escapes the rest as
//! `\uXXXX`) and integers.
#![allow(dead_code)]

use std::path::Path;

#[derive(Debug)]
pub enum J {
    Int(i128),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn get(&self, k: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn at(&self, k: &str) -> &J {
        self.get(k)
            .unwrap_or_else(|| panic!("no field {k} in {self:?}"))
    }
    pub fn s(&self, k: &str) -> &str {
        match self.at(k) {
            J::Str(s) => s,
            v => panic!("{k} is not a string: {v:?}"),
        }
    }
    pub fn n(&self, k: &str) -> i128 {
        match self.at(k) {
            J::Int(n) => *n,
            v => panic!("{k} is not an integer: {v:?}"),
        }
    }
    pub fn arr(&self, k: &str) -> &[J] {
        match self.at(k) {
            J::Arr(a) => a,
            v => panic!("{k} is not an array: {v:?}"),
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            J::Str(s) => s,
            v => panic!("not a string: {v:?}"),
        }
    }
}

pub fn parse(text: &str) -> J {
    fn ws(b: &[u8], i: &mut usize) {
        while b.get(*i).is_some_and(u8::is_ascii_whitespace) {
            *i += 1;
        }
    }
    fn val(b: &[u8], i: &mut usize) -> J {
        ws(b, i);
        match b[*i] {
            b'{' | b'[' => {
                let obj = b[*i] == b'{';
                *i += 1;
                let (mut m, mut a) = (Vec::new(), Vec::new());
                loop {
                    ws(b, i);
                    if b[*i] == b'}' || b[*i] == b']' {
                        *i += 1;
                        break;
                    }
                    if obj {
                        let J::Str(k) = val(b, i) else { panic!("key") };
                        ws(b, i);
                        assert_eq!(b[*i], b':');
                        *i += 1;
                        m.push((k, val(b, i)));
                    } else {
                        a.push(val(b, i));
                    }
                    ws(b, i);
                    if b[*i] == b',' {
                        *i += 1;
                    }
                }
                if obj { J::Obj(m) } else { J::Arr(a) }
            }
            b'"' => {
                *i += 1;
                let mut s = String::new();
                while b[*i] != b'"' {
                    if b[*i] == b'\\' {
                        *i += 1;
                        match b[*i] {
                            b'"' | b'\\' => s.push(char::from(b[*i])),
                            // `json.dumps` writes non-ASCII as \uXXXX (BMP only here).
                            b'u' => {
                                let h = std::str::from_utf8(&b[*i + 1..*i + 5]).unwrap();
                                s.push(
                                    char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap(),
                                );
                                *i += 4;
                            }
                            e => panic!("unsupported escape \\{}", char::from(e)),
                        }
                    } else {
                        s.push(char::from(b[*i]));
                    }
                    *i += 1;
                }
                *i += 1;
                J::Str(s)
            }
            _ => {
                let start = *i;
                while b.get(*i).is_some_and(|c| c.is_ascii_digit() || *c == b'-') {
                    *i += 1;
                }
                J::Int(std::str::from_utf8(&b[start..*i]).unwrap().parse().unwrap())
            }
        }
    }
    let mut i = 0;
    let v = val(text.as_bytes(), &mut i);
    ws(text.as_bytes(), &mut i);
    assert_eq!(i, text.len(), "trailing bytes");
    v
}

/// `tests/golden/<name>`, found from the calling crate's directory upwards.
pub fn load(manifest_dir: &str, name: &str) -> J {
    let dir = Path::new(manifest_dir)
        .ancestors()
        .map(|a| a.join("tests/golden"))
        .find(|d| d.join(name).exists())
        .unwrap_or_else(|| panic!("tests/golden/{name} not found above {manifest_dir}"));
    parse(&std::fs::read_to_string(dir.join(name)).unwrap())
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
