//! Checks `frame::parse` against `frame_vectors.txt`, which an independent Python script wrote
//! (no Rust involved), so any implementation of 06 §6.2 can use the same file.

use vyrn_nic::frame;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn parse_matches_the_published_vectors() {
    let file = include_str!("frame_vectors.txt");
    let mut n = 0;
    for line in file
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, bytes, want) = (f[0], unhex(f[1]), (f[2], f[3]));
        let got = match frame::parse(&bytes) {
            Ok(p) => ("ok".to_string(), p.payload.len().to_string()),
            Err(e) => ("err".to_string(), format!("{e:?}")),
        };
        assert_eq!((got.0.as_str(), got.1.as_str()), want, "{name}");
        n += 1;
    }
    assert_eq!(n, 13);
}
