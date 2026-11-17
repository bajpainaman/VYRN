//! The fast-path frame (06 §6.2): Ethernet II, IPv4 with IHL 5 and no options, UDP. No VLAN tag,
//! 42 bytes of headers. `build` sets DF, TTL 64 and a zero UDP checksum; `parse` reads fixed
//! offsets and rejects every frame the fast path drops.
//!
//! Standards reused: Ethernet II framing (IEEE 802.3), IPv4 (RFC 791) with the header checksum
//! of RFC 1071, UDP (RFC 768, which allows a zero checksum over IPv4).

use core::net::Ipv4Addr;

/// `PLT_FRAME_HDR_BYTES`: Ethernet (14) + IPv4 (20) + UDP (8).
pub const HDR_BYTES: usize = 42;
/// The largest frame without FCS on a 1500-byte MTU.
pub const MAX_FRAME_BYTES: usize = 1514;
/// The largest UDP payload a fast-path frame carries.
pub const MAX_PAYLOAD: usize = MAX_FRAME_BYTES - HDR_BYTES;
/// The shortest Ethernet frame without FCS; shorter frames are padded up to it on the wire.
pub const MIN_FRAME_BYTES: usize = 60;

const ETH_HDR: usize = 14;
const IP_HDR: usize = 20;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const IP_PROTO_UDP: u8 = 17;
const IP_FLAG_MF: u16 = 0x2000;
const IP_FLAG_DF: u16 = 0x4000;
const IP_FRAG_OFFSET: u16 = 0x1FFF;
const TTL: u8 = 64;

/// One end of a fast-path frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Endpoint {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// The fields of the 42 header bytes that vary between frames.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameHdr {
    pub src: Endpoint,
    pub dst: Endpoint,
}

/// A frame `parse` accepted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Parsed<'a> {
    pub hdr: FrameHdr,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuildError {
    /// The payload is over `MAX_PAYLOAD`.
    PayloadTooLong,
    /// The output buffer is shorter than `HDR_BYTES` plus the payload.
    BufferTooShort,
}

/// Why `parse` dropped a frame (06 §6.2: dropped and counted before any MAC check).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// Shorter than `HDR_BYTES`, or longer than `MAX_FRAME_BYTES`.
    Length,
    /// An 802.1Q or 802.1ad tag.
    Vlan,
    /// An EtherType other than IPv4.
    NotIpv4,
    /// IP version other than 4, or IHL other than 5 (options).
    IpHeader,
    /// More-fragments set or a nonzero fragment offset.
    Fragment,
    NotUdp,
    /// The IPv4 total length disagrees with the frame length.
    IpLength,
    /// The UDP length disagrees with the IPv4 length.
    UdpLength,
    IpChecksum,
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The RFC 1071 checksum of an IPv4 header: zero when computed over a header that already holds
/// its correct checksum.
pub fn ipv4_checksum(hdr: &[u8; IP_HDR]) -> u16 {
    let (words, _) = hdr.as_chunks::<2>();
    let mut sum: u32 = words
        .iter()
        .map(|w| u32::from(u16::from_be_bytes(*w)))
        .sum();
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Writes the 42 header bytes of a frame carrying `payload_len` bytes.
pub fn write_header(
    hdr: &FrameHdr,
    payload_len: usize,
    out: &mut [u8; HDR_BYTES],
) -> Result<(), BuildError> {
    if payload_len > MAX_PAYLOAD {
        return Err(BuildError::PayloadTooLong);
    }
    // MAX_PAYLOAD + 28 fits in u16.
    let ip_len = (payload_len + IP_HDR + 8) as u16;
    out[0..6].copy_from_slice(&hdr.dst.mac);
    out[6..12].copy_from_slice(&hdr.src.mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    let mut ip = [0u8; IP_HDR];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    // Identification 0: DF is set, so no fragment is ever reassembled from it.
    ip[6..8].copy_from_slice(&IP_FLAG_DF.to_be_bytes());
    ip[8] = TTL;
    ip[9] = IP_PROTO_UDP;
    ip[12..16].copy_from_slice(&hdr.src.ip.octets());
    ip[16..20].copy_from_slice(&hdr.dst.ip.octets());
    let csum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    out[ETH_HDR..ETH_HDR + IP_HDR].copy_from_slice(&ip);
    let udp = &mut out[ETH_HDR + IP_HDR..];
    udp[0..2].copy_from_slice(&hdr.src.port.to_be_bytes());
    udp[2..4].copy_from_slice(&hdr.dst.port.to_be_bytes());
    udp[4..6].copy_from_slice(&(ip_len - IP_HDR as u16).to_be_bytes());
    // UDP checksum 0: IPv4 allows it, and the packet MACs authenticate the payload (06 §6.2).
    udp[6..8].copy_from_slice(&[0, 0]);
    Ok(())
}

/// Writes a whole frame into `out` and returns its length. Frames under `MIN_FRAME_BYTES` are
/// not padded; the NIC pads them on the wire.
pub fn build(hdr: &FrameHdr, payload: &[u8], out: &mut [u8]) -> Result<usize, BuildError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(BuildError::PayloadTooLong);
    }
    let len = HDR_BYTES + payload.len();
    let Some(out) = out.get_mut(..len) else {
        return Err(BuildError::BufferTooShort);
    };
    let (head, body) = out.split_at_mut(HDR_BYTES);
    let head: &mut [u8; HDR_BYTES] = head.try_into().map_err(|_| BuildError::BufferTooShort)?;
    write_header(hdr, payload.len(), head)?;
    body.copy_from_slice(payload);
    Ok(len)
}

/// Reads a fast-path frame. A frame of exactly `MIN_FRAME_BYTES` may carry Ethernet padding
/// after the IPv4 packet; any other length must match the IPv4 total length exactly.
pub fn parse(frame: &[u8]) -> Result<Parsed<'_>, ParseError> {
    if frame.len() < HDR_BYTES || frame.len() > MAX_FRAME_BYTES {
        return Err(ParseError::Length);
    }
    match be16(frame, 12) {
        ETHERTYPE_IPV4 => {}
        ETHERTYPE_VLAN | ETHERTYPE_QINQ => return Err(ParseError::Vlan),
        _ => return Err(ParseError::NotIpv4),
    }
    let ip: &[u8; IP_HDR] = frame[ETH_HDR..ETH_HDR + IP_HDR]
        .try_into()
        .map_err(|_| ParseError::Length)?;
    if ip[0] != 0x45 {
        return Err(ParseError::IpHeader);
    }
    let frag = be16(ip, 6);
    if frag & (IP_FLAG_MF | IP_FRAG_OFFSET) != 0 {
        return Err(ParseError::Fragment);
    }
    if ip[9] != IP_PROTO_UDP {
        return Err(ParseError::NotUdp);
    }
    let ip_len = usize::from(be16(ip, 2));
    let carried = frame.len() - ETH_HDR;
    let padded = frame.len() == MIN_FRAME_BYTES && ip_len < carried;
    if ip_len < IP_HDR + 8 || (ip_len != carried && !padded) {
        return Err(ParseError::IpLength);
    }
    if ipv4_checksum(ip) != 0 {
        return Err(ParseError::IpChecksum);
    }
    let udp = &frame[ETH_HDR + IP_HDR..];
    if usize::from(be16(udp, 4)) != ip_len - IP_HDR {
        return Err(ParseError::UdpLength);
    }
    let mac = |at: usize| -> [u8; 6] { frame[at..at + 6].try_into().unwrap_or([0; 6]) };
    let addr = |at: usize| Ipv4Addr::new(ip[at], ip[at + 1], ip[at + 2], ip[at + 3]);
    Ok(Parsed {
        hdr: FrameHdr {
            src: Endpoint {
                mac: mac(6),
                ip: addr(12),
                port: be16(udp, 0),
            },
            dst: Endpoint {
                mac: mac(0),
                ip: addr(16),
                port: be16(udp, 2),
            },
        },
        payload: &frame[HDR_BYTES..ETH_HDR + ip_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr() -> FrameHdr {
        FrameHdr {
            src: Endpoint {
                mac: [2, 0, 0, 0, 0, 1],
                ip: Ipv4Addr::new(192, 168, 0, 1),
                port: 40000,
            },
            dst: Endpoint {
                mac: [2, 0, 0, 0, 0, 2],
                ip: Ipv4Addr::new(192, 168, 0, 199),
                port: 20007,
            },
        }
    }

    fn frame(payload_len: usize) -> Vec<u8> {
        let payload: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();
        let mut out = vec![0; HDR_BYTES + payload_len];
        assert_eq!(build(&hdr(), &payload, &mut out), Ok(out.len()));
        out
    }

    /// Rewrites the IPv4 checksum after a test edits the header.
    fn fix_csum(f: &mut [u8]) {
        f[24..26].fill(0);
        let ip: [u8; 20] = f[14..34].try_into().unwrap();
        f[24..26].copy_from_slice(&ipv4_checksum(&ip).to_be_bytes());
    }

    #[test]
    fn ip_header_matches_a_published_vector() {
        // The worked example of the IPv4 header checksum on Wikipedia ("Internet checksum"):
        // 192.168.0.1 -> 192.168.0.199, total length 0x73, DF, TTL 64, UDP; checksum 0xB861.
        let f = frame(0x73 - 28);
        let want = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xB8, 0x61, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ];
        assert_eq!(f[14..34], want);
        // Ethernet: dst MAC, src MAC, IPv4. UDP: ports, length 0x73 - 20, checksum 0.
        assert_eq!(f[0..14], [2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        assert_eq!(f[34..42], [0x9C, 0x40, 0x4E, 0x27, 0x00, 0x5F, 0, 0]);
    }

    #[test]
    fn round_trip() {
        for len in [0, 1, 18, 192, MAX_PAYLOAD] {
            let f = frame(len);
            let p = parse(&f).unwrap();
            assert_eq!(p.hdr, hdr());
            assert_eq!(p.payload.len(), len);
            assert!(p.payload.iter().enumerate().all(|(i, &b)| b == i as u8));
        }
    }

    #[test]
    fn build_rejects_what_it_cannot_write() {
        let mut out = [0u8; MAX_FRAME_BYTES + 1];
        assert_eq!(
            build(&hdr(), &[0; MAX_PAYLOAD + 1], &mut out),
            Err(BuildError::PayloadTooLong)
        );
        assert_eq!(
            build(&hdr(), &[0; 10], &mut [0; HDR_BYTES + 9]),
            Err(BuildError::BufferTooShort)
        );
        assert_eq!(build(&hdr(), &[0; 10], &mut [0; 100]), Ok(52));
    }

    #[test]
    fn ethernet_padding_is_accepted_only_at_the_minimum_length() {
        let mut f = frame(4); // 46 bytes
        f.resize(MIN_FRAME_BYTES, 0);
        assert_eq!(parse(&f).unwrap().payload, [0, 1, 2, 3]);
        f.push(0);
        assert_eq!(parse(&f), Err(ParseError::IpLength));
        let mut f = frame(4);
        f.resize(MIN_FRAME_BYTES - 1, 0);
        assert_eq!(parse(&f), Err(ParseError::IpLength));
    }

    #[test]
    fn malformed_frames_are_rejected() {
        type Edit = fn(&mut Vec<u8>);
        let cases: [(&str, Edit, ParseError); 12] = [
            (
                "vlan",
                |f| f[12..14].copy_from_slice(&[0x81, 0x00]),
                ParseError::Vlan,
            ),
            (
                "qinq",
                |f| f[12..14].copy_from_slice(&[0x88, 0xA8]),
                ParseError::Vlan,
            ),
            (
                "arp",
                |f| f[12..14].copy_from_slice(&[0x08, 0x06]),
                ParseError::NotIpv4,
            ),
            ("ipv6 version", |f| f[14] = 0x65, ParseError::IpHeader),
            ("ip options", |f| f[14] = 0x46, ParseError::IpHeader),
            ("more fragments", |f| f[20] |= 0x20, ParseError::Fragment),
            ("fragment offset", |f| f[21] = 1, ParseError::Fragment),
            ("tcp", |f| f[23] = 6, ParseError::NotUdp),
            ("ip length short", |f| f[17] -= 1, ParseError::IpLength),
            ("trailing byte", |f| f.push(0), ParseError::IpLength),
            ("udp length", |f| f[39] += 1, ParseError::UdpLength),
            ("ip checksum", |f| f[25] ^= 1, ParseError::IpChecksum),
        ];
        for (name, edit, want) in cases {
            let mut f = frame(100);
            edit(&mut f);
            if !matches!(name, "ip checksum" | "trailing byte") && f[12..14] == [8, 0] {
                fix_csum(&mut f); // so the check under test, not the checksum, rejects it
            }
            assert_eq!(parse(&f), Err(want), "{name}");
        }
    }

    #[test]
    fn every_truncation_and_oversize_is_rejected() {
        let f = frame(200);
        for len in 0..f.len() {
            assert!(parse(&f[..len]).is_err(), "prefix {len}");
        }
        let mut big = frame(MAX_PAYLOAD);
        big.push(0);
        assert_eq!(parse(&big), Err(ParseError::Length));
    }
}
