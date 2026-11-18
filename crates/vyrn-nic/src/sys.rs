//! `vyrn-nic::sys` (UNSAFE.toml). Every `unsafe` block needs a `// SAFETY:` comment.
//!
//! Linux `recvmmsg`/`sendmmsg` for `kernel_udp` (06 §6.6): one syscall per burst of up to `BATCH`
//! IPv4 datagrams. The message headers live on the caller's stack for the one call, so nothing
//! here holds a raw pointer past its return. Other targets use std's sockets and need none of it.
//! `set_pktinfo` and `Recvd::dst` let a wildcard-bound socket learn each datagram's destination.

#[cfg(target_os = "linux")]
pub(crate) use linux::*;

/// Pins the calling thread to CPU `cpu` (`sched_setaffinity`, 11 §3.6); refused off Linux.
pub fn pin_current_thread(cpu: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if cpu < libc::CPU_SETSIZE as usize {
        // SAFETY: zeroed is the empty set; CPU_SET writes bit cpu < CPU_SETSIZE of the live set.
        let rc = unsafe {
            let mut set: libc::cpu_set_t = core::mem::zeroed();
            libc::CPU_SET(cpu, &mut set);
            libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set)
        };
        return (rc == 0)
            .then_some(())
            .ok_or_else(std::io::Error::last_os_error);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no such cpu here",
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    use core::mem;
    use core::net::{Ipv4Addr, SocketAddrV4};
    use std::io;
    use std::os::fd::RawFd;

    const PKTINFO_BYTES: u32 = mem::size_of::<libc::in_pktinfo>() as u32;

    /// The most datagrams one call moves: `RX_BURST`, the most frames one `poll` returns.
    pub(crate) const BATCH: usize = vyrn_wire::RX_BURST;

    /// Bytes of ancillary data each received message has room for: one `IP_PKTINFO` message,
    /// the only one a socket of this crate asks for (`set_pktinfo`). Sockets that do not ask get
    /// none and leave it unused.
    // SAFETY: CMSG_SPACE is arithmetic on its argument and touches no memory.
    const CTRL_BYTES: usize = unsafe { libc::CMSG_SPACE(PKTINFO_BYTES) } as usize;

    /// One message's control buffer, aligned for `cmsghdr`.
    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    struct Ctrl([u8; CTRL_BYTES]);

    /// What `recv_batch` learned about one received datagram.
    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct Recvd {
        /// Bytes written to the message's buffer.
        pub(crate) len: usize,
        /// The datagram was longer than its buffer (`MSG_TRUNC`), so `len` is not its size.
        pub(crate) trunc: bool,
        /// The sender, or `None` when the kernel named no IPv4 address.
        pub(crate) src: Option<SocketAddrV4>,
        /// `in_pktinfo.ipi_addr`, the destination address in the datagram's IP header, or `None`
        /// when its `IP_PKTINFO` message is missing or cut short (`MSG_CTRUNC`).
        pub(crate) dst: Option<Ipv4Addr>,
    }

    /// Asks the kernel for an `IP_PKTINFO` control message on every datagram `fd` receives.
    pub(crate) fn set_pktinfo(fd: RawFd) -> io::Result<()> {
        let on: libc::c_int = 1;
        let len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        let opt = (&raw const on).cast();
        // SAFETY: `opt` points at a live c_int and `len` is its size, so the kernel reads only it.
        let rc = unsafe { libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, opt, len) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `ipi_addr` of the `IP_PKTINFO` message `recvmmsg` left in `m`'s control buffer.
    fn pktinfo_dst(m: &libc::msghdr) -> Option<Ipv4Addr> {
        if m.msg_flags & libc::MSG_CTRUNC != 0 {
            return None;
        }
        // SAFETY: CMSG_LEN is arithmetic on its argument and touches no memory.
        let need = unsafe { libc::CMSG_LEN(PKTINFO_BYTES) } as usize;
        // SAFETY: `m`'s control buffer is live (its `Ctrl` outlives this call) and the kernel set
        // `msg_controllen` to the bytes it wrote there; CMSG_FIRSTHDR checks it.
        let mut c = unsafe { libc::CMSG_FIRSTHDR(m) };
        while !c.is_null() {
            // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR give null or a header inside the buffer, which
            // `Ctrl` aligns for cmsghdr.
            let h = unsafe { &*c };
            if (h.cmsg_level, h.cmsg_type) == (libc::IPPROTO_IP, libc::IP_PKTINFO)
                && h.cmsg_len as usize >= need
            {
                // SAFETY: without MSG_CTRUNC, cmsg_len covers a whole in_pktinfo after the header.
                let p = unsafe {
                    libc::CMSG_DATA(c)
                        .cast::<libc::in_pktinfo>()
                        .read_unaligned()
                };
                return Some(Ipv4Addr::from(u32::from_be(p.ipi_addr.s_addr)));
            }
            // SAFETY: as above; CMSG_NXTHDR returns null past the end of the buffer.
            c = unsafe { libc::CMSG_NXTHDR(m, c) };
        }
        None
    }

    fn to_sockaddr(a: SocketAddrV4) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: a.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*a.ip()).to_be(),
            },
            sin_zero: [0; 8],
        }
    }

    fn from_sockaddr(s: &libc::sockaddr_in, len: libc::socklen_t) -> Option<SocketAddrV4> {
        let whole = len as usize >= mem::size_of::<libc::sockaddr_in>();
        (whole && s.sin_family == libc::AF_INET as libc::sa_family_t).then(|| {
            SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr)),
                u16::from_be(s.sin_port),
            )
        })
    }

    fn empty_sockaddr() -> libc::sockaddr_in {
        to_sockaddr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }

    fn empty_iovec() -> libc::iovec {
        libc::iovec {
            iov_base: core::ptr::null_mut(),
            iov_len: 0,
        }
    }

    fn empty_mmsghdr() -> libc::mmsghdr {
        // SAFETY: `mmsghdr` is integers and raw pointers (plus private padding on musl), for
        // which all-zero bytes are a valid value: null pointers and zero lengths.
        unsafe { mem::zeroed() }
    }

    /// Receives up to `BATCH` datagrams with one non-blocking `recvmmsg`, datagram `i` into the
    /// `i`-th buffer of `bufs` and described by `out[i]`. Returns how many arrived. An empty
    /// socket is `ErrorKind::WouldBlock`; a signal before any datagram is `Interrupted`.
    pub(crate) fn recv_batch<'a>(
        fd: RawFd,
        bufs: impl Iterator<Item = &'a mut [u8]>,
        out: &mut [Recvd; BATCH],
    ) -> io::Result<usize> {
        let mut hdrs = [empty_mmsghdr(); BATCH];
        let mut iovs = [empty_iovec(); BATCH];
        let mut names = [empty_sockaddr(); BATCH];
        let mut ctrl = [Ctrl([0; CTRL_BYTES]); BATCH];
        let mut n = 0;
        for (((buf, iov), name), (h, c)) in bufs
            .zip(&mut iovs)
            .zip(&mut names)
            .zip(hdrs.iter_mut().zip(&mut ctrl))
        {
            iov.iov_base = buf.as_mut_ptr().cast();
            iov.iov_len = buf.len();
            let m = &mut h.msg_hdr;
            m.msg_name = (name as *mut libc::sockaddr_in).cast();
            m.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            m.msg_iov = iov;
            m.msg_iovlen = 1;
            m.msg_control = c.0.as_mut_ptr().cast();
            m.msg_controllen = CTRL_BYTES as _;
            n += 1;
        }
        if n == 0 {
            return Ok(0);
        }
        // SAFETY: `hdrs[..n]` are initialized message headers. Each points at its own `iovs`,
        // `names` and `ctrl` entry, which live on this frame until the call returns, and each
        // iovec at a buffer of `bufs`, borrowed mutably for 'a, with its true length, so the
        // kernel writes only inside them. `n <= BATCH` and a null timeout is allowed.
        let got = unsafe {
            libc::recvmmsg(
                fd,
                hdrs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT as _,
                core::ptr::null_mut(),
            )
        };
        let got = usize::try_from(got).map_err(|_| io::Error::last_os_error())?;
        for ((o, h), name) in out.iter_mut().zip(&hdrs).zip(&names).take(got) {
            *o = Recvd {
                len: h.msg_len as usize,
                trunc: h.msg_hdr.msg_flags & libc::MSG_TRUNC != 0,
                src: from_sockaddr(name, h.msg_hdr.msg_namelen),
                dst: pktinfo_dst(&h.msg_hdr),
            };
        }
        Ok(got)
    }

    /// Sends `msgs`, each a payload and its destination, at most `BATCH` of them, with one
    /// non-blocking `sendmmsg`. Returns how many the kernel took from the front; fewer than
    /// `msgs.len()` means the next one failed and calling again with the rest reports why. An
    /// error means the first one was not sent.
    pub(crate) fn send_batch(fd: RawFd, msgs: &[(&[u8], SocketAddrV4)]) -> io::Result<usize> {
        let n = msgs.len().min(BATCH);
        let mut hdrs = [empty_mmsghdr(); BATCH];
        let mut iovs = [empty_iovec(); BATCH];
        let mut names = [empty_sockaddr(); BATCH];
        for (((&(payload, dst), iov), name), h) in msgs
            .iter()
            .zip(&mut iovs)
            .zip(&mut names)
            .zip(&mut hdrs)
            .take(n)
        {
            // sendmmsg only reads through iov_base; the pointer is `*mut` by the C type alone.
            iov.iov_base = payload.as_ptr().cast_mut().cast();
            iov.iov_len = payload.len();
            *name = to_sockaddr(dst);
            let m = &mut h.msg_hdr;
            m.msg_name = (name as *mut libc::sockaddr_in).cast();
            m.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            m.msg_iov = iov;
            m.msg_iovlen = 1;
        }
        if n == 0 {
            return Ok(0);
        }
        // SAFETY: `hdrs[..n]` are initialized message headers pointing at this frame's `iovs`
        // and `names` entries and at payloads borrowed from `msgs`, all live until the call
        // returns. The kernel only reads them (and writes `msg_len` in `hdrs`). `n <= BATCH`.
        let sent = unsafe {
            libc::sendmmsg(
                fd,
                hdrs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT as _,
            )
        };
        usize::try_from(sent).map_err(|_| io::Error::last_os_error())
    }
}
