//! `vyrn-replica::vx` (UNSAFE.toml): loads `libvyrn_vx_client` (spec/11-build.md §5.3) and runs
//! its threads over a region the shell owns (`vx/abi/pbv.h`, client section). Every `unsafe`
//! block needs a `// SAFETY:` comment. [`crate::VxReplay`] drives the region; this module only
//! loads, starts and stops.

use core::ffi::{CStr, c_void};
use core::sync::atomic::{AtomicU64, Ordering};
use std::ffi::CString;
use std::path::Path;
use std::thread::JoinHandle;

/// `PBV_ABI_VERSION`.
pub const ABI_VERSION: u32 = 3;

/// One 128-byte line of the shared region: 16 words.
#[repr(C, align(128))]
#[derive(Default)]
pub struct Line(pub [AtomicU64; 16]);

type NewFn =
    unsafe extern "C" fn(*const u8, *const u8, u32, *const u8, u32, *const Line) -> *mut c_void;
type LaneFn = unsafe extern "C" fn(*mut c_void, u32);
type BboFn = unsafe extern "C" fn(*mut c_void);
type FreeFn = unsafe extern "C" fn(*mut c_void);
type U32Fn = unsafe extern "C" fn() -> u32;
type BytesFn = unsafe extern "C" fn(u32) -> u64;

/// The context pointer, handed to the client's threads. The client synchronises every access.
#[derive(Clone, Copy)]
struct Ctx(*mut c_void);
// SAFETY: pbv.h: each entry point may run on its own thread over one context.
unsafe impl Send for Ctx {}

/// A running client: its context, its region and its `n + 1` threads.
pub struct Client {
    ctx: Ctx,
    free: FreeFn,
    mem: Box<[Line]>,
    threads: Vec<JoinHandle<()>>,
}

/// # Safety
/// `F` must be the function pointer type of the pbv.h function `name`.
unsafe fn sym<F: Copy>(lib: *mut c_void, name: &CStr) -> Result<F, String> {
    // SAFETY: `lib` is a handle from dlopen and `name` is NUL-terminated.
    let p = unsafe { libc::dlsym(lib, name.as_ptr()) };
    if p.is_null() {
        return Err(format!("missing symbol {name:?}"));
    }
    // SAFETY: `F` is a function pointer, the size of `p`; the caller names its signature.
    Ok(unsafe { core::mem::transmute_copy::<*mut c_void, F>(&p) })
}

impl Client {
    /// Loads the library at `path`, makes a context from the pbv.h config (64 bytes), account
    /// (80 each) and session (32 each) tables over a region sized for the config's lane count,
    /// and starts a thread per lane and the BBO thread.
    pub fn start(path: &Path, cfg: &[u8], accts: &[u8], sess: &[u8]) -> Result<Self, String> {
        let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
        // SAFETY: `c` is a NUL-terminated path; the library has no initialisers of its own.
        let lib = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if lib.is_null() {
            return Err(format!("dlopen {} failed", path.display()));
        }
        // SAFETY: each type is the pbv.h signature of the symbol it is read as.
        let (version, bytes, new, lane, bbo, free) = unsafe {
            (
                sym::<U32Fn>(lib, c"pbv_abi_version")?,
                sym::<BytesFn>(lib, c"pbv_shared_bytes")?,
                sym::<NewFn>(lib, c"pbv_new")?,
                sym::<LaneFn>(lib, c"pbv_lane_run")?,
                sym::<BboFn>(lib, c"pbv_bbo_run")?,
                sym::<FreeFn>(lib, c"pbv_free")?,
            )
        };
        // SAFETY: takes no arguments.
        let v = unsafe { version() };
        if v != ABI_VERSION {
            return Err(format!("client ABI version {v}, shell {ABI_VERSION}"));
        }
        // The region and threads follow the lane count pbv_new reads (cfg byte 8).
        let n = cfg.get(8).copied().unwrap_or(0);
        if cfg.len() != 64 || !accts.len().is_multiple_of(80) || !sess.len().is_multiple_of(32) {
            return Err("malformed pbv tables".into());
        }
        // SAFETY: takes a lane count.
        let len = unsafe { bytes(u32::from(n)) };
        let lines = usize::try_from(len.div_ceil(128)).map_err(|e| e.to_string())?;
        let mem: Box<[Line]> = (0..lines).map(|_| Line::default()).collect();
        let na = u32::try_from(accts.len() / 80).map_err(|e| e.to_string())?;
        let ns = u32::try_from(sess.len() / 32).map_err(|e| e.to_string())?;
        // SAFETY: the tables are valid for their lengths and pbv_new copies them; `mem` is
        // 128-aligned, zeroed, `pbv_shared_bytes(n)` long, and outlives the context (Drop).
        let ctx = unsafe {
            new(
                cfg.as_ptr(),
                accts.as_ptr(),
                na,
                sess.as_ptr(),
                ns,
                mem.as_ptr(),
            )
        };
        if ctx.is_null() {
            return Err("pbv_new rejected the config".into());
        }
        let ctx = Ctx(ctx);
        let mut threads = Vec::new();
        for l in 0..u32::from(n) {
            threads.push(std::thread::spawn(move || {
                let x = ctx;
                // SAFETY: the context is live until Drop joins this thread.
                unsafe { lane(x.0, l) }
            }));
        }
        threads.push(std::thread::spawn(move || {
            let x = ctx;
            // SAFETY: as above.
            unsafe { bbo(x.0) }
        }));
        Ok(Self {
            ctx,
            free,
            mem,
            threads,
        })
    }

    /// The shared region, by line.
    pub fn mem(&self) -> &[Line] {
        &self.mem
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(l) = self.mem.first() {
            l.0[0].store(1, Ordering::Release);
        }
        self.threads.drain(..).for_each(|t| drop(t.join()));
        // SAFETY: every thread that used the context has returned; it is freed once.
        unsafe { (self.free)(self.ctx.0) }
    }
}
