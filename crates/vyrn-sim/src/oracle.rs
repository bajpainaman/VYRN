//! `vyrn-sim::oracle` (UNSAFE.toml): loads `libvyrn_vx_oracle` (spec/11-build.md §5.2) and
//! calls its C ABI (`vx/abi/pbv.h`). Every `unsafe` block needs a `// SAFETY:` comment.

use crate::oracle_abi::{ABI_VERSION, Account, Config, Event, Record, Session};
use core::ffi::{CStr, c_void};
use std::ffi::CString;
use std::path::Path;
type NewFn =
    unsafe extern "C" fn(*const Config, *const Account, u32, *const Session, u32) -> *mut c_void;
type ApplyFn = unsafe extern "C" fn(*mut c_void, *const Event, *mut Record, u32) -> u32;
type StateFn = unsafe extern "C" fn(*const c_void, *mut u8, u64) -> u64;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type VersionFn = unsafe extern "C" fn() -> u32;
/// One oracle book in a loaded library. The library stays loaded for the process.
pub struct Oracle {
    book: *mut c_void,
    apply: ApplyFn,
    state: StateFn,
    free: FreeFn,
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
impl Oracle {
    /// Loads the library at `path` and makes a book from the config and tables.
    pub fn new(path: &Path, cfg: &Config, a: &[Account], s: &[Session]) -> Result<Self, String> {
        let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
        // SAFETY: `c` is a NUL-terminated path; the library has no initialisers of its own.
        let lib = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if lib.is_null() {
            return Err(format!("dlopen {} failed", path.display()));
        }
        // SAFETY: each type is the pbv.h signature of the symbol it is read as.
        let (version, new, apply, state, free) = unsafe {
            (
                sym::<VersionFn>(lib, c"pbo_abi_version")?,
                sym::<NewFn>(lib, c"pbo_new")?,
                sym::<ApplyFn>(lib, c"pbo_apply")?,
                sym::<StateFn>(lib, c"pbo_state_bytes")?,
                sym::<FreeFn>(lib, c"pbo_free")?,
            )
        };
        // SAFETY: takes no arguments.
        let v = unsafe { version() };
        if v != ABI_VERSION {
            return Err(format!("oracle ABI version {v}, harness {ABI_VERSION}"));
        }
        let na = u32::try_from(a.len()).map_err(|e| e.to_string())?;
        let ns = u32::try_from(s.len()).map_err(|e| e.to_string())?;
        // SAFETY: the slices are valid for their lengths; pbo_new copies what it keeps.
        let book = unsafe { new(cfg, a.as_ptr(), na, s.as_ptr(), ns) };
        if book.is_null() {
            return Err("pbo_new rejected the config".into());
        }
        Ok(Self {
            book,
            apply,
            state,
            free,
        })
    }
    /// Applies one event. `Ok` holds its records; `Err` holds a `PBO_E_*` code. After
    /// `PBO_E_CAP` the event was applied, so the caller fails rather than retries (11 §5.2).
    pub fn apply(&mut self, ev: &Event) -> Result<Vec<Record>, u32> {
        const CAP: u32 = 4096;
        let mut out = vec![Record::default(); CAP as usize];
        // SAFETY: `book` is live, `ev` is one event and `out` has room for `CAP` records.
        let n = unsafe { (self.apply)(self.book, ev, out.as_mut_ptr(), CAP) };
        if n > CAP {
            return Err(n);
        }
        out.truncate(n as usize);
        Ok(out)
    }
    /// The canonical state bytes (pbv.h, version 1).
    pub fn state_bytes(&self) -> Vec<u8> {
        // SAFETY: a null buffer with cap 0 only asks for the size.
        let n = unsafe { (self.state)(self.book, core::ptr::null_mut(), 0) };
        let mut v = vec![0u8; usize::try_from(n).unwrap_or(0)];
        // SAFETY: `v` holds `n` bytes, the size the library asked for.
        assert_eq!(unsafe { (self.state)(self.book, v.as_mut_ptr(), n) }, n);
        v
    }
}
impl Drop for Oracle {
    fn drop(&mut self) {
        // SAFETY: `book` came from pbo_new and is freed once.
        unsafe { (self.free)(self.book) }
    }
}
