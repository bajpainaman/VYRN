//! The `vyrn-admin` library: the admin-channel codec of 04 §4.4 and the `CtlDone` bytes of
//! 10 §2.4, so that a client SDK or a test can open a BASE session without this binary.
//!
//! Reading (spec gap, labelled): 11 §1.3 says a `bin/` package holds no logic, but names no crate
//! for the admin messages. Until 11 does, the codec is this package's library target.
#![forbid(unsafe_code)]

pub mod codec;
