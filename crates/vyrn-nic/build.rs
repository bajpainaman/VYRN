//! Builds the C shim with clang (spec/11-build.md §4.1), on Linux and only with the `shim`
//! feature. kernel_udp and sim need no C, so by default, and always on macOS, this looks for no
//! compiler (06 §7.4).
fn main() {
    println!("cargo:rerun-if-changed=../../c/vyrn-nic-shim");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_SHIM");
    let linux = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");
    if !linux || std::env::var_os("CARGO_FEATURE_SHIM").is_none() {
        return;
    }
    cc::Build::new()
        .compiler("clang")
        .archiver("llvm-ar")
        .file("../../c/vyrn-nic-shim/shim.c")
        .include("../../c/vyrn-nic-shim")
        .flag("-std=c11")
        .flag("-flto=thin")
        .flag("-fno-strict-aliasing")
        .flag("-fwrapv")
        .flag("-fno-delete-null-pointer-checks")
        .flag("-ftrivial-auto-var-init=zero")
        .flag("-fvisibility=hidden")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror")
        .flag("-Wconversion")
        .flag("-Wstrict-prototypes")
        .flag("-Wmissing-prototypes")
        .compile("vyrn_nic_shim");
}
